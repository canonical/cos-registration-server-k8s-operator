import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import ops
import ops.testing

from charm import (
    CosRegistrationServerCharm,
    md5_dict,
    md5_dir,
    md5_list,
    md5_update_from_file,
)

ops.testing.SIMULATE_CAN_CONNECT = True


k8s_resource_multipatch = patch.multiple(
    "charm.KubernetesComputeResourcesPatch",
    _namespace="test-namespace",
    _patch=lambda *a, **kw: True,
    is_ready=lambda *a, **kw: True,
)


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = ops.testing.Harness(CosRegistrationServerCharm)
        self.addCleanup(self.harness.cleanup)

        self.name = "cos-registration-server"

        self.harness.set_model_name("testmodel")
        self.harness.container_pebble_ready(self.name)
        self.harness.handle_exec(self.name, ["/usr/bin/install.bash"], result=0)
        self.harness.handle_exec(self.name, ["/usr/bin/configure.bash"], result=0)

        self.harness.add_storage("database", attach=True)[0]

        self.external_host = "1.2.3.4"
        self.external_url = f"http://{self.external_host}/{self.harness._backend.model_name}-{self.harness._backend.app_name}"

        self.harness.set_leader(True)
        self.harness.begin()

    def test_create_super_user_action(self):
        self.harness.set_can_connect(self.name, True)
        self.harness.handle_exec(
            self.name, ["/usr/bin/create_super_user.bash", "--noinput"], result=0
        )
        action_output = self.harness.run_action("get-admin-password")
        self.assertEqual(len(action_output.results), 3)
        second_action_output = self.harness.run_action("get-admin-password")
        self.assertEqual(
            action_output.results["password"], second_action_output.results["password"]
        )

    def test_cos_registration_server_pebble_ready(self):
        with patch.multiple("charm.IngressPerAppRequirer", url=self.external_url):
            # Expected plan after Pebble ready with default config
            command = " ".join(["/usr/bin/launcher.bash"])

            expected_plan = {
                "services": {
                    self.name: {
                        "override": "replace",
                        "summary": "cos-registration-server-k8s service",
                        "command": command,
                        "startup": "enabled",
                        "environment": {
                            "ALLOWED_HOST_DJANGO": f"{self.external_host},{self.harness.charm.internal_host}",
                            "SCRIPT_NAME": f"/{self.harness._backend.model_name}-{self.harness._backend.app_name}",
                            "COS_MODEL_NAME": f"{self.harness._backend.model_name}",
                        },
                    }
                },
            }
            # Simulate the container coming up and emission of pebble-ready event
            self.harness.container_pebble_ready(self.name)
            # Get the plan now we've run PebbleReady
            updated_plan = self.harness.get_container_pebble_plan(self.name).to_dict()
            # Check we've got the plan we expected
            self.assertEqual(expected_plan, updated_plan)
            # Check the service was started
            service = self.harness.model.unit.get_container(self.name).get_service(self.name)
            self.assertTrue(service.is_running())
            # Ensure we set an ActiveStatus with no message
            self.assertEqual(self.harness.model.unit.status, ops.ActiveStatus())

    def test_update_status(
        self,
    ):
        self.harness.set_can_connect(self.name, True)

        self.harness.charm._update_grafana_dashboards = Mock()
        self.harness.charm._update_auth_devices_keys = Mock()
        self.harness.charm._update_loki_alert_rule_files_devices = Mock()
        self.harness.charm._update_prometheus_alert_rule_files_devices = Mock()

        self.harness.charm.on.update_status.emit()

        self.assertEqual(self.harness.charm._update_grafana_dashboards.call_count, 1)
        self.assertEqual(self.harness.charm._update_auth_devices_keys.call_count, 1)
        self.assertEqual(self.harness.charm._update_loki_alert_rule_files_devices.call_count, 1)
        self.assertEqual(
            self.harness.charm._update_prometheus_alert_rule_files_devices.call_count, 1
        )

    @patch("requests.get")
    def test_get_pub_keys_from_db_success(self, mock_get):
        mock_get.return_value.json.return_value = [
            {"uid": "0", "public_ssh_key": "ssh-rsa pubkey1"},
            {"uid": "1", "public_ssh_key": "ssh-rsa pubkey2"},
        ]
        result = self.harness.charm._get_auth_devices_keys_from_db()
        self.assertEqual(
            result,
            [
                {"uid": "0", "public_ssh_key": "ssh-rsa pubkey1"},
                {"uid": "1", "public_ssh_key": "ssh-rsa pubkey2"},
            ],
        )
        mock_get.assert_called_once_with(
            f"{self.harness.charm.internal_url}/api/v1/devices/?fields=uid,public_ssh_key"
        )

    @patch("requests.get")
    def test_update_auth_devices_keys_changed(self, mock_get):
        mock_get.return_value.json.return_value = [
            {"uid": "0", "public_ssh_key": "ssh-rsa pubkey1"}
        ]
        self.harness.charm._stored.auth_devices_keys_hash = ""
        self.harness.charm._update_auth_devices_keys()
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/devices/?fields=uid,public_ssh_key"
        )
        self.assertNotEqual(self.harness.charm._stored.auth_devices_keys_hash, "")

        previous_hash = self.harness.charm._stored.auth_devices_keys_hash
        mock_get.return_value.json.return_value = [
            {"uid": "0", "public_ssh_key": "ssh-rsa pubkey1"},
            {"uid": "1", "public_ssh_key": "ssh-rsa pubkey2"},
        ]
        self.harness.charm._update_auth_devices_keys()
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/devices/?fields=uid,public_ssh_key"
        )
        self.assertNotEqual(self.harness.charm._stored.auth_devices_keys_hash, previous_hash)

    @patch("requests.get")
    def test_update_auth_devices_keys_not_changed(self, mock_get):
        mock_get.return_value.json.return_value = [
            {"uid": "0", "public_ssh_key": "ssh-rsa pubkey1"}
        ]
        self.harness.charm._stored.auth_devices_keys_hash = ""
        self.harness.charm._update_auth_devices_keys()
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/devices/?fields=uid,public_ssh_key"
        )
        self.assertNotEqual(self.harness.charm._stored.auth_devices_keys_hash, "")

        previous_hash = self.harness.charm._stored.auth_devices_keys_hash
        self.harness.charm._update_auth_devices_keys()
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/devices/?fields=uid,public_ssh_key"
        )
        self.assertEqual(self.harness.charm._stored.auth_devices_keys_hash, previous_hash)

    @patch("requests.get")
    def test_get_grafana_dashboards_from_db_success(self, mock_get):
        mock_get.return_value.json.return_value = [
            {"uid": "my_dashboard", "dashboard": {"annotations": True, "dashboard": True}}
        ]
        result = self.harness.charm._get_grafana_dashboards_from_db()
        self.assertEqual(
            result,
            [{"uid": "my_dashboard", "dashboard": {"annotations": True, "dashboard": True}}],
        )
        mock_get.assert_called_once_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/grafana/dashboards/"
        )

    @patch("requests.get")
    def test_update_grafana_dashboards_changed(self, mock_get):
        mock_get.return_value.json.return_value = [
            {"uid": "my_dashboard", "dashboard": {"annotations": True, "dashboard": True}}
        ]
        self.harness.charm._stored.dashboard_dict_hash = ""
        self.harness.charm._update_grafana_dashboards()
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/grafana/dashboards/"
        )
        self.assertNotEqual(self.harness.charm._stored.dashboard_dict_hash, "")

        previous_hash = self.harness.charm._stored.dashboard_dict_hash
        mock_get.return_value.json.return_value = [
            {"uid": "my_dashboard2", "dashboard": {"annotations": True, "dashboard": True}}
        ]
        self.harness.charm._update_grafana_dashboards()
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/grafana/dashboards/"
        )
        self.assertNotEqual(self.harness.charm._stored.dashboard_dict_hash, previous_hash)

    @patch("requests.get")
    def test_update_grafana_dashboards_not_changed(self, mock_get):
        mock_get.return_value.json.return_value = [
            {"uid": "my_dashboard", "dashboard": {"annotations": True, "dashboard": True}}
        ]
        self.harness.charm._stored.dashboard_dict_hash = ""
        self.harness.charm._update_grafana_dashboards()
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/grafana/dashboards/"
        )
        self.assertNotEqual(self.harness.charm._stored.dashboard_dict_hash, "")
        print(self.harness.charm._stored.dashboard_dict_hash)
        previous_hash = self.harness.charm._stored.dashboard_dict_hash
        mock_get.return_value.json.return_value = [
            {"uid": "my_dashboard", "dashboard": {"annotations": True, "dashboard": True}}
        ]
        self.harness.charm._update_grafana_dashboards()
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/grafana/dashboards/"
        )
        self.assertEqual(self.harness.charm._stored.dashboard_dict_hash, previous_hash)

    @patch("requests.get")
    def test_get_loki_alert_rule_files_from_db_success(self, mock_get):
        loki_alert = """group:
          - name: my-group
            alert: my-alert"""

        mock_get.return_value.json.return_value = [{"uid": "my_alert", "rules": loki_alert}]
        result = self.harness.charm._get_alert_rule_files_from_db("loki")
        self.assertEqual(
            result,
            [{"uid": "my_alert", "rules": loki_alert}],
        )
        mock_get.assert_called_once_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/loki/alert_rules/"
        )

    @patch("requests.get")
    def test_update_loki_alert_rule_files_changed(self, mock_get):
        loki_alert = """group:
          - name: my-group
            alert: my-alert"""
        mock_get.return_value.json.return_value = [{"uid": "my_alert", "rules": loki_alert}]
        self.harness.charm._stored.loki_alert_rules_hash = ""
        self.harness.charm._update_loki_alert_rule_files_devices()
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/loki/alert_rules/"
        )
        self.assertNotEqual(self.harness.charm._stored.loki_alert_rules_hash, "")

        previous_hash = self.harness.charm._stored.loki_alert_rules_hash
        mock_get.return_value.json.return_value = [{"uid": "my_rule2", "rules": loki_alert}]
        self.harness.charm._update_loki_alert_rule_files_devices()
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/loki/alert_rules/"
        )
        self.assertNotEqual(self.harness.charm._stored.loki_alert_rules_hash, previous_hash)

    @patch("requests.get")
    def test_update_loki_alert_rules_files_not_changed(self, mock_get):
        loki_alert = """group:
          - name: my-group
            alert: my-alert"""
        mock_get.return_value.json.return_value = [{"uid": "my_rule", "rules": loki_alert}]
        self.harness.charm._stored.loki_alert_rules_hash = ""
        self.harness.charm._update_loki_alert_rule_files_devices()
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/loki/alert_rules/"
        )
        self.assertNotEqual(self.harness.charm._stored.loki_alert_rules_hash, "")
        previous_hash = self.harness.charm._stored.loki_alert_rules_hash
        self.harness.charm._update_loki_alert_rule_files_devices()
        print(self.harness.charm._stored.loki_alert_rules_hash)
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/loki/alert_rules/"
        )
        self.assertEqual(self.harness.charm._stored.loki_alert_rules_hash, previous_hash)

    @patch("requests.get")
    def test_get_prometheus_alert_rule_files_from_db_success(self, mock_get):
        prometheus_alert = """group:
          - name: my-group
            alert: my-alert"""

        mock_get.return_value.json.return_value = [{"uid": "my_alert", "rules": prometheus_alert}]
        result = self.harness.charm._get_alert_rule_files_from_db("prometheus")
        self.assertEqual(
            result,
            [{"uid": "my_alert", "rules": prometheus_alert}],
        )
        mock_get.assert_called_once_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/prometheus/alert_rules/"
        )

    @patch("requests.get")
    def test_update_prometheus_alert_rule_files_changed(self, mock_get):
        prometheus_alert = """group:
          - name: my-group
            alert: my-alert"""
        mock_get.return_value.json.return_value = [{"uid": "my_alert", "rules": prometheus_alert}]
        self.harness.charm._stored.prometheus_alert_rules_hash = ""
        self.harness.charm._update_prometheus_alert_rule_files_devices()
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/prometheus/alert_rules/"
        )
        self.assertNotEqual(self.harness.charm._stored.prometheus_alert_rules_hash, "")

        previous_hash = self.harness.charm._stored.prometheus_alert_rules_hash
        mock_get.return_value.json.return_value = [{"uid": "my_rule2", "rules": prometheus_alert}]
        self.harness.charm._update_prometheus_alert_rule_files_devices()
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/prometheus/alert_rules/"
        )
        self.assertNotEqual(self.harness.charm._stored.prometheus_alert_rules_hash, previous_hash)

    @patch("requests.get")
    def test_update_prometheus_alert_rule_files_not_changed(self, mock_get):
        prometheus_alert = """group:
          - name: my-group
            alert: my-alert"""
        mock_get.return_value.json.return_value = [{"uid": "my_rule", "rules": prometheus_alert}]
        self.harness.charm._stored.prometheus_alert_rules_hash = ""
        self.harness.charm._update_prometheus_alert_rule_files_devices()
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/prometheus/alert_rules/"
        )
        self.assertNotEqual(self.harness.charm._stored.prometheus_alert_rules_hash, "")
        previous_hash = self.harness.charm._stored.prometheus_alert_rules_hash
        self.harness.charm._update_prometheus_alert_rule_files_devices()
        print(self.harness.charm._stored.prometheus_alert_rules_hash)
        mock_get.assert_called_with(
            f"{self.harness.charm.internal_url}/api/v1/applications/prometheus/alert_rules/"
        )
        self.assertEqual(self.harness.charm._stored.prometheus_alert_rules_hash, previous_hash)


class TestMD5(unittest.TestCase):
    def create_file(self, name, content):
        with open(self.directory_path / Path(name), "w") as f:
            f.write(content)

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.directory_path = Path(self.temporary_directory.name)

    def test_md5_update_file(self):
        self.create_file("robot-1.json", '{"dashboard": True}')
        hash = hashlib.md5()
        result = md5_update_from_file(self.directory_path / Path("robot-1.json"), hash)
        self.assertNotEqual(result, str())

    def test_md5_dir(self):
        self.create_file("robot-1.json", '{"dashboard": True}')
        self.create_file("robot-2.json", '{"dashboard": False}')
        result = md5_dir(self.directory_path)
        self.assertNotEqual(result, str())

    def test_md5_dict(self):
        test_dict = {"key1": "value1", "key2": "value2"}

        result = md5_dict(test_dict)
        self.assertNotEqual(result, str())

    def test_md5_list(self):
        test_list = [{"key1": "value"}, {"key2": "value"}]

        result = md5_list(test_list)
        self.assertNotEqual(result, str())
