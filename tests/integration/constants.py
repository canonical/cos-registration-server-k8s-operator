import pathlib

import yaml

METADATA = yaml.safe_load(pathlib.Path("./charmcraft.yaml").read_text(encoding="UTF-8"))
RESOURCE_NAME = "cos-registration-server-image"
APP_NAME = METADATA["name"]

APP_GRAFANA_DASHBOARD_DEVICES = "grafana-dashboard-devices"
APP_LOGGING = "logging"
APP_LOKI_ALERT_RULE_FILES_DEVICES = "logging-alerts-devices"
APP_PROMETHEUS_ALERT_RULE_FILES_DEVICES = "send-remote-write-alerts-devices"
APP_TRACING = "tracing"
APP_PROBES = "probes"
APP_PROBES_DEVICES = "probes-devices"
APP_DATABASE = "database"
APP_CERTIFICATES = "certificates"

LOKI_ALERT_RULE_FILES_DIRECTORY_DEVICES = pathlib.Path("./src/loki_alert_rules/devices")
PROMETHEUS_ALERT_RULE_FILES_DIRECTORY_DEVICES = pathlib.Path(
    "./src/prometheus_alert_rules/devices"
)
LOKI_ALERT_RULE_FILE = """groups:
        - name: example
          rules:
          - name: my-group
            alert: my-alert
            expr: up == 0
            for: 5m"""
PROMETHEUS_ALERT_RULE_FILE = """groups:
        - name: example
          rules:
          - name: my-group
            alert: my-alert
            expr: up == 0
            for: 5m"""

GRAFANA_DASHBOARD_FILES_DIRECTORY_DEVICES = pathlib.Path("./src/grafana_dashboards/devices")
GRAFANA_DASHBOARD_FILE = """{
  "title": "Example Dashboard",
  "schemaVersion": 36,
  "version": 1,
  "panels": []
}"""

PROMETHEUS_RECEIVE_REMOTE_WRITE = "receive-remote-write"
PROMETHEUS_APP = "prometheus-k8s"

POSTGRESQL_APP = "postgresql-k8s"
POSTGRESQL_APP_CHANNEL = "14/stable"
POSTGRESQL_DATABASE = "database"

GRAFANA_AGENT_APP = "grafana-agent-k8s"
GRAFANA_AGENT_METRICS_ENDPOINT = "metrics-endpoint"
GRAFANA_AGENT_GRAFANA_DASHBOARD = "grafana-dashboards-consumer"
GRAFANA_AGENT_LOGGING_PROVIDER = "logging-provider"
GRAFANA_AGENT_TRACING_ENDPOINT = "tracing-provider"

BLACKBOX_APP = "blackbox-exporter-k8s"
BLACKBOX_PROBES = "probes"

SSC_APP = "self-signed-certificates"
SSC_CERTIFICATES = "certificates"
