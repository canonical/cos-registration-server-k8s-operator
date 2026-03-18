import logging
import os
import pathlib
import subprocess
from collections.abc import Generator
from typing import Any, Dict

import jubilant
import pytest
import yaml

from tests.integration.constants import (
    APP_CERTIFICATES,
    APP_DATABASE,
    APP_GRAFANA_DASHBOARD_DEVICES,
    APP_LOKI_ALERT_RULE_FILES_DEVICES,
    APP_PROBES,
    APP_PROBES_DEVICES,
    APP_PROMETHEUS_ALERT_RULE_FILES_DEVICES,
    APP_TRACING,
    BLACKBOX_APP,
    BLACKBOX_PROBES,
    GRAFANA_AGENT_APP,
    GRAFANA_AGENT_GRAFANA_DASHBOARD,
    GRAFANA_AGENT_LOGGING_PROVIDER,
    GRAFANA_AGENT_TRACING_ENDPOINT,
    GRAFANA_DASHBOARD_FILE,
    GRAFANA_DASHBOARD_FILES_DIRECTORY_DEVICES,
    LOKI_ALERT_RULE_FILE,
    LOKI_ALERT_RULE_FILES_DIRECTORY_DEVICES,
    POSTGRESQL_APP,
    POSTGRESQL_APP_CHANNEL,
    POSTGRESQL_DATABASE,
    PROMETHEUS_ALERT_RULE_FILE,
    PROMETHEUS_ALERT_RULE_FILES_DIRECTORY_DEVICES,
    PROMETHEUS_APP,
    PROMETHEUS_RECEIVE_REMOTE_WRITE,
    RESOURCE_NAME,
    SSC_APP,
    SSC_CERTIFICATES,
)

logger = logging.getLogger(__name__)


def alert_rule_files() -> None:
    """Create alert rule files & directory if it does not exist."""
    LOKI_ALERT_RULE_FILES_DIRECTORY_DEVICES.mkdir(parents=True, exist_ok=True)
    PROMETHEUS_ALERT_RULE_FILES_DIRECTORY_DEVICES.mkdir(parents=True, exist_ok=True)
    (LOKI_ALERT_RULE_FILES_DIRECTORY_DEVICES / "my_rule.rule").write_text(LOKI_ALERT_RULE_FILE)
    (PROMETHEUS_ALERT_RULE_FILES_DIRECTORY_DEVICES / "my_rule.rule").write_text(
        PROMETHEUS_ALERT_RULE_FILE
    )


def grafana_dashboards_files() -> None:
    """Create Grafana dashboard files & directory if it does not exist."""
    GRAFANA_DASHBOARD_FILES_DIRECTORY_DEVICES.mkdir(parents=True, exist_ok=True)
    (GRAFANA_DASHBOARD_FILES_DIRECTORY_DEVICES / "my-dashboard.json").write_text(
        GRAFANA_DASHBOARD_FILE
    )


def pytest_sessionstart(session):
    alert_rule_files()
    grafana_dashboards_files()


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@pytest.fixture(scope="module")
def juju(request: pytest.FixtureRequest) -> Generator[jubilant.Juju, None, None]:
    """Pytest fixture that wraps :meth:`jubilant.with_model`."""

    def show_debug_log(juju: jubilant.Juju):
        if request.session.testsfailed:
            log = juju.debug_log(limit=1000)
            print(log, end="")

    use_existing = _env_flag("JUJU_USE_EXISTING", default=False)
    if use_existing:
        juju = jubilant.Juju()
        yield juju
        show_debug_log(juju)
        return

    model = os.environ.get("JUJU_MODEL")
    if model:
        juju = jubilant.Juju(model=model)
        yield juju
        show_debug_log(juju)
        return

    keep_models = _env_flag("JUJU_KEEP_MODELS", default=False)
    with jubilant.temp_model(keep=keep_models) as juju:
        juju.wait_timeout = 10 * 60
        yield juju
        show_debug_log(juju)
        return


@pytest.fixture(scope="session")
def metadata() -> Dict[str, Any]:
    """Provides charm metadata."""
    return yaml.safe_load(pathlib.Path("./charmcraft.yaml").read_text(encoding="UTF-8"))


@pytest.fixture(scope="module", name="cos_registration_server")
def app_fixture(
    juju: jubilant.Juju,
    metadata: Dict[str, Any],
    charm_file: str,
):
    """Builds and deploys the charm and its required relations/resources."""
    app_name = metadata["name"]

    charm_oci_image = metadata["resources"][RESOURCE_NAME]["upstream-source"]
    charm_resources = {RESOURCE_NAME: charm_oci_image}

    juju.deploy(
        charm=charm_file,
        app=app_name,
        resources=charm_resources,
    )

    juju.deploy(
        POSTGRESQL_APP,
        channel=POSTGRESQL_APP_CHANNEL,
        trust=True,
    )

    juju.deploy(PROMETHEUS_APP, channel="1/stable", trust=True)

    juju.deploy(GRAFANA_AGENT_APP, channel="1/stable")

    juju.deploy(BLACKBOX_APP, channel="1/stable", trust=True)

    juju.deploy(SSC_APP, channel="1/stable", trust=True)

    logger.info(
        "Adding relation: %s:%s and %s:%s",
        app_name,
        APP_DATABASE,
        POSTGRESQL_APP,
        POSTGRESQL_DATABASE,
    )
    juju.integrate(app_name, f"{POSTGRESQL_APP}:{POSTGRESQL_DATABASE}")

    logger.info(
        "Adding relation: %s:%s and %s:%s",
        app_name,
        APP_GRAFANA_DASHBOARD_DEVICES,
        GRAFANA_AGENT_APP,
        GRAFANA_AGENT_GRAFANA_DASHBOARD,
    )
    juju.integrate(
        f"{app_name}:{APP_GRAFANA_DASHBOARD_DEVICES}",
        f"{GRAFANA_AGENT_APP}:{GRAFANA_AGENT_GRAFANA_DASHBOARD}",
    )

    logger.info(
        "Adding relation: %s:%s and %s:%s",
        app_name,
        APP_LOKI_ALERT_RULE_FILES_DEVICES,
        GRAFANA_AGENT_APP,
        GRAFANA_AGENT_LOGGING_PROVIDER,
    )
    juju.integrate(
        f"{app_name}:{APP_LOKI_ALERT_RULE_FILES_DEVICES}",
        f"{GRAFANA_AGENT_APP}:{GRAFANA_AGENT_LOGGING_PROVIDER}",
    )

    logger.info(
        "Adding relation: %s:%s and %s:%s",
        app_name,
        APP_PROMETHEUS_ALERT_RULE_FILES_DEVICES,
        PROMETHEUS_APP,
        PROMETHEUS_RECEIVE_REMOTE_WRITE,
    )
    # We cannot use the grafana agent since it doesn't have a
    # receive-remote-write integration
    juju.integrate(
        f"{app_name}:{APP_PROMETHEUS_ALERT_RULE_FILES_DEVICES}",
        f"{PROMETHEUS_APP}:{PROMETHEUS_RECEIVE_REMOTE_WRITE}",
    )

    logger.info(
        "Adding relation: %s:%s and %s:%s",
        app_name,
        APP_TRACING,
        GRAFANA_AGENT_APP,
        GRAFANA_AGENT_TRACING_ENDPOINT,
    )
    juju.integrate(
        f"{app_name}:{APP_TRACING}",
        f"{GRAFANA_AGENT_APP}:{GRAFANA_AGENT_TRACING_ENDPOINT}",
    )

    logger.info(
        "Adding relation: %s:%s and %s:%s",
        app_name,
        APP_PROBES,
        BLACKBOX_APP,
        BLACKBOX_PROBES,
    )
    juju.integrate(f"{app_name}:{APP_PROBES}", f"{BLACKBOX_APP}:{BLACKBOX_PROBES}")

    logger.info(
        "Adding relation: %s:%s and %s:%s",
        app_name,
        APP_PROBES_DEVICES,
        BLACKBOX_APP,
        BLACKBOX_PROBES,
    )
    juju.integrate(f"{app_name}:{APP_PROBES_DEVICES}", f"{BLACKBOX_APP}:{BLACKBOX_PROBES}")

    logger.info(
        "Adding relation: %s:%s and %s:%s",
        app_name,
        APP_CERTIFICATES,
        SSC_APP,
        SSC_CERTIFICATES,
    )
    juju.integrate(f"{app_name}:{APP_CERTIFICATES}", f"{SSC_APP}:{SSC_CERTIFICATES}")

    juju.wait(
        lambda status: jubilant.all_active(status, PROMETHEUS_APP),
        timeout=1000,
    )
    juju.wait(
        lambda status: jubilant.all_active(status, POSTGRESQL_APP),
        timeout=1000,
    )
    juju.wait(
        lambda status: jubilant.all_active(status, BLACKBOX_APP),
        timeout=1000,
    )

    juju.wait(
        lambda status: jubilant.all_active(status, SSC_APP),
        timeout=1000,
    )

    juju.wait(lambda status: jubilant.all_active(status, app_name), timeout=1000)
    # we do not wait for grafana_agent_app since it's
    # in a blocked state by design.

    return app_name


@pytest.fixture(scope="session")
def charm_file(metadata: Dict[str, Any]):
    """Pytest fixture that packs the charm and returns the filename, or --charm-file if set."""
    charm_file = os.environ.get("CHARM_FILE")
    if charm_file:
        return charm_file

    try:
        subprocess.run(["charmcraft", "pack"], check=True, capture_output=True, text=True)  # nosec B603, B607
    except subprocess.CalledProcessError as exc:
        raise OSError(f"Error packing charm: {exc}; Stderr:\n{exc.stderr}") from None

    app_name = metadata["name"]
    charm_path = pathlib.Path(__file__).parent.parent.parent
    charms = [p.absolute() for p in charm_path.glob(f"{app_name}_*.charm")]
    assert charms, f"{app_name} .charm file not found"
    assert len(charms) == 1, f"{app_name} has more than one .charm file, unsure which to use"
    return str(charms[0])
