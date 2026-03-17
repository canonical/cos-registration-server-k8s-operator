#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant
import pytest

from tests.integration.constants import (
    APP_CERTIFICATES,
    APP_DATABASE,
    APP_GRAFANA_DASHBOARD_DEVICES,
    APP_LOKI_ALERT_RULE_FILES_DEVICES,
    APP_NAME,
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
    POSTGRESQL_APP,
    POSTGRESQL_DATABASE,
    PROMETHEUS_APP,
    PROMETHEUS_RECEIVE_REMOTE_WRITE,
    SSC_APP,
    SSC_CERTIFICATES,
)
from tests.integration.juju import relation_application_data

logger = logging.getLogger(__name__)


def wait_for_active_idle_without_error(juju: jubilant.Juju, timeout: int = 60 * 45):
    """Wait for the model to settle without errors."""
    logger.info(f"waiting for the model ({juju.model}) to settle ...")
    # grafana_agent_app stays in blocked state by design
    juju.wait(
        ready=lambda status: jubilant.all_active(
            status, APP_NAME, POSTGRESQL_APP, PROMETHEUS_APP, BLACKBOX_APP, SSC_APP
        ),
        delay=10,
        timeout=timeout,
        error=jubilant.any_error,
    )
    logger.info("waiting for agents idle ...")
    juju.wait(
        jubilant.all_agents_idle,
        delay=10,
        timeout=timeout,
        error=lambda status: jubilant.any_error(
            status, APP_NAME, POSTGRESQL_APP, PROMETHEUS_APP, BLACKBOX_APP, SSC_APP
        ),
    )


APP_UNIT = f"{APP_NAME}/0"
GRAFANA_AGENT_UNIT = f"{GRAFANA_AGENT_APP}/0"
PROMETHEUS_UNIT = f"{PROMETHEUS_APP}/0"
BLACKBOX_UNIT = f"{BLACKBOX_APP}/0"
SSC_UNIT = f"{SSC_APP}/0"
POSTGRESQL_UNIT = f"{POSTGRESQL_APP}/0"


@pytest.mark.abort_on_fail
def test_deploy(cos_registration_server: str, juju):
    """Assert the deployment reaches active status."""
    wait_for_active_idle_without_error(juju)


def test_alert_rules_devices(juju):
    """Test if devices alert rules are defined in relation."""
    data = relation_application_data(
        juju,
        GRAFANA_AGENT_UNIT,
        GRAFANA_AGENT_LOGGING_PROVIDER,
        APP_UNIT,
        APP_LOKI_ALERT_RULE_FILES_DEVICES,
    )
    assert "my-alert" in data[0]["alert_rules"]


def test_grafana_dashboards_devices(juju):
    """Test if devices dashboards are defined in relation."""
    data = relation_application_data(
        juju,
        GRAFANA_AGENT_UNIT,
        GRAFANA_AGENT_GRAFANA_DASHBOARD,
        APP_UNIT,
        APP_GRAFANA_DASHBOARD_DEVICES,
    )
    assert "my-dashboard" in data[0]["dashboards"]


def test_prometheus_alert_rules_devices(juju):
    """Test if devices alert rules are defined in relation."""
    # migrate from prometheus to grafana_agent
    data = relation_application_data(
        juju,
        PROMETHEUS_UNIT,
        PROMETHEUS_RECEIVE_REMOTE_WRITE,
        APP_UNIT,
        APP_PROMETHEUS_ALERT_RULE_FILES_DEVICES,
    )

    assert "my-alert" in data[0]["alert_rules"]


def test_tracing(juju):
    """Test logging is defined in relation data bag."""
    data = relation_application_data(
        juju, APP_UNIT, APP_TRACING, GRAFANA_AGENT_UNIT, GRAFANA_AGENT_TRACING_ENDPOINT
    )
    assert data


def test_blackbox(juju):
    """Test probes are defined in relation data bag."""
    data = relation_application_data(juju, BLACKBOX_UNIT, BLACKBOX_PROBES, APP_UNIT, APP_PROBES)
    assert "cos-registration-server-k8s/api/v1/health/" in data[0]["scrape_probes"]


def test_blackbox_devices(juju):
    """Test devices probes are defined in relation data bag."""
    data = relation_application_data(
        juju, BLACKBOX_UNIT, BLACKBOX_PROBES, APP_UNIT, APP_PROBES_DEVICES
    )
    assert data[0]["scrape_probes"]


def test_integrate_self_signed_certificates(juju):

    data = relation_application_data(juju, APP_UNIT, APP_CERTIFICATES, SSC_UNIT, SSC_CERTIFICATES)
    assert data == []


def test_postgresql(juju):
    data = relation_application_data(
        juju, APP_UNIT, APP_DATABASE, POSTGRESQL_UNIT, POSTGRESQL_DATABASE
    )
    database = data[0]["data"]
    assert "requested-secrets" in database
    assert "username" in database
    assert "password" in database
