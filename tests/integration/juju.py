"""Juju/Jubilant integration helpers."""

import json
import logging

import jubilant

logger = logging.getLogger(__name__)


def show_unit(juju: jubilant.Juju, unit: str) -> dict:
    """Return show-unit data for a unit."""
    output = juju._cli("show-unit", unit, "--format", "json")
    if isinstance(output, (tuple, list)):
        output = output[0]
    data = json.loads(output)
    if isinstance(data, dict) and unit in data:
        return data[unit]
    return data


def relation_application_data(
    juju: jubilant.Juju,
    unit: str,
    endpoint: str,
    related_unit: str,
    related_endpoint: str,
) -> list[dict]:
    """Return relation application-data entries for a unit relation."""
    unit_data = show_unit(juju, unit)
    data_items: list[dict] = []
    for rel in unit_data.get("relation-info", []):
        if rel.get("endpoint") != endpoint:
            continue
        if rel.get("related-endpoint") != related_endpoint:
            continue
        related_units = rel.get("related-units", {})
        if not isinstance(related_units, dict) or related_unit not in related_units:
            continue
        app_data = rel.get("application-data")
        if isinstance(app_data, dict) and app_data:
            data_items.append(app_data)
        related_app = rel.get("related-application")
        if isinstance(related_app, dict):
            related_app_data = related_app.get("application-data")
            if isinstance(related_app_data, dict) and related_app_data:
                data_items.append(related_app_data)
    return data_items
