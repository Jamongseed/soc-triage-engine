from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

import yaml


def load_allowlist(file_path: str | Path) -> dict[str, Any]:
    """
    Load suppression policy from YAML.

    Supported policy keys:
    - allowed_ssh_logins
    - suppressed_rules
    - suppressed_user_agents
    - suppressed_paths
    - trusted_services
    - trusted_networks
    - maintenance_windows
    """
    path = Path(file_path)

    if not path.exists():
        return _empty_policy()

    with open(path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    for key in _empty_policy():
        data.setdefault(key, [])

    return data


def _empty_policy() -> dict[str, list[Any]]:
    return {
        "allowed_ssh_logins": [],
        "suppressed_rules": [],
        "suppressed_user_agents": [],
        "suppressed_paths": [],
        "trusted_services": [],
        "trusted_networks": [],
        "maintenance_windows": [],
    }


def _get_raw_event(alert: dict[str, Any]) -> dict[str, Any]:
    raw_event = alert.get("raw_event", {})
    if isinstance(raw_event, dict):
        return raw_event
    return {}


def _get_field(alert: dict[str, Any], field: str) -> Any:
    if field in alert:
        return alert.get(field)

    raw_event = _get_raw_event(alert)
    return raw_event.get(field)


def _get_user(alert: dict[str, Any]) -> str | None:
    return _get_field(alert, "user")


def _get_src_ip(alert: dict[str, Any]) -> str | None:
    return _get_field(alert, "src_ip")


def _get_event_type(alert: dict[str, Any]) -> str | None:
    return _get_field(alert, "event_type")


def _get_user_agent(alert: dict[str, Any]) -> str:
    return str(_get_field(alert, "user_agent") or "")


def _get_url(alert: dict[str, Any]) -> str:
    return str(_get_field(alert, "url") or "")


def _contains(value: str, pattern: str | None) -> bool:
    if not pattern:
        return False
    return pattern.lower() in value.lower()


def _parse_timestamp(timestamp: str | None) -> datetime | None:
    if not timestamp:
        return None

    value = str(timestamp).replace("+09:00", "")

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _matches_allowed_ssh_login(
    alert: dict[str, Any],
    allowed_ssh_logins: list[dict[str, Any]],
) -> str | None:
    if alert.get("rule_id") != "SSH-SUCCESS-001":
        return None

    src_ip = _get_src_ip(alert)
    user = _get_user(alert)

    for item in allowed_ssh_logins:
        if item.get("src_ip") == src_ip and item.get("user") == user:
            return item.get("reason", "Allowed SSH login")

    return None


def _matches_suppressed_rule(
    alert: dict[str, Any],
    suppressed_rules: list[dict[str, Any]],
) -> str | None:
    rule_id = alert.get("rule_id")
    src_ip = _get_src_ip(alert)

    for item in suppressed_rules:
        if item.get("rule_id") != rule_id:
            continue

        policy_src_ip = item.get("src_ip")

        if policy_src_ip is None or policy_src_ip == src_ip:
            return item.get("reason", "Suppressed by rule policy")

    return None


def _matches_suppressed_user_agent(
    alert: dict[str, Any],
    suppressed_user_agents: list[dict[str, Any]],
) -> str | None:
    rule_id = alert.get("rule_id")
    src_ip = _get_src_ip(alert)
    user_agent = _get_user_agent(alert)

    for item in suppressed_user_agents:
        policy_rule_id = item.get("rule_id")
        policy_src_ip = item.get("src_ip")

        if policy_rule_id and policy_rule_id != rule_id:
            continue

        if policy_src_ip and policy_src_ip != src_ip:
            continue

        if _contains(user_agent, item.get("user_agent_contains")):
            return item.get("reason", "Suppressed by user-agent policy")

    return None


def _matches_suppressed_path(
    alert: dict[str, Any],
    suppressed_paths: list[dict[str, Any]],
) -> str | None:
    rule_id = alert.get("rule_id")
    src_ip = _get_src_ip(alert)
    url = _get_url(alert)

    for item in suppressed_paths:
        policy_rule_id = item.get("rule_id")
        policy_src_ip = item.get("src_ip")

        if policy_rule_id and policy_rule_id != rule_id:
            continue

        if policy_src_ip and policy_src_ip != src_ip:
            continue

        if _contains(url, item.get("path_contains")):
            return item.get("reason", "Suppressed by path policy")

    return None


def _matches_trusted_service(
    alert: dict[str, Any],
    trusted_services: list[dict[str, Any]],
) -> str | None:
    rule_id = alert.get("rule_id")
    event_type = _get_event_type(alert)
    src_ip = _get_src_ip(alert)
    user_agent = _get_user_agent(alert)

    for item in trusted_services:
        policy_rule_id = item.get("rule_id")
        policy_event_type = item.get("event_type")
        policy_src_ip = item.get("src_ip")

        if policy_rule_id and policy_rule_id != rule_id:
            continue

        if policy_event_type and policy_event_type != event_type:
            continue

        if policy_src_ip and policy_src_ip != src_ip:
            continue

        if _contains(user_agent, item.get("user_agent_contains")):
            return item.get("reason", "Trusted service policy")

    return None


def _matches_trusted_network(
    alert: dict[str, Any],
    trusted_networks: list[dict[str, Any]],
) -> str | None:
    src_ip = _get_src_ip(alert)
    event_type = _get_event_type(alert)
    rule_id = alert.get("rule_id")

    if not src_ip:
        return None

    try:
        parsed_ip = ip_address(src_ip)
    except ValueError:
        return None

    for item in trusted_networks:
        cidr = item.get("cidr")
        suppress_event_types = item.get("suppress_event_types", [])
        suppress_rule_ids = item.get("suppress_rule_ids", [])

        if not cidr:
            continue

        try:
            network = ip_network(cidr, strict=False)
        except ValueError:
            continue

        if parsed_ip not in network:
            continue

        if suppress_event_types and event_type not in suppress_event_types:
            continue

        if suppress_rule_ids and rule_id not in suppress_rule_ids:
            continue

        return item.get("reason", f"Trusted network policy: {cidr}")

    return None


def _matches_maintenance_window(
    alert: dict[str, Any],
    maintenance_windows: list[dict[str, Any]],
) -> str | None:
    rule_id = alert.get("rule_id")
    event_type = _get_event_type(alert)
    alert_time = _parse_timestamp(alert.get("timestamp"))

    if alert_time is None:
        return None

    for item in maintenance_windows:
        start = _parse_timestamp(item.get("start"))
        end = _parse_timestamp(item.get("end"))

        if start is None or end is None:
            continue

        if not (start <= alert_time <= end):
            continue

        suppress_rule_ids = item.get("suppress_rule_ids", [])
        suppress_event_types = item.get("suppress_event_types", [])

        if suppress_rule_ids and rule_id not in suppress_rule_ids:
            continue

        if suppress_event_types and event_type not in suppress_event_types:
            continue

        return item.get("reason", "Scheduled maintenance window")

    return None


def get_suppression_reason(
    alert: dict[str, Any],
    policy: dict[str, Any],
) -> str | None:
    checks = [
        _matches_allowed_ssh_login(alert, policy.get("allowed_ssh_logins", [])),
        _matches_trusted_service(alert, policy.get("trusted_services", [])),
        _matches_suppressed_rule(alert, policy.get("suppressed_rules", [])),
        _matches_suppressed_user_agent(alert, policy.get("suppressed_user_agents", [])),
        _matches_suppressed_path(alert, policy.get("suppressed_paths", [])),
        _matches_maintenance_window(alert, policy.get("maintenance_windows", [])),
        _matches_trusted_network(alert, policy.get("trusted_networks", [])),
    ]

    for reason in checks:
        if reason:
            return reason

    return None


def suppress_alerts(
    alerts: list[dict[str, Any]],
    policy: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    unsuppressed_alerts = []
    suppressed_alerts = []

    for alert in alerts:
        reason = get_suppression_reason(alert, policy)

        if reason:
            suppressed_alert = alert.copy()
            suppressed_alert["suppressed"] = True
            suppressed_alert["suppress_reason"] = reason
            suppressed_alerts.append(suppressed_alert)
        else:
            unsuppressed_alerts.append(alert)

    return unsuppressed_alerts, suppressed_alerts
