from __future__ import annotations

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
    - trusted_networks
    """
    path = Path(file_path)

    if not path.exists():
        return {
            "allowed_ssh_logins": [],
            "suppressed_rules": [],
            "trusted_networks": [],
        }

    with open(path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    data.setdefault("allowed_ssh_logins", [])
    data.setdefault("suppressed_rules", [])
    data.setdefault("trusted_networks", [])

    return data


def _get_raw_event(alert: dict[str, Any]) -> dict[str, Any]:
    raw_event = alert.get("raw_event", {})
    if isinstance(raw_event, dict):
        return raw_event

    return {}


def _get_user(alert: dict[str, Any]) -> str | None:
    raw_event = _get_raw_event(alert)
    return alert.get("user") or raw_event.get("user")


def _get_src_ip(alert: dict[str, Any]) -> str | None:
    raw_event = _get_raw_event(alert)
    return alert.get("src_ip") or raw_event.get("src_ip")


def _get_event_type(alert: dict[str, Any]) -> str | None:
    raw_event = _get_raw_event(alert)
    return alert.get("event_type") or raw_event.get("event_type")


def _matches_allowed_ssh_login(
    alert: dict[str, Any],
    allowed_ssh_logins: list[dict[str, Any]],
) -> str | None:
    """
    Suppress known SSH successful logins from trusted IP/user pairs.
    """
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
    """
    Suppress specific rule_id + optional src_ip combinations.

    If src_ip is omitted in the policy, the rule_id is suppressed globally.
    """
    rule_id = alert.get("rule_id")
    src_ip = _get_src_ip(alert)

    for item in suppressed_rules:
        if item.get("rule_id") != rule_id:
            continue

        policy_src_ip = item.get("src_ip")

        if policy_src_ip is None or policy_src_ip == src_ip:
            return item.get("reason", "Suppressed by rule policy")

    return None


def _matches_trusted_network(
    alert: dict[str, Any],
    trusted_networks: list[dict[str, Any]],
) -> str | None:
    """
    Suppress selected event types from trusted CIDR ranges.
    """
    src_ip = _get_src_ip(alert)
    event_type = _get_event_type(alert)

    if not src_ip:
        return None

    try:
        parsed_ip = ip_address(src_ip)
    except ValueError:
        return None

    for item in trusted_networks:
        cidr = item.get("cidr")
        suppress_event_types = item.get("suppress_event_types", [])

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

        return item.get("reason", f"Trusted network policy: {cidr}")

    return None


def get_suppression_reason(
    alert: dict[str, Any],
    policy: dict[str, Any],
) -> str | None:
    """
    Return suppression reason if alert matches any suppression policy.
    """
    checks = [
        _matches_allowed_ssh_login(
            alert,
            policy.get("allowed_ssh_logins", []),
        ),
        _matches_suppressed_rule(
            alert,
            policy.get("suppressed_rules", []),
        ),
        _matches_trusted_network(
            alert,
            policy.get("trusted_networks", []),
        ),
    ]

    for reason in checks:
        if reason:
            return reason

    return None


def suppress_alerts(
    alerts: list[dict[str, Any]],
    policy: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Split alerts into unsuppressed and suppressed alerts.
    """
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
