from pathlib import Path
from typing import Any

import yaml


def load_allowlist(file_path: str | Path) -> dict[str, Any]:
    path = Path(file_path)

    if not path.exists():
        return {"allowed_ssh_logins": []}

    with open(path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    data.setdefault("allowed_ssh_logins", [])
    return data


def _is_allowed_ssh_success(alert: dict[str, Any], allowlist: dict[str, Any]) -> tuple[bool, str | None]:
    if alert.get("rule_id") != "SSH-SUCCESS-001":
        return False, None

    raw_event = alert.get("raw_event", {})
    src_ip = raw_event.get("src_ip")
    user = raw_event.get("user")

    for item in allowlist.get("allowed_ssh_logins", []):
        if item.get("src_ip") == src_ip and item.get("user") == user:
            return True, item.get("reason", "Allowed SSH login")

    return False, None


def suppress_alerts(
    alerts: list[dict[str, Any]],
    allowlist: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Suppress alerts that match allowlist rules.

    Returns:
    - remaining alerts
    - suppressed alerts
    """
    remaining_alerts = []
    suppressed_alerts = []

    for alert in alerts:
        is_allowed, reason = _is_allowed_ssh_success(alert, allowlist)

        if is_allowed:
            suppressed_alert = alert.copy()
            suppressed_alert["suppressed"] = True
            suppressed_alert["suppress_reason"] = reason
            suppressed_alerts.append(suppressed_alert)
            continue

        remaining_alerts.append(alert)

    return remaining_alerts, suppressed_alerts
