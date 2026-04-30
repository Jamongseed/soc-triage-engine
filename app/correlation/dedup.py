from collections import defaultdict
from datetime import datetime
from typing import Any


def _parse_timestamp(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp)


def _build_dedup_key(alert: dict[str, Any]) -> tuple[str, str]:
    """
    Build a simple dedup key.

    Current rule:
    - same source IP
    - same rule ID

    Example:
    45.12.33.10 + WEB-SQLI-001
    """
    return (
        alert.get("src_ip") or "unknown",
        alert.get("rule_id") or "unknown",
    )


def deduplicate_alerts(
    alerts: list[dict[str, Any]],
    window_minutes: int = 10,
) -> list[dict[str, Any]]:
    """
    Deduplicate repeated alerts within a time window.

    Alerts with the same src_ip and rule_id within the configured window
    are merged into one representative alert.

    The representative alert keeps:
    - first_seen
    - last_seen
    - duplicate_count
    - related_alert_ids
    """
    grouped_alerts: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for alert in sorted(alerts, key=lambda item: item["timestamp"]):
        key = _build_dedup_key(alert)
        grouped_alerts[key].append(alert)

    deduped_alerts = []

    for _, group in grouped_alerts.items():
        current_group = []

        for alert in group:
            if not current_group:
                current_group.append(alert)
                continue

            first_timestamp = _parse_timestamp(current_group[0]["timestamp"])
            current_timestamp = _parse_timestamp(alert["timestamp"])
            diff_minutes = (current_timestamp - first_timestamp).total_seconds() / 60

            if diff_minutes <= window_minutes:
                current_group.append(alert)
            else:
                deduped_alerts.append(_merge_alert_group(current_group))
                current_group = [alert]

        if current_group:
            deduped_alerts.append(_merge_alert_group(current_group))

    return sorted(deduped_alerts, key=lambda item: item["timestamp"])


def _merge_alert_group(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Merge a group of duplicate alerts into one alert.
    """
    first_alert = alerts[0].copy()
    first_alert["first_seen"] = alerts[0]["timestamp"]
    first_alert["last_seen"] = alerts[-1]["timestamp"]
    first_alert["duplicate_count"] = len(alerts)
    first_alert["related_alert_ids"] = [alert["alert_id"] for alert in alerts]

    if len(alerts) > 1:
        first_alert["dedup_summary"] = (
            f"{len(alerts)} repeated alerts merged "
            f"for {first_alert['src_ip']} / {first_alert['rule_id']}"
        )
    else:
        first_alert["dedup_summary"] = "No duplicates"

    return first_alert


def calculate_reduction_rate(original_count: int, deduped_count: int) -> float:
    """
    Calculate alert reduction rate as percentage.
    """
    if original_count == 0:
        return 0.0

    return round(((original_count - deduped_count) / original_count) * 100, 2)
