from collections import defaultdict
from datetime import datetime
from typing import Any


DEFAULT_DEDUP_KEY = ["src_ip", "rule_id"]
DEFAULT_DEDUP_WINDOW_MINUTES = 10


def _parse_timestamp(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp)


def _get_nested_value(data: dict[str, Any], field: str) -> Any:
    """
    Read a field from alert first, then raw_event.

    Example:
    - src_ip
    - rule_id
    - raw_event.user
    """
    if field in data:
        return data.get(field)

    raw_event = data.get("raw_event", {})
    if isinstance(raw_event, dict) and field in raw_event:
        return raw_event.get(field)

    return None


def _get_dedup_key_fields(alert: dict[str, Any]) -> list[str]:
    dedup = alert.get("dedup", {})

    if not isinstance(dedup, dict):
        return DEFAULT_DEDUP_KEY

    key_fields = dedup.get("key", DEFAULT_DEDUP_KEY)

    if not key_fields:
        return DEFAULT_DEDUP_KEY

    return key_fields


def _get_dedup_window_minutes(
    alert: dict[str, Any],
    fallback_window_minutes: int,
) -> int:
    dedup = alert.get("dedup", {})

    if not isinstance(dedup, dict):
        return fallback_window_minutes

    try:
        return int(dedup.get("window_minutes", fallback_window_minutes))
    except (TypeError, ValueError):
        return fallback_window_minutes


def _build_dedup_key(alert: dict[str, Any]) -> tuple[str, ...]:
    key_fields = _get_dedup_key_fields(alert)
    key_parts = []

    for field in key_fields:
        value = _get_nested_value(alert, field)
        key_parts.append(str(value if value is not None else "unknown"))

    return tuple(key_parts)


def deduplicate_alerts(
    alerts: list[dict[str, Any]],
    window_minutes: int = DEFAULT_DEDUP_WINDOW_MINUTES,
) -> list[dict[str, Any]]:
    """
    Deduplicate repeated alerts using rule-specific dedup configuration.

    If an alert contains:
      alert["dedup"]["key"]
      alert["dedup"]["window_minutes"]

    then those values are used.

    Otherwise, fallback behavior is:
      key = src_ip + rule_id
      window = window_minutes
    """
    grouped_alerts: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)

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

            group_window_minutes = _get_dedup_window_minutes(
                current_group[0],
                fallback_window_minutes=window_minutes,
            )

            first_timestamp = _parse_timestamp(current_group[0]["timestamp"])
            current_timestamp = _parse_timestamp(alert["timestamp"])
            diff_minutes = (current_timestamp - first_timestamp).total_seconds() / 60

            if diff_minutes <= group_window_minutes:
                current_group.append(alert)
            else:
                deduped_alerts.append(_merge_alert_group(current_group, group_window_minutes))
                current_group = [alert]

        if current_group:
            group_window_minutes = _get_dedup_window_minutes(
                current_group[0],
                fallback_window_minutes=window_minutes,
            )
            deduped_alerts.append(_merge_alert_group(current_group, group_window_minutes))

    return sorted(deduped_alerts, key=lambda item: item["timestamp"])


def _merge_alert_group(
    alerts: list[dict[str, Any]],
    window_minutes: int,
) -> dict[str, Any]:
    """
    Merge a group of duplicate alerts into one representative alert.
    """
    first_alert = alerts[0].copy()
    first_alert["first_seen"] = alerts[0]["timestamp"]
    first_alert["last_seen"] = alerts[-1]["timestamp"]
    first_alert["duplicate_count"] = len(alerts)
    first_alert["related_alert_ids"] = [alert["alert_id"] for alert in alerts]
    first_alert["dedup_window_minutes"] = window_minutes
    first_alert["dedup_key"] = list(_build_dedup_key(first_alert))

    if len(alerts) > 1:
        first_alert["dedup_summary"] = (
            f"{len(alerts)} repeated alerts merged "
            f"within {window_minutes} minutes"
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
