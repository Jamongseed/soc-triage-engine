from typing import Any


def build_timeline(incident: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Build a simple attack timeline from incident alerts.
    """
    timeline = []

    for alert in sorted(incident["alerts"], key=lambda item: item["timestamp"]):
        timeline.append(
            {
                "timestamp": alert["timestamp"],
                "rule_id": alert["rule_id"],
                "title": alert["rule_name"],
                "severity": alert["severity"],
                "duplicate_count": alert.get("duplicate_count", 1),
                "dedup_window_minutes": alert.get("dedup_window_minutes"),
                "first_seen": alert.get("first_seen", alert["timestamp"]),
                "last_seen": alert.get("last_seen", alert["timestamp"]),
                "evidence": alert["evidence"],
            }
        )

    return timeline


def attach_timelines(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Attach timeline field to every incident.
    """
    for incident in incidents:
        incident["timeline"] = build_timeline(incident)

    return incidents
