from collections import defaultdict
from datetime import datetime
from typing import Any


SEVERITY_SCORE = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _parse_timestamp(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp)


def _calculate_incident_severity(alerts: list[dict[str, Any]]) -> str:
    """
    Calculate incident severity from related alerts.

    Rule:
    - If one source IP triggers 3 or more different rule types, escalate to critical.
    - Otherwise use the highest alert severity.
    """
    unique_rules = {alert["rule_id"] for alert in alerts}
    max_score = max(SEVERITY_SCORE.get(alert["severity"], 1) for alert in alerts)

    if len(unique_rules) >= 3:
        return "critical"

    for severity, score in SEVERITY_SCORE.items():
        if score == max_score:
            return severity

    return "low"


def _build_summary(src_ip: str, alerts: list[dict[str, Any]]) -> str:
    rule_names = sorted({alert["rule_name"] for alert in alerts})

    if len(rule_names) == 1:
        return f"{src_ip} triggered {rule_names[0]}."

    return f"{src_ip} triggered multiple suspicious activities: {', '.join(rule_names)}."


def correlate_alerts_by_src_ip(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Group alerts by src_ip and convert them into incidents.
    """
    grouped_alerts = defaultdict(list)

    for alert in alerts:
        src_ip = alert.get("src_ip") or "unknown"
        grouped_alerts[src_ip].append(alert)

    incidents = []

    for index, (src_ip, related_alerts) in enumerate(grouped_alerts.items(), start=1):
        sorted_alerts = sorted(related_alerts, key=lambda alert: alert["timestamp"])
        first_seen = sorted_alerts[0]["timestamp"]
        last_seen = sorted_alerts[-1]["timestamp"]
        techniques = sorted(
            {
                technique
                for alert in sorted_alerts
                for technique in alert.get("mitre", [])
            }
        )

        incidents.append(
            {
                "incident_id": f"INC-{index:06d}",
                "src_ip": src_ip,
                "severity": _calculate_incident_severity(sorted_alerts),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "alert_count": len(sorted_alerts),
                "unique_rule_count": len({alert["rule_id"] for alert in sorted_alerts}),
                "techniques": techniques,
                "summary": _build_summary(src_ip, sorted_alerts),
                "alerts": sorted_alerts,
            }
        )

    return incidents
