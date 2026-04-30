from collections import defaultdict
from typing import Any

from scoring.mitre import enrich_mitre_context
from scoring.sequence import calculate_sequence_score


def _build_summary(src_ip: str, alerts: list[dict[str, Any]], score_result: dict[str, Any]) -> str:
    rule_names = sorted({alert["rule_name"] for alert in alerts})
    observed_stages = score_result.get("observed_stages", [])

    if (
        "web_exploitation_attempt" in observed_stages
        and "ssh_bruteforce" in observed_stages
        and "ssh_successful_login" in observed_stages
    ):
        return (
            f"{src_ip} showed a possible compromise sequence: "
            "web exploitation attempts, SSH brute force activity, and successful SSH login."
        )

    if (
        "ssh_bruteforce" in observed_stages
        and "ssh_successful_login" in observed_stages
    ):
        return (
            f"{src_ip} showed SSH brute force activity followed by successful login."
        )

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

        sources = sorted(
            {
                alert.get("source")
                for alert in sorted_alerts
                if alert.get("source")
            }
        )
        
        mitre_context = enrich_mitre_context(techniques)
        score_result = calculate_sequence_score(sorted_alerts)

        incidents.append(
            {
                "incident_id": f"INC-{index:06d}",
                "src_ip": src_ip,
                "severity": score_result["severity"],
                "confidence_score": score_result["confidence_score"],
                "observed_stages": score_result["observed_stages"],
                "scoring_reasons": score_result["scoring_reasons"],
                "first_seen": first_seen,
                "last_seen": last_seen,
                "alert_count": len(sorted_alerts),
                "sources": sources,
                "unique_rule_count": len({alert["rule_id"] for alert in sorted_alerts}),
                "techniques": mitre_context["techniques"],
                "tactics": mitre_context["tactics"],
                "technique_details": mitre_context["technique_details"],
                "summary": _build_summary(src_ip, sorted_alerts, score_result),
                "alerts": sorted_alerts,
            }
        )

    return incidents
