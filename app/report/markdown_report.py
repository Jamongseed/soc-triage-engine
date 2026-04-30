from datetime import datetime
from pathlib import Path
from typing import Any


def _format_mitre_techniques(techniques: list[str]) -> str:
    if not techniques:
        return "None"

    return ", ".join(techniques)


def _format_evidence(evidence: dict[str, Any]) -> str:
    matched_field = evidence.get("matched_field", "unknown")
    matched_pattern = evidence.get("matched_pattern", "unknown")

    return f"{matched_field}={matched_pattern}"


def _format_list(values: list[str]) -> str:
    if not values:
        return "None"

    return ", ".join(values)


def generate_incident_report(
    incidents: list[dict[str, Any]],
    raw_alert_count: int,
    deduped_alert_count: int,
    reduction_rate: float,
) -> str:
    """
    Generate a Markdown incident report from correlated incidents.
    """
    generated_at = datetime.now().isoformat(timespec="seconds")

    lines = [
        "# SOC Alert Triage Report",
        "",
        f"- Generated At: `{generated_at}`",
        f"- Total Incidents: `{len(incidents)}`",
        f"- Raw Alerts: `{raw_alert_count}`",
        f"- Deduped Alerts: `{deduped_alert_count}`",
        f"- Alert Reduction Rate: `{reduction_rate}%`",
        "",
        "## Executive Summary",
        "",
    ]

    if not incidents:
        lines.extend(
            [
                "No incidents were generated from the provided logs.",
                "",
            ]
        )
    else:
        critical_count = sum(1 for incident in incidents if incident["severity"] == "critical")
        high_count = sum(1 for incident in incidents if incident["severity"] == "high")
        medium_count = sum(1 for incident in incidents if incident["severity"] == "medium")
        low_count = sum(1 for incident in incidents if incident["severity"] == "low")

        lines.extend(
            [
                f"- Critical Incidents: `{critical_count}`",
                f"- High Incidents: `{high_count}`",
                f"- Medium Incidents: `{medium_count}`",
                f"- Low Incidents: `{low_count}`",
                "",
                "The engine grouped raw security alerts into incident-level findings, "
                "deduplicated repeated alerts, reconstructed attack timelines, and applied "
                "sequence-based severity scoring for analyst review.",
                "",
            ]
        )

    lines.extend(
        [
            "## Incident Details",
            "",
        ]
    )

    for incident in incidents:
        lines.extend(
            [
                f"### {incident['incident_id']} - {incident['severity'].upper()}",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Source IP | `{incident['src_ip']}` |",
                f"| Severity | `{incident['severity']}` |",
                f"| Confidence Score | `{incident.get('confidence_score', 0)}` |",
                f"| First Seen | `{incident['first_seen']}` |",
                f"| Last Seen | `{incident['last_seen']}` |",
                f"| Alert Count | `{incident['alert_count']}` |",
                f"| Unique Rule Count | `{incident['unique_rule_count']}` |",
                f"| MITRE Techniques | `{_format_mitre_techniques(incident.get('techniques', []))}` |",
                f"| MITRE Tactics | `{_format_list(incident.get('tactics', []))}` |",
                f"| Observed Stages | `{_format_list(incident.get('observed_stages', []))}` |",
                "",
                "#### Summary",
                "",
                incident["summary"],
                "",
                "#### MITRE Context",
                "",
            ]
        )

        for detail in incident.get("technique_details", []):
            tactics = ", ".join(detail.get("tactics", []))
            lines.append(
                f"- `{detail.get('technique')}` {detail.get('name')} "
                f"→ {tactics}"
            )

        lines.extend(
            [
                "",
                "#### Scoring Reasons",
                "",
            ]
        )

        for reason in incident.get("scoring_reasons", []):
            lines.append(f"- {reason}")

        lines.extend(
            [
                "",
                "#### Attack Timeline",
                "",
                "| Time | Severity | Rule | Duplicates | Evidence |",
                "|---|---|---|---:|---|",
            ]
        )

        for item in incident.get("timeline", []):
            lines.append(
                f"| `{item['timestamp']}` "
                f"| `{item['severity']}` "
                f"| {item['title']} "
                f"| `{item.get('duplicate_count', 1)}` "
                f"| `{_format_evidence(item.get('evidence', {}))}` |"
            )

        lines.extend(
            [
                "",
                "#### Analyst Notes",
                "",
                "- Review whether the source IP should be blocked or monitored.",
                "- Check whether similar requests were observed from nearby IP ranges.",
                "- Validate whether the target endpoint was vulnerable or successfully accessed.",
                "",
            ]
        )

    return "\n".join(lines)


def write_incident_report(file_path: str | Path, report: str) -> None:
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(report)
