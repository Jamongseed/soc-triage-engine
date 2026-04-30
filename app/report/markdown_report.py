from datetime import datetime
from pathlib import Path
from typing import Any


def _format_mitre_techniques(techniques: list[str]) -> str:
    if not techniques:
        return "None"

    return ", ".join(techniques)


def _format_list(values: list[str]) -> str:
    if not values:
        return "None"

    return ", ".join(values)


def _format_evidence(evidence: dict[str, Any]) -> str:
    matched_field = evidence.get("matched_field", "unknown")
    matched_pattern = evidence.get("matched_pattern", "unknown")

    return f"{matched_field}={matched_pattern}"


def _get_containment_priority(incident: dict[str, Any]) -> str:
    severity = incident.get("severity", "low")
    confidence_score = incident.get("confidence_score", 0)
    observed_stages = set(incident.get("observed_stages", []))

    if (
        severity == "critical"
        or confidence_score >= 85
        or (
            "ssh_bruteforce" in observed_stages
            and "ssh_successful_login" in observed_stages
        )
    ):
        return "P1 - Immediate containment recommended"

    if severity == "high" or confidence_score >= 65:
        return "P2 - Investigate and contain during active response window"

    if severity == "medium" or confidence_score >= 35:
        return "P3 - Review and monitor"

    return "P4 - Low priority review"


def _build_triage_verdict(incident: dict[str, Any]) -> str:
    observed_stages = set(incident.get("observed_stages", []))
    severity = incident.get("severity", "low")
    confidence_score = incident.get("confidence_score", 0)

    if (
        "web_exploitation_attempt" in observed_stages
        and "ssh_bruteforce" in observed_stages
        and "ssh_successful_login" in observed_stages
    ):
        return (
            "Possible compromise sequence detected. The same source IP performed web exploitation attempts, "
            "triggered SSH brute force behavior, and later achieved successful SSH login."
        )

    if (
        "ssh_bruteforce" in observed_stages
        and "ssh_successful_login" in observed_stages
    ):
        return (
            "Possible credential compromise detected. SSH brute force behavior was followed by successful login."
        )

    if "ssh_bruteforce" in observed_stages:
        return "SSH brute force behavior detected. Credential attack activity should be reviewed."

    if "web_exploitation_attempt" in observed_stages:
        return "Web exploitation activity detected. Review target endpoints and response codes."

    if "web_scan" in observed_stages:
        return "Web scanner activity detected. Monitor for follow-up exploitation attempts."

    return (
        f"Suspicious activity detected with {severity.upper()} severity "
        f"and confidence score {confidence_score}."
    )


def _build_why_this_matters(incident: dict[str, Any]) -> list[str]:
    observed_stages = set(incident.get("observed_stages", []))
    reasons = []

    if "web_scan" in observed_stages:
        reasons.append(
            "Web scanning often appears before exploitation attempts and may indicate target discovery activity."
        )

    if "web_exploitation_attempt" in observed_stages:
        reasons.append(
            "Web exploitation attempts may indicate attempts to access sensitive files, inject payloads, or abuse vulnerable endpoints."
        )

    if "ssh_bruteforce" in observed_stages:
        reasons.append(
            "SSH brute force activity indicates repeated credential guessing and increases account compromise risk."
        )

    if "ssh_successful_login" in observed_stages:
        reasons.append(
            "A successful SSH login after suspicious activity should be treated as high-risk until validated."
        )

    if len(incident.get("tactics", [])) >= 3:
        reasons.append(
            "Multiple MITRE ATT&CK tactics were observed, suggesting this is more than a single isolated alert."
        )

    if not reasons:
        reasons.append(
            "The event should be reviewed to determine whether it represents malicious behavior or expected activity."
        )

    return reasons


def _build_recommended_actions(incident: dict[str, Any]) -> list[str]:
    observed_stages = set(incident.get("observed_stages", []))
    actions = []

    if (
        "ssh_bruteforce" in observed_stages
        and "ssh_successful_login" in observed_stages
    ):
        actions.extend(
            [
                "Immediately review the successful SSH session and associated user account.",
                "Rotate credentials for the affected user and check for unauthorized SSH keys.",
                "Review shell history, process execution, and file modifications around the login time.",
            ]
        )
    elif "ssh_bruteforce" in observed_stages:
        actions.extend(
            [
                "Rate-limit or block the source IP at the firewall or SSH access layer.",
                "Review authentication logs for additional failed login bursts from related IP ranges.",
                "Verify whether password authentication should be disabled in favor of key-based access.",
            ]
        )

    if "web_exploitation_attempt" in observed_stages:
        actions.extend(
            [
                "Review web server logs around the first exploitation attempt.",
                "Validate whether the targeted endpoints are vulnerable or exposed unintentionally.",
                "Check application logs for errors, unusual parameters, or suspicious response patterns.",
            ]
        )

    if "web_scan" in observed_stages:
        actions.extend(
            [
                "Check whether the source IP performed broader reconnaissance across other endpoints.",
                "Consider blocking scanner-like traffic if it is not part of an approved assessment.",
            ]
        )

    if not actions:
        actions.append("Review the related raw events and validate whether the activity is expected.")

    # Preserve order while removing duplicates.
    unique_actions = []
    seen = set()

    for action in actions:
        if action not in seen:
            unique_actions.append(action)
            seen.add(action)

    return unique_actions


def _build_evidence_summary(incident: dict[str, Any]) -> list[str]:
    alerts = incident.get("alerts", [])
    evidence_lines = []

    for alert in alerts:
        evidence = alert.get("evidence", {})
        duplicate_count = alert.get("duplicate_count", 1)
        line = (
            f"{alert.get('rule_name', 'Unknown Rule')} "
            f"({alert.get('severity', 'unknown').upper()}) "
            f"matched `{_format_evidence(evidence)}`"
        )

        if duplicate_count > 1:
            line += f" and merged {duplicate_count} repeated alerts"

        evidence_lines.append(line)

    return evidence_lines


def _severity_counts(incidents: list[dict[str, Any]]) -> dict[str, int]:
    severities = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for incident in incidents:
        severity = incident.get("severity", "low")

        if severity in severities:
            severities[severity] += 1

    return severities


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
    severity_counts = _severity_counts(incidents)

    lines = [
        "# SOC Alert Triage Report",
        "",
        "## Report Metadata",
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
        lines.extend(
            [
                f"- Critical Incidents: `{severity_counts['critical']}`",
                f"- High Incidents: `{severity_counts['high']}`",
                f"- Medium Incidents: `{severity_counts['medium']}`",
                f"- Low Incidents: `{severity_counts['low']}`",
                "",
                "The engine grouped raw security alerts into incident-level findings, "
                "suppressed known false positives, deduplicated repeated alerts, "
                "reconstructed attack timelines, enriched MITRE ATT&CK context, "
                "and applied sequence-based severity scoring for analyst review.",
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
        containment_priority = _get_containment_priority(incident)
        triage_verdict = _build_triage_verdict(incident)
        why_this_matters = _build_why_this_matters(incident)
        recommended_actions = _build_recommended_actions(incident)
        evidence_summary = _build_evidence_summary(incident)

        lines.extend(
            [
                f"### {incident['incident_id']} - {incident['severity'].upper()}",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Source IP | `{incident['src_ip']}` |",
                f"| Severity | `{incident['severity']}` |",
                f"| Confidence Score | `{incident.get('confidence_score', 0)}` |",
                f"| Containment Priority | `{containment_priority}` |",
                f"| First Seen | `{incident['first_seen']}` |",
                f"| Last Seen | `{incident['last_seen']}` |",
                f"| Alert Count | `{incident['alert_count']}` |",
                f"| Unique Rule Count | `{incident['unique_rule_count']}` |",
                f"| MITRE Techniques | `{_format_mitre_techniques(incident.get('techniques', []))}` |",
                f"| MITRE Tactics | `{_format_list(incident.get('tactics', []))}` |",
                f"| Observed Stages | `{_format_list(incident.get('observed_stages', []))}` |",
                "",
                "#### Triage Verdict",
                "",
                triage_verdict,
                "",
                "#### Why This Matters",
                "",
            ]
        )

        for reason in why_this_matters:
            lines.append(f"- {reason}")

        lines.extend(
            [
                "",
                "#### Evidence Summary",
                "",
            ]
        )

        for evidence in evidence_summary:
            lines.append(f"- {evidence}")

        lines.extend(
            [
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
                "#### Recommended Actions",
                "",
            ]
        )

        for index, action in enumerate(recommended_actions, start=1):
            lines.append(f"{index}. {action}")

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
                "- Confirm whether the source IP is external, internal, trusted, or already blocked.",
                "- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.",
                "- Review raw logs and surrounding events before closing or escalating the incident.",
                "",
            ]
        )

    return "\n".join(lines)


def write_incident_report(file_path: str | Path, report: str) -> None:
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(report)
