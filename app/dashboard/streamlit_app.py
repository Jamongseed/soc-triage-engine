import json
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st


BASE_DIR = Path(__file__).resolve().parent.parent.parent
OUTPUTS_DIR = BASE_DIR / "outputs"

ALERTS_FILE = OUTPUTS_DIR / "alerts.json"
SUPPRESSED_ALERTS_FILE = OUTPUTS_DIR / "suppressed_alerts.json"
DEDUPED_ALERTS_FILE = OUTPUTS_DIR / "deduped_alerts.json"
INCIDENTS_FILE = OUTPUTS_DIR / "incidents.json"
REPORT_FILE = OUTPUTS_DIR / "incident_report.md"


st.set_page_config(
    page_title="SOC Alert Triage Engine",
    page_icon="🛡️",
    layout="wide",
)


def load_json(file_path: Path, default: Any) -> Any:
    if not file_path.exists():
        return default

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_text(file_path: Path) -> str:
    if not file_path.exists():
        return ""

    return file_path.read_text(encoding="utf-8")


def severity_badge(severity: str) -> str:
    severity = severity.lower()

    if severity == "critical":
        return "🔴 CRITICAL"
    if severity == "high":
        return "🟠 HIGH"
    if severity == "medium":
        return "🟡 MEDIUM"
    if severity == "low":
        return "🟢 LOW"

    return severity.upper()


def alerts_to_dataframe(alerts: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []

    for alert in alerts:
        evidence = alert.get("evidence", {})
        rows.append(
            {
                "Alert ID": alert.get("alert_id"),
                "Time": alert.get("timestamp"),
                "Source IP": alert.get("src_ip"),
                "Severity": alert.get("severity"),
                "Rule": alert.get("rule_name"),
                "Rule ID": alert.get("rule_id"),
                "Duplicates": alert.get("duplicate_count", 1),
                "Evidence": f"{evidence.get('matched_field')}={evidence.get('matched_pattern')}",
            }
        )

    return pd.DataFrame(rows)


def suppressed_to_dataframe(alerts: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []

    for alert in alerts:
        rows.append(
            {
                "Alert ID": alert.get("alert_id"),
                "Time": alert.get("timestamp"),
                "Source IP": alert.get("src_ip"),
                "Rule": alert.get("rule_name"),
                "Reason": alert.get("suppress_reason"),
            }
        )

    return pd.DataFrame(rows)


def incidents_to_dataframe(incidents: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []

    for incident in incidents:
        rows.append(
            {
                "Incident ID": incident.get("incident_id"),
                "Source IP": incident.get("src_ip"),
                "Severity": incident.get("severity"),
                "First Seen": incident.get("first_seen"),
                "Last Seen": incident.get("last_seen"),
                "Alert Count": incident.get("alert_count"),
                "Unique Rule Count": incident.get("unique_rule_count"),
                "MITRE Techniques": ", ".join(incident.get("techniques", [])),
                "Summary": incident.get("summary"),
            }
        )

    return pd.DataFrame(rows)


def timeline_to_dataframe(incident: dict[str, Any]) -> pd.DataFrame:
    rows = []

    for item in incident.get("timeline", []):
        evidence = item.get("evidence", {})
        rows.append(
            {
                "Time": item.get("timestamp"),
                "Severity": item.get("severity"),
                "Rule": item.get("title"),
                "Rule ID": item.get("rule_id"),
                "Duplicates": item.get("duplicate_count", 1),
                "Evidence": f"{evidence.get('matched_field')}={evidence.get('matched_pattern')}",
            }
        )

    return pd.DataFrame(rows)


raw_alerts = load_json(ALERTS_FILE, [])
suppressed_alerts = load_json(SUPPRESSED_ALERTS_FILE, [])
deduped_alerts = load_json(DEDUPED_ALERTS_FILE, [])
incidents = load_json(INCIDENTS_FILE, [])
report = load_text(REPORT_FILE)

raw_count = len(raw_alerts)
suppressed_count = len(suppressed_alerts)
deduped_count = len(deduped_alerts)
incident_count = len(incidents)

if raw_count == 0:
    reduction_rate = 0.0
else:
    reduction_rate = round(((raw_count - deduped_count) / raw_count) * 100, 2)


st.title("SOC Alert Triage Engine")
st.caption(
    "Alert suppression, deduplication, incident correlation, and attack timeline reconstruction dashboard"
)

if not OUTPUTS_DIR.exists() or not INCIDENTS_FILE.exists():
    st.warning(
        "No output files found. Run `python app/main.py` first to generate analysis results."
    )
    st.stop()


st.subheader("Overview")

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Raw Alerts", raw_count)
col2.metric("Suppressed Alerts", suppressed_count)
col3.metric("Deduped Alerts", deduped_count)
col4.metric("Incidents", incident_count)
col5.metric("Reduction Rate", f"{reduction_rate}%")


st.divider()

tab_overview, tab_incidents, tab_alerts, tab_suppressed, tab_report = st.tabs(
    [
        "Incident Overview",
        "Incident Detail",
        "Deduped Alerts",
        "Suppressed Alerts",
        "Report Preview",
    ]
)


with tab_overview:
    st.subheader("Incident List")

    incident_df = incidents_to_dataframe(incidents)

    if incident_df.empty:
        st.info("No incidents generated.")
    else:
        severity_filter = st.multiselect(
            "Filter by severity",
            options=sorted(incident_df["Severity"].dropna().unique().tolist()),
            default=sorted(incident_df["Severity"].dropna().unique().tolist()),
        )

        filtered_df = incident_df[incident_df["Severity"].isin(severity_filter)]

        st.dataframe(filtered_df, use_container_width=True, hide_index=True)


with tab_incidents:
    st.subheader("Incident Detail")

    if not incidents:
        st.info("No incidents available.")
    else:
        incident_options = [
            f"{incident['incident_id']} | {incident['src_ip']} | {incident['severity'].upper()}"
            for incident in incidents
        ]

        selected = st.selectbox("Select incident", incident_options)
        selected_index = incident_options.index(selected)
        incident = incidents[selected_index]

        left, right = st.columns([1, 2])

        with left:
            st.markdown("### Incident Summary")
            st.write(f"**Incident ID:** `{incident['incident_id']}`")
            st.write(f"**Source IP:** `{incident['src_ip']}`")
            st.write(f"**Severity:** {severity_badge(incident['severity'])}")
            st.write(f"**First Seen:** `{incident['first_seen']}`")
            st.write(f"**Last Seen:** `{incident['last_seen']}`")
            st.write(f"**Alert Count:** `{incident['alert_count']}`")
            st.write(f"**Unique Rule Count:** `{incident['unique_rule_count']}`")
            st.write(
                f"**MITRE Techniques:** `{', '.join(incident.get('techniques', []))}`"
            )

        with right:
            st.markdown("### Analyst Summary")
            st.info(incident.get("summary", "No summary available."))

            st.markdown("### Attack Timeline")
            timeline_df = timeline_to_dataframe(incident)

            if timeline_df.empty:
                st.info("No timeline events available.")
            else:
                st.dataframe(timeline_df, use_container_width=True, hide_index=True)


with tab_alerts:
    st.subheader("Deduped Alerts")

    deduped_df = alerts_to_dataframe(deduped_alerts)

    if deduped_df.empty:
        st.info("No deduped alerts available.")
    else:
        st.dataframe(deduped_df, use_container_width=True, hide_index=True)

        st.markdown("### Alert Count by Rule")
        rule_counts = (
            deduped_df.groupby("Rule")
            .size()
            .reset_index(name="Count")
            .sort_values("Count", ascending=False)
        )
        st.bar_chart(rule_counts.set_index("Rule"))


with tab_suppressed:
    st.subheader("Suppressed Alerts")

    suppressed_df = suppressed_to_dataframe(suppressed_alerts)

    if suppressed_df.empty:
        st.info("No suppressed alerts.")
    else:
        st.dataframe(suppressed_df, use_container_width=True, hide_index=True)


with tab_report:
    st.subheader("Generated Markdown Report")

    if not report:
        st.info("No report generated.")
    else:
        st.markdown(report)
