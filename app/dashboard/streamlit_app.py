import json
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
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
    layout="wide",
    initial_sidebar_state="expanded",
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


def severity_rank(severity: str) -> int:
    order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }
    return order.get((severity or "").lower(), 0)


def severity_color(severity: str) -> str:
    color_map = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#facc15",
        "low": "#22c55e",
    }
    return color_map.get((severity or "").lower(), "#94a3b8")


def severity_badge_html(severity: str) -> str:
    color = severity_color(severity)
    text = (severity or "unknown").upper()
    return f"""
        <span style="
            display:inline-flex;
            align-items:center;
            justify-content:center;
            padding:5px 11px;
            border-radius:999px;
            font-size:12px;
            font-weight:800;
            color:white;
            background:{color};
            box-shadow: 0 6px 18px {color}55;
        ">{text}</span>
    """


def format_display_time(timestamp: str | None) -> str:
    if not timestamp:
        return "-"

    value = str(timestamp)
    value = value.replace("+09:00", "")

    try:
        date_part, time_part = value.split("T", 1)
        month_day = date_part[5:]
        return f"{month_day} {time_part}"
    except ValueError:
        return value


def inject_css() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background:
                radial-gradient(circle at top left, rgba(59,130,246,0.12), transparent 28%),
                radial-gradient(circle at top right, rgba(168,85,247,0.10), transparent 24%),
                linear-gradient(180deg, #07101d 0%, #0b1220 100%);
        }

        .main .block-container {
            max-width: 1480px;
            padding-top: 2.4rem;
            padding-bottom: 2rem;
        }

        section.main > div {
            overflow: visible !important;
        }

        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #0d1628 0%, #0b1220 100%);
            border-right: 1px solid rgba(148, 163, 184, 0.16);
        }

        [data-testid="stSidebar"] * {
            color: #e5edf9;
        }

        div[data-testid="stMetric"] {
            background: transparent;
            border: none;
        }

        .hero-shell {
            padding: 2px;
            border-radius: 28px;
            background: linear-gradient(135deg, #2563eb 0%, #7c3aed 40%, #06b6d4 100%);
            box-shadow: 0 24px 60px rgba(37, 99, 235, 0.20);
            margin-top: 0.35rem;
            margin-bottom: 1.4rem;
            overflow: visible;
        }

        .hero-inner {
            border-radius: 26px;
            background:
                radial-gradient(circle at 15% 20%, rgba(59,130,246,0.22), transparent 18%),
                radial-gradient(circle at 85% 25%, rgba(168,85,247,0.22), transparent 18%),
                linear-gradient(135deg, #081224 0%, #0b1730 45%, #111827 100%);
            padding: 28px 28px 24px 28px;
            color: white;
        }

        .hero-title {
            font-size: 34px;
            font-weight: 900;
            margin-bottom: 8px;
            line-height: 1.1;
            letter-spacing: -0.03em;
        }

        .hero-subtitle {
            font-size: 14px;
            color: #cbd5e1;
            line-height: 1.6;
            margin-bottom: 18px;
        }

        .hero-chip-row {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }

        .hero-chip {
            background: rgba(255,255,255,0.08);
            border: 1px solid rgba(255,255,255,0.08);
            color: #f8fafc;
            border-radius: 999px;
            padding: 8px 12px;
            font-size: 12px;
            font-weight: 700;
            backdrop-filter: blur(10px);
        }

        .kpi-card {
            position: relative;
            overflow: hidden;
            border-radius: 22px;
            padding: 18px 18px 16px 18px;
            background: linear-gradient(180deg, rgba(15,23,42,0.92) 0%, rgba(17,24,39,0.96) 100%);
            border: 1px solid rgba(148,163,184,0.18);
            min-height: 136px;
            box-shadow: 0 10px 30px rgba(2, 6, 23, 0.28);
        }

        .kpi-card::before {
            content: "";
            position: absolute;
            inset: 0;
            background: radial-gradient(circle at top right, rgba(96,165,250,0.14), transparent 30%);
            pointer-events: none;
        }

        .kpi-label {
            font-size: 12px;
            color: #a8b3c7;
            font-weight: 700;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }

        .kpi-value {
            font-size: 34px;
            font-weight: 900;
            line-height: 1;
            color: #ffffff;
            margin-bottom: 10px;
        }

        .kpi-desc {
            font-size: 12px;
            color: #93a4bb;
            line-height: 1.5;
        }

        .section-title {
            font-size: 23px;
            font-weight: 900;
            color: #f8fafc;
            margin-top: 4px;
            margin-bottom: 12px;
            letter-spacing: -0.02em;
        }

        .subtle-title {
            font-size: 16px;
            font-weight: 800;
            color: #f8fafc;
            margin-bottom: 8px;
        }

        .glass-panel {
            background: rgba(15,23,42,0.80);
            border: 1px solid rgba(148,163,184,0.14);
            border-radius: 22px;
            padding: 18px;
            box-shadow: 0 12px 28px rgba(2, 6, 23, 0.18);
        }

        .incident-card {
            border-radius: 20px;
            padding: 18px;
            margin-bottom: 14px;
            background: linear-gradient(180deg, rgba(15,23,42,0.88) 0%, rgba(17,24,39,0.96) 100%);
            border: 1px solid rgba(148,163,184,0.14);
            box-shadow: 0 10px 24px rgba(2, 6, 23, 0.18);
        }

        .incident-card-head {
            display:flex;
            justify-content:space-between;
            align-items:center;
            gap:12px;
            margin-bottom: 10px;
        }

        .incident-card-title {
            color:#f8fafc;
            font-size:18px;
            font-weight:900;
        }

        .incident-meta {
            color:#bfd0e6;
            font-size:13px;
            line-height:1.7;
            margin-bottom: 10px;
        }

        .incident-summary {
            color:#e2e8f0;
            font-size:14px;
            line-height:1.6;
        }

        .flow-wrap {
            display:flex;
            flex-wrap:wrap;
            gap:8px;
            margin-top: 8px;
        }

        .flow-step {
            display:inline-flex;
            align-items:center;
            gap:8px;
            border-radius:999px;
            padding:8px 12px;
            font-size:12px;
            font-weight:700;
            color:#e5edf9;
            background: rgba(59,130,246,0.14);
            border:1px solid rgba(96,165,250,0.22);
        }

        .timeline-item {
            position: relative;
            margin-bottom: 12px;
            border-radius: 18px;
            padding: 16px 16px 14px 16px;
            background: linear-gradient(180deg, rgba(17,24,39,0.95) 0%, rgba(15,23,42,0.98) 100%);
            border: 1px solid rgba(148,163,184,0.12);
            box-shadow: 0 10px 20px rgba(2, 6, 23, 0.15);
        }

        .timeline-top {
            display:flex;
            justify-content:space-between;
            align-items:center;
            gap:10px;
            margin-bottom: 10px;
        }

        .timeline-title {
            color:#f8fafc;
            font-size:15px;
            font-weight:800;
        }

        .timeline-time {
            color:#94a3b8;
            font-size:12px;
            white-space: nowrap;
        }

        .timeline-body {
            color:#d6e2f2;
            font-size:13px;
            line-height:1.6;
        }

        .timeline-pill {
            display:inline-block;
            margin-right:8px;
            margin-top:6px;
            padding:5px 9px;
            border-radius:999px;
            font-size:12px;
            font-weight:700;
            color:#dbeafe;
            background: rgba(59,130,246,0.12);
            border:1px solid rgba(96,165,250,0.18);
        }

        .sidebar-kpi {
            background: linear-gradient(180deg, rgba(15,23,42,0.94) 0%, rgba(17,24,39,0.98) 100%);
            border: 1px solid rgba(148,163,184,0.14);
            border-radius: 18px;
            padding: 14px;
            margin-bottom: 10px;
        }

        .sidebar-kpi-label {
            font-size: 12px;
            color: #9db0c8;
            font-weight: 700;
            margin-bottom: 6px;
        }

        .sidebar-kpi-value {
            font-size: 24px;
            color: #ffffff;
            font-weight: 900;
        }

        .small-note {
            color: #94a3b8;
            font-size: 12px;
        }

        .stTabs [data-baseweb="tab-list"] {
            gap: 8px;
        }

        .stTabs [data-baseweb="tab"] {
            border-radius: 999px;
            background: rgba(255,255,255,0.03);
            padding-left: 18px;
            padding-right: 18px;
        }

        .stTabs [aria-selected="true"] {
            background: linear-gradient(135deg, rgba(37,99,235,0.22), rgba(124,58,237,0.22));
            border: 1px solid rgba(96,165,250,0.18);
        }

        .stDataFrame {
            border-radius: 18px;
            overflow: hidden;
            border: 1px solid rgba(148,163,184,0.12);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def kpi_card_html(label: str, value: str, desc: str) -> str:
    return f"""
        <div class="kpi-card">
            <div class="kpi-label">{label}</div>
            <div class="kpi-value">{value}</div>
            <div class="kpi-desc">{desc}</div>
        </div>
    """


def incident_card_html(incident: dict[str, Any]) -> str:
    border_color = severity_color(incident.get("severity", ""))
    return f"""
        <div class="incident-card" style="border-left: 5px solid {border_color};">
            <div class="incident-card-head">
                <div class="incident-card-title">
                    {incident.get("incident_id", "-")} | {incident.get("src_ip", "-")}
                </div>
                <div>{severity_badge_html(incident.get("severity", ""))}</div>
            </div>
            <div class="incident-meta">
                Alert Count: <b>{incident.get("alert_count", 0)}</b> |
                Unique Rules: <b>{incident.get("unique_rule_count", 0)}</b> |
                Confidence: <b>{incident.get("confidence_score", 0)}</b><br>
                First Seen: <b>{format_display_time(incident.get("first_seen"))}</b><br>
                Last Seen: <b>{format_display_time(incident.get("last_seen"))}</b><br>
                MITRE Techniques: <b>{", ".join(incident.get("techniques", [])) or "-"}</b><br>
                Observed Stages: <b>{", ".join(incident.get("observed_stages", [])) or "-"}</b>
            </div>
            <div class="incident-summary">{incident.get("summary", "-")}</div>
        </div>
    """


def build_attack_flow_html(incident: dict[str, Any]) -> str:
    steps = []
    for item in incident.get("timeline", []):
        steps.append(f'<span class="flow-step">{item.get("title", "-")}</span>')
    return "<div class='flow-wrap'>" + "".join(steps) + "</div>"


def build_timeline_html(incident: dict[str, Any]) -> str:
    html_parts = []
    for item in incident.get("timeline", []):
        evidence = item.get("evidence", {})
        html_parts.append(
            f"""
            <div class="timeline-item" style="border-left: 4px solid {severity_color(item.get("severity", ""))};">
                <div class="timeline-top">
                    <div class="timeline-title">
                        {item.get("title", "-")} {severity_badge_html(item.get("severity", ""))}
                    </div>
                    <div class="timeline-time">{format_display_time(item.get("timestamp"))}</div>
                </div>
                <div class="timeline-body">
                    <span class="timeline-pill">Rule ID: {item.get("rule_id", "-")}</span>
                    <span class="timeline-pill">Duplicates: {item.get("duplicate_count", 1)}</span>
                    <br>
                    Matched Field: <b>{evidence.get("matched_field", "-")}</b><br>
                    Matched Pattern: <b>{evidence.get("matched_pattern", "-")}</b>
                </div>
            </div>
            """
        )
    return "".join(html_parts) if html_parts else "<div class='small-note'>No timeline events available.</div>"


def alerts_to_dataframe(alerts: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for alert in alerts:
        evidence = alert.get("evidence", {})
        rows.append(
            {
                "Alert ID": alert.get("alert_id"),
                "Time": format_display_time(alert.get("timestamp")),
                "Source IP": alert.get("src_ip"),
                "Severity": (alert.get("severity") or "").upper(),
                "Rule": alert.get("rule_name"),
                "Rule ID": alert.get("rule_id"),
                "Duplicates": alert.get("duplicate_count", 1),
                "Dedup Window": alert.get("dedup_window_minutes"),
                "Matched Field": evidence.get("matched_field"),
                "Matched Pattern": evidence.get("matched_pattern"),
            }
        )
    df = pd.DataFrame(rows)
    if not df.empty:
        df["Severity Rank"] = df["Severity"].map(
            {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        ).fillna(0)
        df = df.sort_values(["Severity Rank", "Time"], ascending=[False, True]).drop(columns=["Severity Rank"])
    return df


def incidents_to_dataframe(incidents: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for incident in incidents:
        rows.append(
            {
                "Incident ID": incident.get("incident_id"),
                "Source IP": incident.get("src_ip"),
                "Severity": (incident.get("severity") or "").upper(),
                "Confidence": incident.get("confidence_score", 0),
                "First Seen": format_display_time(incident.get("first_seen")),
                "Last Seen": format_display_time(incident.get("last_seen")),
                "Alert Count": incident.get("alert_count"),
                "Unique Rules": incident.get("unique_rule_count"),
                "MITRE Techniques": ", ".join(incident.get("techniques", [])),
                "Observed Stages": ", ".join(incident.get("observed_stages", [])),
                "Summary": incident.get("summary"),
            }
        )
    df = pd.DataFrame(rows)
    if not df.empty:
        df["Severity Rank"] = df["Severity"].map(
            {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        ).fillna(0)
        df = df.sort_values(["Severity Rank", "Alert Count"], ascending=[False, False]).drop(columns=["Severity Rank"])
    return df


def suppressed_to_dataframe(alerts: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for alert in alerts:
        rows.append(
            {
                "Alert ID": alert.get("alert_id"),
                "Time": format_display_time(alert.get("timestamp")),
                "Dedup Window": alert.get("dedup_window_minutes"),
                "Source IP": alert.get("src_ip"),
                "Rule": alert.get("rule_name"),
                "Reason": alert.get("suppress_reason"),
            }
        )
    return pd.DataFrame(rows)


def timeline_to_dataframe(incident: dict[str, Any]) -> pd.DataFrame:
    rows = []
    for idx, item in enumerate(incident.get("timeline", []), start=1):
        evidence = item.get("evidence", {})
        rows.append(
            {
                "Step": idx,
                "Time": format_display_time(item.get("timestamp")),
                "Severity": (item.get("severity") or "").upper(),
                "Rule": item.get("title"),
                "Rule ID": item.get("rule_id"),
                "Duplicates": item.get("duplicate_count", 1),
                "Matched Field": evidence.get("matched_field"),
                "Matched Pattern": evidence.get("matched_pattern"),
            }
        )
    return pd.DataFrame(rows)


def make_incident_severity_chart(incidents: list[dict[str, Any]]) -> go.Figure:
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }
    for incident in incidents:
        key = (incident.get("severity") or "").upper()
        if key in counts:
            counts[key] += 1

    fig = go.Figure(
        data=[
            go.Pie(
                labels=list(counts.keys()),
                values=list(counts.values()),
                hole=0.60,
                marker=dict(colors=["#ef4444", "#f97316", "#facc15", "#22c55e"]),
                textinfo="label+value",
            )
        ]
    )
    fig.update_layout(
        template="plotly_dark",
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=320,
        showlegend=False,
    )
    return fig


def make_top_rules_chart(deduped_df: pd.DataFrame) -> go.Figure:
    if deduped_df.empty:
        fig = go.Figure()
        fig.update_layout(template="plotly_dark", height=320)
        return fig

    chart_df = (
        deduped_df.groupby("Rule")
        .size()
        .reset_index(name="Count")
        .sort_values("Count", ascending=True)
        .tail(10)
    )

    fig = px.bar(
        chart_df,
        x="Count",
        y="Rule",
        orientation="h",
        text="Count",
        color="Count",
        color_continuous_scale="Blues",
    )
    fig.update_layout(
        template="plotly_dark",
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=320,
        coloraxis_showscale=False,
        yaxis_title=None,
        xaxis_title=None,
    )
    fig.update_traces(textposition="outside")
    return fig


def make_alert_severity_chart(deduped_df: pd.DataFrame) -> go.Figure:
    if deduped_df.empty:
        fig = go.Figure()
        fig.update_layout(template="plotly_dark", height=300)
        return fig

    chart_df = (
        deduped_df.groupby("Severity")
        .size()
        .reset_index(name="Count")
    )

    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    chart_df["Order"] = chart_df["Severity"].map(order).fillna(0)
    chart_df = chart_df.sort_values("Order", ascending=False)

    fig = px.bar(
        chart_df,
        x="Severity",
        y="Count",
        color="Severity",
        color_discrete_map={
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#facc15",
            "LOW": "#22c55e",
        },
        text="Count",
    )
    fig.update_layout(
        template="plotly_dark",
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=300,
        showlegend=False,
        xaxis_title=None,
        yaxis_title=None,
    )
    fig.update_traces(textposition="outside")
    return fig


def make_alert_by_ip_chart(deduped_df: pd.DataFrame) -> go.Figure:
    if deduped_df.empty:
        fig = go.Figure()
        fig.update_layout(template="plotly_dark", height=300)
        return fig

    chart_df = (
        deduped_df.groupby("Source IP")
        .size()
        .reset_index(name="Count")
        .sort_values("Count", ascending=False)
        .head(10)
    )

    fig = px.bar(
        chart_df,
        x="Source IP",
        y="Count",
        text="Count",
        color="Count",
        color_continuous_scale="Tealgrn",
    )
    fig.update_layout(
        template="plotly_dark",
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=300,
        coloraxis_showscale=False,
        xaxis_title=None,
        yaxis_title=None,
    )
    fig.update_traces(textposition="outside")
    return fig


def make_timeline_scatter(incident: dict[str, Any]) -> go.Figure:
    timeline_df = timeline_to_dataframe(incident)
    if timeline_df.empty:
        fig = go.Figure()
        fig.update_layout(template="plotly_dark", height=320)
        return fig

    fig = px.scatter(
        timeline_df,
        x="Time",
        y="Step",
        color="Severity",
        hover_data=["Rule", "Rule ID", "Matched Field", "Matched Pattern"],
        color_discrete_map={
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#facc15",
            "LOW": "#22c55e",
        },
        size=[14] * len(timeline_df),
    )
    fig.update_traces(mode="lines+markers")
    fig.update_layout(
        template="plotly_dark",
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=320,
        yaxis_title="Step",
        xaxis_title=None,
    )
    return fig


inject_css()

raw_alerts = load_json(ALERTS_FILE, [])
suppressed_alerts = load_json(SUPPRESSED_ALERTS_FILE, [])
deduped_alerts = load_json(DEDUPED_ALERTS_FILE, [])
incidents = load_json(INCIDENTS_FILE, [])
report_text = load_text(REPORT_FILE)

if not OUTPUTS_DIR.exists() or not INCIDENTS_FILE.exists():
    st.warning("No analysis output found. Run `python app/main.py` first.")
    st.stop()

raw_count = len(raw_alerts)
suppressed_count = len(suppressed_alerts)
deduped_count = len(deduped_alerts)
incident_count = len(incidents)
reduction_rate = round(((raw_count - deduped_count) / raw_count) * 100, 2) if raw_count else 0.0

critical_incidents = sum(1 for x in incidents if (x.get("severity") or "").lower() == "critical")
high_incidents = sum(1 for x in incidents if (x.get("severity") or "").lower() == "high")
medium_incidents = sum(1 for x in incidents if (x.get("severity") or "").lower() == "medium")
low_incidents = sum(1 for x in incidents if (x.get("severity") or "").lower() == "low")

incident_df = incidents_to_dataframe(incidents)
deduped_df = alerts_to_dataframe(deduped_alerts)
suppressed_df = suppressed_to_dataframe(suppressed_alerts)

st.markdown(
    f"""
    <div class="hero-shell">
        <div class="hero-inner">
            <div class="hero-title">SOC Alert Triage Engine</div>
            <div class="hero-subtitle">
                Multi-source alert triage dashboard for suppression, deduplication,
                incident correlation, and attack timeline reconstruction.
            </div>
            <div class="hero-chip-row">
                <div class="hero-chip">Raw Alerts: {raw_count}</div>
                <div class="hero-chip">Suppressed: {suppressed_count}</div>
                <div class="hero-chip">Deduped: {deduped_count}</div>
                <div class="hero-chip">Incidents: {incident_count}</div>
                <div class="hero-chip">Reduction Rate: {reduction_rate}%</div>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("Controls")

    severity_options = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    selected_severities = st.multiselect(
        "Incident Severity Filter",
        severity_options,
        default=severity_options,
    )

    min_alert_count = st.slider(
        "Minimum Alert Count",
        min_value=1,
        max_value=max(1, max([incident.get("alert_count", 1) for incident in incidents], default=1)),
        value=1,
    )

    show_markdown_report = st.checkbox("Show markdown report preview", value=True)

    st.markdown("### Snapshot")
    st.markdown(
        f"""
        <div class="sidebar-kpi">
            <div class="sidebar-kpi-label">Critical Incidents</div>
            <div class="sidebar-kpi-value">{critical_incidents}</div>
        </div>
        <div class="sidebar-kpi">
            <div class="sidebar-kpi-label">High Incidents</div>
            <div class="sidebar-kpi-value">{high_incidents}</div>
        </div>
        <div class="sidebar-kpi">
            <div class="sidebar-kpi-label">Suppressed Alerts</div>
            <div class="sidebar-kpi-value">{suppressed_count}</div>
        </div>
        <div class="small-note">Use the filters to narrow the incident view.</div>
        """,
        unsafe_allow_html=True,
    )

k1, k2, k3, k4, k5 = st.columns(5)
with k1:
    st.markdown(kpi_card_html("Raw Alerts", str(raw_count), "Before suppression and deduplication"), unsafe_allow_html=True)
with k2:
    st.markdown(kpi_card_html("Suppressed", str(suppressed_count), "Allowlist-filtered alerts"), unsafe_allow_html=True)
with k3:
    st.markdown(kpi_card_html("Deduped Alerts", str(deduped_count), "Noise-reduced alert set"), unsafe_allow_html=True)
with k4:
    st.markdown(kpi_card_html("Incidents", str(incident_count), "Correlated investigation units"), unsafe_allow_html=True)
with k5:
    st.markdown(kpi_card_html("Reduction Rate", f"{reduction_rate}%", "Reduction after processing"), unsafe_allow_html=True)

tab1, tab2, tab3, tab4, tab5 = st.tabs(
    ["Executive Overview", "Incident Explorer", "Alerts", "Suppressed", "Report"]
)

with tab1:
    st.markdown('<div class="section-title">Executive Overview</div>', unsafe_allow_html=True)

    filtered_incidents = [
        inc for inc in incidents
        if (inc.get("severity", "").upper() in selected_severities)
        and (inc.get("alert_count", 0) >= min_alert_count)
    ]

    overview_left, overview_right = st.columns([1.15, 1])

    with overview_left:
        st.markdown('<div class="glass-panel">', unsafe_allow_html=True)
        st.markdown('<div class="subtle-title">Incident Summary</div>', unsafe_allow_html=True)

        if not filtered_incidents:
            st.info("No incidents match the selected filters.")
        else:
            filtered_df = incidents_to_dataframe(filtered_incidents)
            st.dataframe(filtered_df, use_container_width=True, hide_index=True)

        st.markdown('</div>', unsafe_allow_html=True)

    with overview_right:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown('<div class="glass-panel">', unsafe_allow_html=True)
            st.markdown('<div class="subtle-title">Severity Distribution</div>', unsafe_allow_html=True)
            st.plotly_chart(make_incident_severity_chart(filtered_incidents), use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)
        with c2:
            st.markdown('<div class="glass-panel">', unsafe_allow_html=True)
            st.markdown('<div class="subtle-title">Top Rules</div>', unsafe_allow_html=True)
            st.plotly_chart(make_top_rules_chart(deduped_df), use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="subtle-title" style="margin-top:14px;">Incident Cards</div>', unsafe_allow_html=True)
    if not filtered_incidents:
        st.info("No incidents available.")
    else:
        for incident in sorted(
            filtered_incidents,
            key=lambda x: (-severity_rank(x.get("severity", "")), -(x.get("alert_count") or 0)),
        ):
            st.markdown(incident_card_html(incident), unsafe_allow_html=True)

with tab2:
    st.markdown('<div class="section-title">Incident Explorer</div>', unsafe_allow_html=True)

    if not incidents:
        st.info("No incidents generated.")
    else:
        sorted_incidents = sorted(
            incidents,
            key=lambda x: (-severity_rank(x.get("severity", "")), -(x.get("alert_count") or 0)),
        )
        incident_labels = [
            f"{inc['incident_id']} | {inc['src_ip']} | {(inc.get('severity') or '').upper()} | alerts={inc.get('alert_count', 0)}"
            for inc in sorted_incidents
        ]

        selected_label = st.selectbox("Select Incident", incident_labels)
        selected_incident = next(
            inc for inc in sorted_incidents
            if f"{inc['incident_id']} | {inc['src_ip']} | {(inc.get('severity') or '').upper()} | alerts={inc.get('alert_count', 0)}" == selected_label
        )

        left, right = st.columns([1.0, 1.25])

        with left:
            st.markdown(incident_card_html(selected_incident), unsafe_allow_html=True)

            st.markdown('<div class="glass-panel">', unsafe_allow_html=True)
            st.markdown('<div class="subtle-title">Attack Flow</div>', unsafe_allow_html=True)
            st.markdown(build_attack_flow_html(selected_incident), unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

            st.markdown('<div style="height:12px"></div>', unsafe_allow_html=True)

            st.markdown('<div class="glass-panel">', unsafe_allow_html=True)
            st.markdown('<div class="subtle-title">Timeline Table</div>', unsafe_allow_html=True)
            timeline_df = timeline_to_dataframe(selected_incident)
            if timeline_df.empty:
                st.info("No timeline data.")
            else:
                st.dataframe(timeline_df, use_container_width=True, hide_index=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with right:
            top_chart, top_dummy = st.columns([1, 0.0001])
            with top_chart:
                st.markdown('<div class="glass-panel">', unsafe_allow_html=True)
                st.markdown('<div class="subtle-title">Timeline Chart</div>', unsafe_allow_html=True)
                st.plotly_chart(make_timeline_scatter(selected_incident), use_container_width=True)
                st.markdown('</div>', unsafe_allow_html=True)

            st.markdown('<div style="height:12px"></div>', unsafe_allow_html=True)

            st.markdown('<div class="glass-panel">', unsafe_allow_html=True)
            st.markdown('<div class="subtle-title">Attack Timeline</div>', unsafe_allow_html=True)
            st.markdown(build_timeline_html(selected_incident), unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

with tab3:
    st.markdown('<div class="section-title">Alert Analytics</div>', unsafe_allow_html=True)

    alert_left, alert_right = st.columns([1.2, 1])

    with alert_left:
        st.markdown('<div class="glass-panel">', unsafe_allow_html=True)
        st.markdown('<div class="subtle-title">Deduplicated Alerts</div>', unsafe_allow_html=True)
        if deduped_df.empty:
            st.info("No deduplicated alerts available.")
        else:
            st.dataframe(deduped_df, use_container_width=True, hide_index=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with alert_right:
        st.markdown('<div class="glass-panel">', unsafe_allow_html=True)
        st.markdown('<div class="subtle-title">Alerts by Severity</div>', unsafe_allow_html=True)
        st.plotly_chart(make_alert_severity_chart(deduped_df), use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div style="height:12px"></div>', unsafe_allow_html=True)

        st.markdown('<div class="glass-panel">', unsafe_allow_html=True)
        st.markdown('<div class="subtle-title">Alerts by Source IP</div>', unsafe_allow_html=True)
        st.plotly_chart(make_alert_by_ip_chart(deduped_df), use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

with tab4:
    st.markdown('<div class="section-title">Suppressed Alerts</div>', unsafe_allow_html=True)
    st.markdown('<div class="glass-panel">', unsafe_allow_html=True)

    if suppressed_df.empty:
        st.info("No suppressed alerts.")
    else:
        st.dataframe(suppressed_df, use_container_width=True, hide_index=True)
        csv_data = suppressed_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download Suppressed Alerts CSV",
            data=csv_data,
            file_name="suppressed_alerts.csv",
            mime="text/csv",
        )

    st.markdown('</div>', unsafe_allow_html=True)

with tab5:
    st.markdown('<div class="section-title">Generated Report</div>', unsafe_allow_html=True)
    st.markdown('<div class="glass-panel">', unsafe_allow_html=True)

    if not show_markdown_report:
        st.info("Enable report preview from the sidebar.")
    elif not report_text:
        st.info("No report file found.")
    else:
        st.code(report_text, language="markdown")

    st.markdown('</div>', unsafe_allow_html=True)