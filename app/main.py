import json
from pathlib import Path

from correlation.correlator import correlate_alerts_by_src_ip
from correlation.dedup import calculate_reduction_rate, deduplicate_alerts
from correlation.suppress import load_allowlist, suppress_alerts
from correlation.timeline import attach_timelines
from parsers.authlog_parser import parse_authlog_file
from parsers.nginx_parser import parse_nginx_file
from parsers.suricata_parser import parse_suricata_eve_file
from report.markdown_report import generate_incident_report, write_incident_report
from rules.matcher import match_rules
from rules.rule_loader import load_rules
from rules.threshold import detect_ssh_bruteforce


BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLE_NGINX_LOG = BASE_DIR / "samples" / "nginx_access.log"
SAMPLE_AUTH_LOG = BASE_DIR / "samples" / "auth.log"
SAMPLE_SURICATA_LOG = BASE_DIR / "samples" / "suricata_eve.json"
RULES_DIR = BASE_DIR / "rules"
ALLOWLIST_FILE = BASE_DIR / "config" / "allowlist.yml"
OUTPUTS_DIR = BASE_DIR / "outputs"


def write_json(file_path: Path, data: object) -> None:
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def parse_optional_suricata_file(file_path: Path) -> list[dict]:
    if not file_path.exists():
        return []

    return parse_suricata_eve_file(str(file_path))


def main() -> None:
    OUTPUTS_DIR.mkdir(exist_ok=True)

    nginx_events = parse_nginx_file(str(SAMPLE_NGINX_LOG))
    auth_events = parse_authlog_file(str(SAMPLE_AUTH_LOG), year=2026)
    suricata_events = parse_optional_suricata_file(SAMPLE_SURICATA_LOG)

    events = nginx_events + auth_events + suricata_events

    rules = load_rules(RULES_DIR)
    allowlist = load_allowlist(ALLOWLIST_FILE)

    rule_alerts = match_rules(events, rules)
    threshold_alerts = detect_ssh_bruteforce(
        events,
        threshold=4,
        window_minutes=10,
    )

    raw_alerts = rule_alerts + threshold_alerts

    for index, alert in enumerate(raw_alerts, start=1):
        alert["alert_id"] = f"A-{index:06d}"

    unsuppressed_alerts, suppressed_alerts = suppress_alerts(raw_alerts, allowlist)

    deduped_alerts = deduplicate_alerts(unsuppressed_alerts, window_minutes=10)
    reduction_rate = calculate_reduction_rate(
        original_count=len(raw_alerts),
        deduped_count=len(deduped_alerts),
    )

    incidents = correlate_alerts_by_src_ip(deduped_alerts)
    incidents = attach_timelines(incidents)

    report = generate_incident_report(
        incidents=incidents,
        raw_alert_count=len(raw_alerts),
        deduped_alert_count=len(deduped_alerts),
        reduction_rate=reduction_rate,
    )

    alerts_output = OUTPUTS_DIR / "alerts.json"
    suppressed_alerts_output = OUTPUTS_DIR / "suppressed_alerts.json"
    deduped_alerts_output = OUTPUTS_DIR / "deduped_alerts.json"
    incidents_output = OUTPUTS_DIR / "incidents.json"
    report_output = OUTPUTS_DIR / "incident_report.md"

    write_json(alerts_output, raw_alerts)
    write_json(suppressed_alerts_output, suppressed_alerts)
    write_json(deduped_alerts_output, deduped_alerts)
    write_json(incidents_output, incidents)
    write_incident_report(report_output, report)

    print(f"[+] Parsed nginx events: {len(nginx_events)}")
    print(f"[+] Parsed auth events: {len(auth_events)}")
    print(f"[+] Parsed suricata events: {len(suricata_events)}")
    print(f"[+] Parsed total events: {len(events)}")
    print(f"[+] Loaded rules: {len(rules)}")
    print(f"[+] Generated rule alerts: {len(rule_alerts)}")
    print(f"[+] Generated threshold alerts: {len(threshold_alerts)}")
    print(f"[+] Generated raw alerts: {len(raw_alerts)}")
    print(f"[+] Suppressed alerts: {len(suppressed_alerts)}")
    print(f"[+] Deduped alerts: {len(deduped_alerts)}")
    print(f"[+] Alert reduction rate: {reduction_rate}%")
    print(f"[+] Generated incidents: {len(incidents)}")

    if suppressed_alerts:
        print("\n[+] Suppressed Alerts")
        for alert in suppressed_alerts:
            print(
                f"{alert['alert_id']} "
                f"{alert['timestamp']} "
                f"{alert['src_ip']} "
                f"{alert['rule_name']} "
                f"reason={alert['suppress_reason']}"
            )

    print("\n[+] Deduped Alerts")
    for alert in deduped_alerts:
        print(
            f"{alert['alert_id']} "
            f"{alert['timestamp']} "
            f"{alert['src_ip']} "
            f"{alert['severity'].upper()} "
            f"{alert['rule_name']} "
            f"duplicates={alert['duplicate_count']} "
            f"{alert['evidence'].get('matched_field')}="
            f"{alert['evidence'].get('matched_pattern')}"
        )

    print("\n[+] Incidents")
    for incident in incidents:
        print(
            f"{incident['incident_id']} "
            f"{incident['src_ip']} "
            f"{incident['severity'].upper()} "
            f"alerts={incident['alert_count']} "
            f"rules={incident['unique_rule_count']}"
        )
        print(f"    {incident['summary']}")

        for item in incident["timeline"]:
            duplicate_count = item.get("duplicate_count", 1)
            print(
                f"    - {item['timestamp']} "
                f"{item['severity'].upper()} "
                f"{item['title']} "
                f"duplicates={duplicate_count} "
                f"{item['evidence'].get('matched_field')}="
                f"{item['evidence'].get('matched_pattern')}"
            )

    print(f"\n[+] Raw alerts written to {alerts_output}")
    print(f"[+] Suppressed alerts written to {suppressed_alerts_output}")
    print(f"[+] Deduped alerts written to {deduped_alerts_output}")
    print(f"[+] Incidents written to {incidents_output}")
    print(f"[+] Incident report written to {report_output}")


if __name__ == "__main__":
    main()
