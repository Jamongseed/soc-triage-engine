import argparse
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

DEFAULT_NGINX_LOG = BASE_DIR / "samples" / "nginx_access.log"
DEFAULT_AUTH_LOG = BASE_DIR / "samples" / "auth.log"
DEFAULT_SURICATA_LOG = BASE_DIR / "samples" / "suricata_eve.json"
DEFAULT_RULES_DIR = BASE_DIR / "rules"
DEFAULT_ALLOWLIST_FILE = BASE_DIR / "config" / "allowlist.yml"
DEFAULT_OUTPUTS_DIR = BASE_DIR / "outputs"


def resolve_path(path_value: str | Path) -> Path:
    path = Path(path_value)

    if path.is_absolute():
        return path

    return BASE_DIR / path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SOC Alert Triage Engine - multi-source alert correlation pipeline"
    )

    parser.add_argument(
        "--nginx-log",
        default=str(DEFAULT_NGINX_LOG),
        help="Path to Nginx access.log file.",
    )

    parser.add_argument(
        "--auth-log",
        default=str(DEFAULT_AUTH_LOG),
        help="Path to Linux auth.log file.",
    )

    parser.add_argument(
        "--suricata-log",
        default=str(DEFAULT_SURICATA_LOG),
        help="Path to Suricata EVE JSON file. If the file does not exist, it is skipped.",
    )

    parser.add_argument(
        "--rules-dir",
        default=str(DEFAULT_RULES_DIR),
        help="Path to detection rules directory.",
    )

    parser.add_argument(
        "--allowlist",
        default=str(DEFAULT_ALLOWLIST_FILE),
        help="Path to suppression policy YAML file.",
    )

    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUTS_DIR),
        help="Directory to write analysis outputs.",
    )

    parser.add_argument(
        "--auth-year",
        type=int,
        default=2026,
        help="Year to use when parsing syslog-style auth.log timestamps.",
    )

    parser.add_argument(
        "--ssh-threshold",
        type=int,
        default=4,
        help="Failed SSH login threshold for brute-force detection.",
    )

    parser.add_argument(
        "--ssh-window-minutes",
        type=int,
        default=10,
        help="Time window in minutes for SSH brute-force threshold detection.",
    )

    parser.add_argument(
        "--dedup-window-minutes",
        type=int,
        default=10,
        help="Fallback deduplication window in minutes when a rule does not define one.",
    )

    return parser.parse_args()


def write_json(file_path: Path, data: object) -> None:
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def parse_optional_suricata_file(file_path: Path) -> list[dict]:
    if not file_path.exists():
        return []

    return parse_suricata_eve_file(str(file_path))


def main() -> None:
    args = parse_args()

    nginx_log = resolve_path(args.nginx_log)
    auth_log = resolve_path(args.auth_log)
    suricata_log = resolve_path(args.suricata_log)
    rules_dir = resolve_path(args.rules_dir)
    allowlist_file = resolve_path(args.allowlist)
    outputs_dir = resolve_path(args.output_dir)

    outputs_dir.mkdir(exist_ok=True)

    nginx_events = parse_nginx_file(str(nginx_log))
    auth_events = parse_authlog_file(str(auth_log), year=args.auth_year)
    suricata_events = parse_optional_suricata_file(suricata_log)

    events = nginx_events + auth_events + suricata_events

    rules = load_rules(rules_dir)
    allowlist = load_allowlist(allowlist_file)

    rule_alerts = match_rules(events, rules)
    threshold_alerts = detect_ssh_bruteforce(
        events,
        threshold=args.ssh_threshold,
        window_minutes=args.ssh_window_minutes,
    )

    raw_alerts = rule_alerts + threshold_alerts

    for index, alert in enumerate(raw_alerts, start=1):
        alert["alert_id"] = f"A-{index:06d}"

    unsuppressed_alerts, suppressed_alerts = suppress_alerts(raw_alerts, allowlist)

    deduped_alerts = deduplicate_alerts(
        unsuppressed_alerts,
        window_minutes=args.dedup_window_minutes,
    )
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

    alerts_output = outputs_dir / "alerts.json"
    suppressed_alerts_output = outputs_dir / "suppressed_alerts.json"
    deduped_alerts_output = outputs_dir / "deduped_alerts.json"
    incidents_output = outputs_dir / "incidents.json"
    report_output = outputs_dir / "incident_report.md"

    write_json(alerts_output, raw_alerts)
    write_json(suppressed_alerts_output, suppressed_alerts)
    write_json(deduped_alerts_output, deduped_alerts)
    write_json(incidents_output, incidents)
    write_incident_report(report_output, report)

    print("[+] Input files")
    print(f"    nginx_log={nginx_log}")
    print(f"    auth_log={auth_log}")
    print(f"    suricata_log={suricata_log}")
    print(f"    rules_dir={rules_dir}")
    print(f"    allowlist={allowlist_file}")
    print(f"    output_dir={outputs_dir}")

    print(f"\n[+] Parsed nginx events: {len(nginx_events)}")
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
        for alert in suppressed_alerts[:30]:
            print(
                f"{alert['alert_id']} "
                f"{alert['timestamp']} "
                f"{alert['src_ip']} "
                f"{alert['rule_name']} "
                f"reason={alert['suppress_reason']}"
            )

        if len(suppressed_alerts) > 30:
            print(f"    ... {len(suppressed_alerts) - 30} more suppressed alerts")

    print("\n[+] Deduped Alerts")
    for alert in deduped_alerts[:50]:
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

    if len(deduped_alerts) > 50:
        print(f"    ... {len(deduped_alerts) - 50} more deduped alerts")

    print("\n[+] Incidents")
    for incident in incidents:
        print(
            f"{incident['incident_id']} "
            f"{incident['src_ip']} "
            f"{incident['severity'].upper()} "
            f"alerts={incident['alert_count']} "
            f"rules={incident['unique_rule_count']} "
            f"sources={','.join(incident.get('sources', []))}"
        )
        print(f"    {incident['summary']}")

        for item in incident["timeline"][:10]:
            duplicate_count = item.get("duplicate_count", 1)
            print(
                f"    - {item['timestamp']} "
                f"{item['severity'].upper()} "
                f"{item['title']} "
                f"duplicates={duplicate_count} "
                f"{item['evidence'].get('matched_field')}="
                f"{item['evidence'].get('matched_pattern')}"
            )

        if len(incident["timeline"]) > 10:
            print(f"      ... {len(incident['timeline']) - 10} more timeline items")

    print(f"\n[+] Raw alerts written to {alerts_output}")
    print(f"[+] Suppressed alerts written to {suppressed_alerts_output}")
    print(f"[+] Deduped alerts written to {deduped_alerts_output}")
    print(f"[+] Incidents written to {incidents_output}")
    print(f"[+] Incident report written to {report_output}")


if __name__ == "__main__":
    main()
