import json
from pathlib import Path

from correlation.correlator import correlate_alerts_by_src_ip
from correlation.dedup import calculate_reduction_rate, deduplicate_alerts
from correlation.timeline import attach_timelines
from parsers.nginx_parser import parse_nginx_file
from rules.matcher import match_rules
from rules.rule_loader import load_rules


BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLE_NGINX_LOG = BASE_DIR / "samples" / "nginx_access.log"
RULES_DIR = BASE_DIR / "rules"
OUTPUTS_DIR = BASE_DIR / "outputs"


def write_json(file_path: Path, data: object) -> None:
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def main() -> None:
    OUTPUTS_DIR.mkdir(exist_ok=True)

    events = parse_nginx_file(str(SAMPLE_NGINX_LOG))
    rules = load_rules(RULES_DIR)

    raw_alerts = match_rules(events, rules)
    deduped_alerts = deduplicate_alerts(raw_alerts, window_minutes=10)
    reduction_rate = calculate_reduction_rate(
        original_count=len(raw_alerts),
        deduped_count=len(deduped_alerts),
    )

    incidents = correlate_alerts_by_src_ip(deduped_alerts)
    incidents = attach_timelines(incidents)

    alerts_output = OUTPUTS_DIR / "alerts.json"
    deduped_alerts_output = OUTPUTS_DIR / "deduped_alerts.json"
    incidents_output = OUTPUTS_DIR / "incidents.json"

    write_json(alerts_output, raw_alerts)
    write_json(deduped_alerts_output, deduped_alerts)
    write_json(incidents_output, incidents)

    print(f"[+] Parsed events: {len(events)}")
    print(f"[+] Loaded rules: {len(rules)}")
    print(f"[+] Generated raw alerts: {len(raw_alerts)}")
    print(f"[+] Deduped alerts: {len(deduped_alerts)}")
    print(f"[+] Alert reduction rate: {reduction_rate}%")
    print(f"[+] Generated incidents: {len(incidents)}")

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
    print(f"[+] Deduped alerts written to {deduped_alerts_output}")
    print(f"[+] Incidents written to {incidents_output}")


if __name__ == "__main__":
    main()
