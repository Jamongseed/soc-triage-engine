import json
from pathlib import Path

from correlation.correlator import correlate_alerts_by_src_ip
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
    alerts = match_rules(events, rules)
    incidents = correlate_alerts_by_src_ip(alerts)
    incidents = attach_timelines(incidents)

    alerts_output = OUTPUTS_DIR / "alerts.json"
    incidents_output = OUTPUTS_DIR / "incidents.json"

    write_json(alerts_output, alerts)
    write_json(incidents_output, incidents)

    print(f"[+] Parsed events: {len(events)}")
    print(f"[+] Loaded rules: {len(rules)}")
    print(f"[+] Generated alerts: {len(alerts)}")
    print(f"[+] Generated incidents: {len(incidents)}")

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
            print(
                f"    - {item['timestamp']} "
                f"{item['severity'].upper()} "
                f"{item['title']} "
                f"{item['evidence'].get('matched_field')}="
                f"{item['evidence'].get('matched_pattern')}"
            )

    print(f"\n[+] Alerts written to {alerts_output}")
    print(f"[+] Incidents written to {incidents_output}")


if __name__ == "__main__":
    main()
