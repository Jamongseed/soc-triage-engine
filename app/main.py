import json
from pathlib import Path

from parsers.nginx_parser import parse_nginx_file
from rules.rule_loader import load_rules
from rules.matcher import match_rules


BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLE_NGINX_LOG = BASE_DIR / "samples" / "nginx_access.log"
RULES_DIR = BASE_DIR / "rules"
OUTPUTS_DIR = BASE_DIR / "outputs"


def main() -> None:
    OUTPUTS_DIR.mkdir(exist_ok=True)

    events = parse_nginx_file(str(SAMPLE_NGINX_LOG))
    rules = load_rules(RULES_DIR)
    alerts = match_rules(events, rules)

    print(f"[+] Parsed events: {len(events)}")
    print(f"[+] Loaded rules: {len(rules)}")
    print(f"[+] Generated alerts: {len(alerts)}")

    for alert in alerts:
        print(
            f"{alert['alert_id']} "
            f"{alert['timestamp']} "
            f"{alert['src_ip']} "
            f"{alert['severity'].upper()} "
            f"{alert['rule_name']} "
            f"{alert['evidence'].get('matched_field')}="
            f"{alert['evidence'].get('matched_pattern')}"
        )

    alerts_output = OUTPUTS_DIR / "alerts.json"

    with open(alerts_output, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=2, ensure_ascii=False)

    print(f"[+] Alerts written to {alerts_output}")


if __name__ == "__main__":
    main()
