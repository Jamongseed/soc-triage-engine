import json
from pathlib import Path

from parsers.nginx_parser import parse_nginx_file


BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLE_NGINX_LOG = BASE_DIR / "samples" / "nginx_access.log"


def main() -> None:
    events = parse_nginx_file(str(SAMPLE_NGINX_LOG))

    print(f"[+] Parsed events: {len(events)}")

    for event in events:
        print(
            f"{event['timestamp']} "
            f"{event['src_ip']} "
            f"{event['method']} "
            f"{event['url']} "
            f"{event['status']} "
            f"{event['user_agent']}"
        )

    print("\n[+] Normalized JSON")
    print(json.dumps(events, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
