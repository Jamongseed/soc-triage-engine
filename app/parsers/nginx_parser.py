import re
from datetime import datetime
from urllib.parse import unquote


NGINX_COMBINED_LOG_PATTERN = re.compile(
    r'(?P<src_ip>\S+) '
    r'\S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) '
    r'(?P<body_bytes_sent>\S+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)


def parse_nginx_timestamp(raw_timestamp: str) -> str:
    """
    Convert Nginx timestamp format to ISO-8601 string.

    Example:
    30/Apr/2026:10:28:11 +0900
    -> 2026-04-30T10:28:11+09:00
    """
    dt = datetime.strptime(raw_timestamp, "%d/%b/%Y:%H:%M:%S %z")
    return dt.isoformat()


def parse_nginx_line(line: str) -> dict | None:
    """
    Parse one Nginx combined access log line into a normalized event.
    """
    match = NGINX_COMBINED_LOG_PATTERN.match(line.strip())

    if not match:
        return None

    data = match.groupdict()
    decoded_url = unquote(data["url"])

    return {
        "timestamp": parse_nginx_timestamp(data["timestamp"]),
        "source": "nginx",
        "event_type": "web_request",
        "src_ip": data["src_ip"],
        "user": None,
        "method": data["method"],
        "url": decoded_url,
        "protocol": data["protocol"],
        "status": int(data["status"]),
        "body_bytes_sent": (
            int(data["body_bytes_sent"])
            if data["body_bytes_sent"].isdigit()
            else 0
        ),
        "referer": None if data["referer"] == "-" else data["referer"],
        "user_agent": data["user_agent"],
        "raw": line.strip(),
    }


def parse_nginx_file(file_path: str) -> list[dict]:
    """
    Parse an Nginx access.log file into normalized events.
    Invalid lines are skipped.
    """
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            event = parse_nginx_line(line)

            if event is None:
                print(f"[!] Failed to parse line {line_number}: {line.strip()}")
                continue

            events.append(event)

    return events
