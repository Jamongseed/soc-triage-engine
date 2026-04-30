import re
from datetime import datetime
from typing import Any


AUTH_LOG_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+'
    r'(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'sshd\[(?P<pid>\d+)\]:\s+'
    r'(?P<message>.*)'
)

FAILED_PASSWORD_PATTERN = re.compile(
    r'Failed password for (?:(?:invalid user )?)(?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2'
)

ACCEPTED_PASSWORD_PATTERN = re.compile(
    r'Accepted password for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2'
)


def _parse_auth_timestamp(month: str, day: str, time_value: str, year: int = 2026) -> str:
    raw_timestamp = f"{year} {month} {day} {time_value}"
    dt = datetime.strptime(raw_timestamp, "%Y %b %d %H:%M:%S")
    return dt.isoformat()


def parse_authlog_line(line: str, year: int = 2026) -> dict[str, Any] | None:
    match = AUTH_LOG_PATTERN.match(line.strip())

    if not match:
        return None

    data = match.groupdict()
    message = data["message"]

    failed_match = FAILED_PASSWORD_PATTERN.search(message)
    if failed_match:
        failed_data = failed_match.groupdict()
        return {
            "timestamp": _parse_auth_timestamp(data["month"], data["day"], data["time"], year),
            "source": "authlog",
            "event_type": "ssh_failed_login",
            "src_ip": failed_data["src_ip"],
            "user": failed_data["user"],
            "src_port": int(failed_data["src_port"]),
            "host": data["host"],
            "pid": int(data["pid"]),
            "auth_result": "failed",
            "raw": line.strip(),
        }

    accepted_match = ACCEPTED_PASSWORD_PATTERN.search(message)
    if accepted_match:
        accepted_data = accepted_match.groupdict()
        return {
            "timestamp": _parse_auth_timestamp(data["month"], data["day"], data["time"], year),
            "source": "authlog",
            "event_type": "ssh_success_login",
            "src_ip": accepted_data["src_ip"],
            "user": accepted_data["user"],
            "src_port": int(accepted_data["src_port"]),
            "host": data["host"],
            "pid": int(data["pid"]),
            "auth_result": "success",
            "raw": line.strip(),
        }

    return None


def parse_authlog_file(file_path: str, year: int = 2026) -> list[dict[str, Any]]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            event = parse_authlog_line(line, year=year)

            if event is None:
                print(f"[!] Failed to parse auth.log line {line_number}: {line.strip()}")
                continue

            events.append(event)

    return events
