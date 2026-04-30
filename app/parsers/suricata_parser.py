import json
from typing import Any


def normalize_suricata_timestamp(timestamp: str) -> str:
    """
    Normalize Suricata timestamp.

    Expected examples:
    - 2026-04-30T11:02:00+09:00
    - 2026-04-30T11:02:00+0900
    """
    if not timestamp:
        return ""

    if timestamp.endswith("+0900"):
        return timestamp[:-5] + "+09:00"

    return timestamp


def parse_suricata_eve_line(line: str) -> dict[str, Any] | None:
    """
    Parse one Suricata EVE JSON line into normalized event format.
    """
    line = line.strip()

    if not line:
        return None

    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    if data.get("event_type") != "alert":
        return None

    alert = data.get("alert", {})

    return {
        "timestamp": normalize_suricata_timestamp(data.get("timestamp", "")),
        "source": "suricata",
        "event_type": "ids_alert",
        "src_ip": data.get("src_ip"),
        "dest_ip": data.get("dest_ip"),
        "src_port": data.get("src_port"),
        "dest_port": data.get("dest_port"),
        "proto": data.get("proto"),
        "signature": alert.get("signature"),
        "category": alert.get("category"),
        "suricata_severity": alert.get("severity"),
        "raw": line,
    }


def parse_suricata_eve_file(file_path: str) -> list[dict[str, Any]]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            event = parse_suricata_eve_line(line)

            if event is not None:
                events.append(event)

    return events
