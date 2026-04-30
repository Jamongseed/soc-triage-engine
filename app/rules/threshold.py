from collections import defaultdict
from datetime import datetime
from typing import Any


def _parse_timestamp(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp)


def detect_ssh_bruteforce(
    events: list[dict[str, Any]],
    threshold: int = 4,
    window_minutes: int = 10,
) -> list[dict[str, Any]]:
    """
    Detect SSH brute force behavior.

    Rule:
    - Same src_ip
    - ssh_failed_login events
    - threshold or more failures within window_minutes
    """
    failed_events_by_ip = defaultdict(list)

    for event in events:
        if event.get("source") != "authlog":
            continue

        if event.get("event_type") != "ssh_failed_login":
            continue

        src_ip = event.get("src_ip") or "unknown"
        failed_events_by_ip[src_ip].append(event)

    alerts = []

    for src_ip, failed_events in failed_events_by_ip.items():
        sorted_events = sorted(failed_events, key=lambda item: item["timestamp"])

        for start_index, start_event in enumerate(sorted_events):
            start_time = _parse_timestamp(start_event["timestamp"])
            window_events = []

            for event in sorted_events[start_index:]:
                current_time = _parse_timestamp(event["timestamp"])
                diff_minutes = (current_time - start_time).total_seconds() / 60

                if diff_minutes <= window_minutes:
                    window_events.append(event)

            if len(window_events) >= threshold:
                users = sorted({event.get("user") for event in window_events if event.get("user")})
                ports = [event.get("src_port") for event in window_events if event.get("src_port")]

                alerts.append(
                    {
                        "rule_id": "SSH-BRUTEFORCE-001",
                        "rule_name": "SSH Brute Force Threshold",
                        "severity": "high",
                        "timestamp": window_events[0]["timestamp"],
                        "source": "authlog",
                        "event_type": "ssh_bruteforce",
                        "src_ip": src_ip,
                        "mitre": ["T1110"],
                        "dedup": {
                            "key": ["src_ip", "rule_id"],
                            "window_minutes": 15,
                        },
                        "evidence": {
                            "matched_field": "failed_login_count",
                            "matched_pattern": f">={threshold} failures within {window_minutes} minutes",
                            "failed_count": len(window_events),
                            "users": users,
                            "ports": ports,
                            "first_seen": window_events[0]["timestamp"],
                            "last_seen": window_events[-1]["timestamp"],
                        },
                        "raw_event": window_events[0],
                    }
                )
                break

    return alerts
