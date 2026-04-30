from typing import Any


def _contains_any(value: str | None, patterns: list[str]) -> tuple[bool, str | None]:
    if value is None:
        return False, None

    lowered_value = value.lower()

    for pattern in patterns:
        if pattern.lower() in lowered_value:
            return True, pattern

    return False, None


def _equals_any(value: str | None, candidates: list[str]) -> tuple[bool, str | None]:
    if value is None:
        return False, None

    for candidate in candidates:
        if value == candidate:
            return True, candidate

    return False, None


def match_rule(event: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any] | None:
    if event.get("source") != rule.get("source"):
        return None

    conditions = rule.get("conditions", {})
    evidence = {}

    if "url_contains" in conditions:
        matched, pattern = _contains_any(event.get("url"), conditions["url_contains"])
        if matched:
            evidence["url"] = event.get("url")
            evidence["matched_field"] = "url"
            evidence["matched_pattern"] = pattern

    if "user_agent_contains" in conditions:
        matched, pattern = _contains_any(
            event.get("user_agent"),
            conditions["user_agent_contains"],
        )
        if matched:
            evidence["user_agent"] = event.get("user_agent")
            evidence["matched_field"] = "user_agent"
            evidence["matched_pattern"] = pattern

    if "event_type_equals" in conditions:
        matched, candidate = _equals_any(
            event.get("event_type"),
            conditions["event_type_equals"],
        )
        if matched:
            evidence["event_type"] = event.get("event_type")
            evidence["matched_field"] = "event_type"
            evidence["matched_pattern"] = candidate

    if "signature_contains" in conditions:
        matched, pattern = _contains_any(
            event.get("signature"),
            conditions["signature_contains"],
        )
        if matched:
            evidence["signature"] = event.get("signature")
            evidence["matched_field"] = "signature"
            evidence["matched_pattern"] = pattern

    if "category_contains" in conditions:
        matched, pattern = _contains_any(
            event.get("category"),
            conditions["category_contains"],
        )
        if matched:
            evidence["category"] = event.get("category")
            evidence["matched_field"] = "category"
            evidence["matched_pattern"] = pattern

    if not evidence:
        return None

    return {
        "rule_id": rule["id"],
        "rule_name": rule["title"],
        "severity": rule["severity"],
        "timestamp": event["timestamp"],
        "source": event["source"],
        "event_type": event["event_type"],
        "src_ip": event.get("src_ip"),
        "mitre": rule.get("mitre", []),
        "dedup": rule.get("dedup", {}),
        "evidence": evidence,
        "raw_event": event,
    }


def match_rules(events: list[dict[str, Any]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts = []

    for event in events:
        for rule in rules:
            alert = match_rule(event, rule)

            if alert is not None:
                alert["alert_id"] = f"A-{len(alerts) + 1:06d}"
                alerts.append(alert)

    return alerts
