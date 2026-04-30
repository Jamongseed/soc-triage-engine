from app.rules.matcher import match_rule


def test_match_suricata_signature_rule():
    event = {
        "timestamp": "2026-04-30T11:02:00+09:00",
        "source": "suricata",
        "event_type": "ids_alert",
        "src_ip": "45.12.33.10",
        "signature": "ET WEB_SERVER SQL Injection Attempt",
        "category": "Web Application Attack",
    }

    rule = {
        "id": "IDS-SQLI-001",
        "title": "IDS SQL Injection Alert",
        "source": "suricata",
        "severity": "high",
        "mitre": ["T1190"],
        "conditions": {
            "signature_contains": ["SQL Injection"],
        },
        "dedup": {
            "key": ["src_ip", "rule_id"],
            "window_minutes": 10,
        },
    }

    alert = match_rule(event, rule)

    assert alert is not None
    assert alert["rule_id"] == "IDS-SQLI-001"
    assert alert["source"] == "suricata"
    assert alert["evidence"]["matched_field"] == "signature"
    assert alert["evidence"]["matched_pattern"] == "SQL Injection"


def test_match_suricata_category_rule():
    event = {
        "timestamp": "2026-04-30T11:02:00+09:00",
        "source": "suricata",
        "event_type": "ids_alert",
        "src_ip": "45.12.33.10",
        "signature": "ET WEB_SERVER SQL Injection Attempt",
        "category": "Web Application Attack",
    }

    rule = {
        "id": "IDS-WEBAPP-001",
        "title": "IDS Web Application Attack",
        "source": "suricata",
        "severity": "medium",
        "mitre": ["T1190"],
        "conditions": {
            "category_contains": ["Web Application Attack"],
        },
    }

    alert = match_rule(event, rule)

    assert alert is not None
    assert alert["evidence"]["matched_field"] == "category"
    assert alert["evidence"]["matched_pattern"] == "Web Application Attack"
