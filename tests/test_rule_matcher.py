from app.rules.matcher import match_rule


def test_match_url_contains_rule():
    event = {
        "timestamp": "2026-04-30T10:31:02+09:00",
        "source": "nginx",
        "event_type": "web_request",
        "src_ip": "45.12.33.10",
        "url": "/product?id=1' OR '1'='1",
        "user_agent": "Mozilla/5.0",
    }

    rule = {
        "id": "WEB-SQLI-001",
        "title": "SQL Injection Attempt",
        "source": "nginx",
        "severity": "high",
        "mitre": ["T1190"],
        "conditions": {
            "url_contains": ["' OR '1'='1"]
        },
    }

    alert = match_rule(event, rule)

    assert alert is not None
    assert alert["rule_id"] == "WEB-SQLI-001"
    assert alert["rule_name"] == "SQL Injection Attempt"
    assert alert["severity"] == "high"
    assert alert["src_ip"] == "45.12.33.10"
    assert alert["evidence"]["matched_field"] == "url"
    assert alert["evidence"]["matched_pattern"] == "' OR '1'='1"


def test_match_event_type_equals_rule():
    event = {
        "timestamp": "2026-04-30T10:35:10",
        "source": "authlog",
        "event_type": "ssh_failed_login",
        "src_ip": "45.12.33.10",
        "user": "root",
    }

    rule = {
        "id": "SSH-FAIL-001",
        "title": "SSH Failed Login",
        "source": "authlog",
        "severity": "medium",
        "mitre": ["T1110"],
        "conditions": {
            "event_type_equals": ["ssh_failed_login"]
        },
    }

    alert = match_rule(event, rule)

    assert alert is not None
    assert alert["rule_id"] == "SSH-FAIL-001"
    assert alert["evidence"]["matched_field"] == "event_type"
    assert alert["evidence"]["matched_pattern"] == "ssh_failed_login"


def test_rule_source_mismatch_returns_none():
    event = {
        "timestamp": "2026-04-30T10:35:10",
        "source": "authlog",
        "event_type": "ssh_failed_login",
        "src_ip": "45.12.33.10",
    }

    rule = {
        "id": "WEB-XSS-001",
        "title": "Cross-Site Scripting Attempt",
        "source": "nginx",
        "severity": "medium",
        "conditions": {
            "url_contains": ["<script>"]
        },
    }

    alert = match_rule(event, rule)

    assert alert is None
