from app.rules.matcher import match_rule


def test_match_web_scan_by_url():
    event = {
        "timestamp": "2026-04-30T11:10:25+09:00",
        "source": "nginx",
        "event_type": "web_request",
        "src_ip": "185.220.101.15",
        "method": "GET",
        "url": "/wp-admin",
        "status": 404,
        "user_agent": "Mozilla/5.0",
    }

    rule = {
        "id": "WEB-SCAN-001",
        "title": "Web Scanner Activity",
        "source": "nginx",
        "severity": "medium",
        "mitre": ["T1595", "T1190"],
        "conditions": {
            "url_contains": ["/admin", "/phpmyadmin", "/wp-admin", "/.env"],
            "user_agent_contains": ["python-requests", "nikto", "nmap", "masscan", "zgrab", "curl"],
        },
    }

    alert = match_rule(event, rule)

    assert alert is not None
    assert alert["rule_id"] == "WEB-SCAN-001"
    assert alert["rule_name"] == "Web Scanner Activity"
    assert alert["severity"] == "medium"
    assert alert["src_ip"] == "185.220.101.15"
    assert alert["evidence"]["matched_field"] == "url"
    assert alert["evidence"]["matched_pattern"] == "/wp-admin"


def test_match_web_scan_by_user_agent():
    event = {
        "timestamp": "2026-04-30T11:10:05+09:00",
        "source": "nginx",
        "event_type": "web_request",
        "src_ip": "185.220.101.15",
        "method": "GET",
        "url": "/index.html",
        "status": 200,
        "user_agent": "python-requests/2.31",
    }

    rule = {
        "id": "WEB-SCAN-001",
        "title": "Web Scanner Activity",
        "source": "nginx",
        "severity": "medium",
        "mitre": ["T1595", "T1190"],
        "conditions": {
            "url_contains": ["/admin", "/phpmyadmin", "/wp-admin", "/.env"],
            "user_agent_contains": ["python-requests", "nikto", "nmap", "masscan", "zgrab", "curl"],
        },
    }

    alert = match_rule(event, rule)

    assert alert is not None
    assert alert["rule_id"] == "WEB-SCAN-001"
    assert alert["evidence"]["matched_field"] == "user_agent"
    assert alert["evidence"]["matched_pattern"] == "python-requests"


def test_do_not_match_normal_web_request_as_scan():
    event = {
        "timestamp": "2026-04-30T11:00:01+09:00",
        "source": "nginx",
        "event_type": "web_request",
        "src_ip": "198.51.100.10",
        "method": "GET",
        "url": "/index.html",
        "status": 200,
        "user_agent": "Mozilla/5.0",
    }

    rule = {
        "id": "WEB-SCAN-001",
        "title": "Web Scanner Activity",
        "source": "nginx",
        "severity": "medium",
        "mitre": ["T1595", "T1190"],
        "conditions": {
            "url_contains": ["/admin", "/phpmyadmin", "/wp-admin", "/.env"],
            "user_agent_contains": ["python-requests", "nikto", "nmap", "masscan", "zgrab", "curl"],
        },
    }

    alert = match_rule(event, rule)

    assert alert is None
