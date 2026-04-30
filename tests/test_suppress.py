from app.correlation.suppress import suppress_alerts


def test_suppress_allowed_ssh_success():
    alerts = [
        {
            "alert_id": "A-000011",
            "rule_id": "SSH-SUCCESS-001",
            "rule_name": "SSH Successful Login",
            "timestamp": "2026-04-30T11:05:12",
            "src_ip": "203.0.113.77",
            "raw_event": {
                "src_ip": "203.0.113.77",
                "user": "jamong",
            },
        }
    ]

    allowlist = {
        "allowed_ssh_logins": [
            {
                "src_ip": "203.0.113.77",
                "user": "jamong",
                "reason": "Known administrator login from trusted IP",
            }
        ]
    }

    remaining, suppressed = suppress_alerts(alerts, allowlist)

    assert len(remaining) == 0
    assert len(suppressed) == 1
    assert suppressed[0]["suppressed"] is True
    assert suppressed[0]["suppress_reason"] == "Known administrator login from trusted IP"


def test_do_not_suppress_unknown_ssh_success():
    alerts = [
        {
            "alert_id": "A-000010",
            "rule_id": "SSH-SUCCESS-001",
            "rule_name": "SSH Successful Login",
            "timestamp": "2026-04-30T10:36:52",
            "src_ip": "45.12.33.10",
            "raw_event": {
                "src_ip": "45.12.33.10",
                "user": "ubuntu",
            },
        }
    ]

    allowlist = {
        "allowed_ssh_logins": [
            {
                "src_ip": "203.0.113.77",
                "user": "jamong",
                "reason": "Known administrator login from trusted IP",
            }
        ]
    }

    remaining, suppressed = suppress_alerts(alerts, allowlist)

    assert len(remaining) == 1
    assert len(suppressed) == 0


def test_suppress_specific_rule_by_src_ip():
    alerts = [
        {
            "alert_id": "A-000001",
            "rule_id": "WEB-SCAN-001",
            "rule_name": "Web Scanner Activity",
            "event_type": "web_request",
            "src_ip": "198.51.100.10",
            "raw_event": {
                "src_ip": "198.51.100.10",
                "event_type": "web_request",
            },
        },
        {
            "alert_id": "A-000002",
            "rule_id": "WEB-SCAN-001",
            "rule_name": "Web Scanner Activity",
            "event_type": "web_request",
            "src_ip": "45.12.33.10",
            "raw_event": {
                "src_ip": "45.12.33.10",
                "event_type": "web_request",
            },
        },
    ]

    policy = {
        "allowed_ssh_logins": [],
        "suppressed_rules": [
            {
                "rule_id": "WEB-SCAN-001",
                "src_ip": "198.51.100.10",
                "reason": "Internal vulnerability scanner",
            }
        ],
        "trusted_networks": [],
    }

    unsuppressed, suppressed = suppress_alerts(alerts, policy)

    assert len(suppressed) == 1
    assert len(unsuppressed) == 1
    assert suppressed[0]["alert_id"] == "A-000001"
    assert suppressed[0]["suppress_reason"] == "Internal vulnerability scanner"


def test_suppress_trusted_network_event_type():
    alerts = [
        {
            "alert_id": "A-000001",
            "rule_id": "SSH-SUCCESS-001",
            "rule_name": "SSH Successful Login",
            "event_type": "ssh_success_login",
            "src_ip": "203.0.113.88",
            "raw_event": {
                "src_ip": "203.0.113.88",
                "event_type": "ssh_success_login",
                "user": "admin",
            },
        },
        {
            "alert_id": "A-000002",
            "rule_id": "SSH-FAIL-001",
            "rule_name": "SSH Failed Login",
            "event_type": "ssh_failed_login",
            "src_ip": "203.0.113.88",
            "raw_event": {
                "src_ip": "203.0.113.88",
                "event_type": "ssh_failed_login",
                "user": "admin",
            },
        },
    ]

    policy = {
        "allowed_ssh_logins": [],
        "suppressed_rules": [],
        "trusted_networks": [
            {
                "cidr": "203.0.113.0/24",
                "suppress_event_types": ["ssh_success_login"],
                "reason": "Trusted administration network",
            }
        ],
    }

    unsuppressed, suppressed = suppress_alerts(alerts, policy)

    assert len(suppressed) == 1
    assert len(unsuppressed) == 1
    assert suppressed[0]["alert_id"] == "A-000001"
    assert suppressed[0]["suppress_reason"] == "Trusted administration network"
    assert unsuppressed[0]["alert_id"] == "A-000002"
