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


def test_suppress_by_user_agent_policy():
    alerts = [
        {
            "alert_id": "A-000001",
            "rule_id": "WEB-SCAN-001",
            "rule_name": "Web Scanner Activity",
            "event_type": "web_request",
            "src_ip": "198.51.100.60",
            "raw_event": {
                "src_ip": "198.51.100.60",
                "event_type": "web_request",
                "user_agent": "Uptime-Kuma/1.23",
                "url": "/server-status",
            },
        }
    ]

    policy = {
        "allowed_ssh_logins": [],
        "suppressed_rules": [],
        "trusted_networks": [],
        "suppressed_user_agents": [
            {
                "user_agent_contains": "Uptime-Kuma",
                "rule_id": "WEB-SCAN-001",
                "reason": "Internal uptime monitoring probe",
            }
        ],
        "suppressed_paths": [],
        "trusted_services": [],
        "maintenance_windows": [],
    }

    unsuppressed, suppressed = suppress_alerts(alerts, policy)

    assert len(unsuppressed) == 0
    assert len(suppressed) == 1
    assert suppressed[0]["suppress_reason"] == "Internal uptime monitoring probe"


def test_suppress_by_path_policy():
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
                "user_agent": "Mozilla/5.0",
                "url": "/server-status",
            },
        }
    ]

    policy = {
        "allowed_ssh_logins": [],
        "suppressed_rules": [],
        "trusted_networks": [],
        "suppressed_user_agents": [],
        "suppressed_paths": [
            {
                "path_contains": "/server-status",
                "src_ip": "198.51.100.10",
                "reason": "Approved Apache status endpoint check",
            }
        ],
        "trusted_services": [],
        "maintenance_windows": [],
    }

    unsuppressed, suppressed = suppress_alerts(alerts, policy)

    assert len(unsuppressed) == 0
    assert len(suppressed) == 1
    assert suppressed[0]["suppress_reason"] == "Approved Apache status endpoint check"


def test_suppress_by_trusted_service_policy():
    alerts = [
        {
            "alert_id": "A-000001",
            "rule_id": "WEB-SCAN-001",
            "rule_name": "Web Scanner Activity",
            "event_type": "web_request",
            "src_ip": "198.51.100.50",
            "raw_event": {
                "src_ip": "198.51.100.50",
                "event_type": "web_request",
                "user_agent": "GitHub-Hookshot/abc",
                "url": "/admin",
            },
        }
    ]

    policy = {
        "allowed_ssh_logins": [],
        "suppressed_rules": [],
        "trusted_networks": [],
        "suppressed_user_agents": [],
        "suppressed_paths": [],
        "trusted_services": [
            {
                "src_ip": "198.51.100.50",
                "user_agent_contains": "GitHub-Hookshot",
                "reason": "Known CI/CD webhook source",
            }
        ],
        "maintenance_windows": [],
    }

    unsuppressed, suppressed = suppress_alerts(alerts, policy)

    assert len(unsuppressed) == 0
    assert len(suppressed) == 1
    assert suppressed[0]["suppress_reason"] == "Known CI/CD webhook source"


def test_suppress_by_maintenance_window_policy():
    alerts = [
        {
            "alert_id": "A-000001",
            "rule_id": "WEB-SCAN-001",
            "rule_name": "Web Scanner Activity",
            "timestamp": "2026-04-30T04:10:00+09:00",
            "event_type": "web_request",
            "src_ip": "45.12.33.10",
            "raw_event": {
                "src_ip": "45.12.33.10",
                "event_type": "web_request",
                "url": "/admin",
                "user_agent": "curl/8.0",
            },
        }
    ]

    policy = {
        "allowed_ssh_logins": [],
        "suppressed_rules": [],
        "trusted_networks": [],
        "suppressed_user_agents": [],
        "suppressed_paths": [],
        "trusted_services": [],
        "maintenance_windows": [
            {
                "start": "2026-04-30T04:00:00",
                "end": "2026-04-30T04:30:00",
                "suppress_rule_ids": ["WEB-SCAN-001"],
                "reason": "Scheduled web assessment window",
            }
        ],
    }

    unsuppressed, suppressed = suppress_alerts(alerts, policy)

    assert len(unsuppressed) == 0
    assert len(suppressed) == 1
    assert suppressed[0]["suppress_reason"] == "Scheduled web assessment window"
