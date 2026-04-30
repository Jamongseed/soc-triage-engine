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
