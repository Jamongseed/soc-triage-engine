from app.correlation.dedup import calculate_reduction_rate, deduplicate_alerts


def test_deduplicate_alerts_same_ip_and_rule_within_window():
    alerts = [
        {
            "alert_id": "A-000001",
            "timestamp": "2026-04-30T10:31:02+09:00",
            "src_ip": "45.12.33.10",
            "rule_id": "WEB-SQLI-001",
            "rule_name": "SQL Injection Attempt",
            "severity": "high",
            "evidence": {},
        },
        {
            "alert_id": "A-000002",
            "timestamp": "2026-04-30T10:31:20+09:00",
            "src_ip": "45.12.33.10",
            "rule_id": "WEB-SQLI-001",
            "rule_name": "SQL Injection Attempt",
            "severity": "high",
            "evidence": {},
        },
        {
            "alert_id": "A-000003",
            "timestamp": "2026-04-30T10:31:43+09:00",
            "src_ip": "45.12.33.10",
            "rule_id": "WEB-SQLI-001",
            "rule_name": "SQL Injection Attempt",
            "severity": "high",
            "evidence": {},
        },
    ]

    deduped = deduplicate_alerts(alerts, window_minutes=10)

    assert len(deduped) == 1
    assert deduped[0]["duplicate_count"] == 3
    assert deduped[0]["related_alert_ids"] == ["A-000001", "A-000002", "A-000003"]


def test_deduplicate_alerts_different_rules_not_merged():
    alerts = [
        {
            "alert_id": "A-000001",
            "timestamp": "2026-04-30T10:29:03+09:00",
            "src_ip": "45.12.33.10",
            "rule_id": "WEB-PATH-001",
            "rule_name": "Path Traversal Attempt",
            "severity": "high",
            "evidence": {},
        },
        {
            "alert_id": "A-000002",
            "timestamp": "2026-04-30T10:31:02+09:00",
            "src_ip": "45.12.33.10",
            "rule_id": "WEB-SQLI-001",
            "rule_name": "SQL Injection Attempt",
            "severity": "high",
            "evidence": {},
        },
    ]

    deduped = deduplicate_alerts(alerts, window_minutes=10)

    assert len(deduped) == 2


def test_calculate_reduction_rate():
    assert calculate_reduction_rate(11, 5) == 54.55
    assert calculate_reduction_rate(5, 3) == 40.0
    assert calculate_reduction_rate(0, 0) == 0.0
