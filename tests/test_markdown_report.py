from app.report.markdown_report import generate_incident_report


def test_generate_incident_report_contains_triage_sections():
    incidents = [
        {
            "incident_id": "INC-000001",
            "src_ip": "45.12.33.10",
            "severity": "critical",
            "confidence_score": 100,
            "first_seen": "2026-04-30T09:45:00+09:00",
            "last_seen": "2026-04-30T09:53:11+09:00",
            "alert_count": 3,
            "unique_rule_count": 3,
            "techniques": ["T1190", "T1110", "T1078"],
            "tactics": ["Initial Access", "Credential Access"],
            "observed_stages": [
                "web_exploitation_attempt",
                "ssh_bruteforce",
                "ssh_successful_login",
            ],
            "technique_details": [
                {
                    "technique": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactics": ["Initial Access"],
                }
            ],
            "scoring_reasons": [
                "Possible compromise sequence detected.",
            ],
            "alerts": [
                {
                    "rule_name": "SQL Injection Attempt",
                    "severity": "high",
                    "duplicate_count": 2,
                    "evidence": {
                        "matched_field": "user_agent",
                        "matched_pattern": "sqlmap",
                    },
                }
            ],
            "timeline": [
                {
                    "timestamp": "2026-04-30T09:45:00+09:00",
                    "severity": "high",
                    "title": "SQL Injection Attempt",
                    "duplicate_count": 2,
                    "evidence": {
                        "matched_field": "user_agent",
                        "matched_pattern": "sqlmap",
                    },
                }
            ],
        }
    ]

    report = generate_incident_report(
        incidents=incidents,
        raw_alert_count=10,
        deduped_alert_count=3,
        reduction_rate=70.0,
    )

    assert "Triage Verdict" in report
    assert "Why This Matters" in report
    assert "Evidence Summary" in report
    assert "Recommended Actions" in report
    assert "Containment Priority" in report
    assert "MITRE Context" in report
    assert "Possible compromise sequence detected" in report
