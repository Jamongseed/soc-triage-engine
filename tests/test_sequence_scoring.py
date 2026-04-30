from app.scoring.sequence import calculate_sequence_score


def test_web_attack_ssh_bruteforce_success_becomes_critical():
    alerts = [
        {
            "rule_id": "WEB-SQLI-001",
            "source": "nginx",
            "severity": "high",
        },
        {
            "rule_id": "SSH-BRUTEFORCE-001",
            "source": "authlog",
            "severity": "high",
        },
        {
            "rule_id": "SSH-SUCCESS-001",
            "source": "authlog",
            "severity": "high",
        },
    ]

    result = calculate_sequence_score(alerts)

    assert result["severity"] == "critical"
    assert result["confidence_score"] >= 85
    assert "web_exploitation_attempt" in result["observed_stages"]
    assert "ssh_bruteforce" in result["observed_stages"]
    assert "ssh_successful_login" in result["observed_stages"]


def test_ssh_bruteforce_only_is_high():
    alerts = [
        {
            "rule_id": "SSH-BRUTEFORCE-001",
            "source": "authlog",
            "severity": "high",
        }
    ]

    result = calculate_sequence_score(alerts)

    assert result["severity"] == "high"
    assert result["confidence_score"] >= 65


def test_web_scan_only_is_low_or_medium():
    alerts = [
        {
            "rule_id": "WEB-SCAN-001",
            "source": "nginx",
            "severity": "medium",
        }
    ]

    result = calculate_sequence_score(alerts)

    assert result["severity"] in {"low", "medium"}
    assert "web_scan" in result["observed_stages"]
