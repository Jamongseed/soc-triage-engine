from typing import Any


def _rule_ids(alerts: list[dict[str, Any]]) -> set[str]:
    return {alert.get("rule_id", "") for alert in alerts}


def _sources(alerts: list[dict[str, Any]]) -> set[str]:
    return {alert.get("source", "") for alert in alerts}


def _has_any(rule_ids: set[str], candidates: set[str]) -> bool:
    return bool(rule_ids.intersection(candidates))


def calculate_sequence_score(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Calculate incident severity and confidence based on attack sequence.

    This scoring model focuses on analyst triage:
    - Which attack stages appeared?
    - Did the same source IP move from web probing to credential attacks?
    - Was there a successful login after brute force behavior?
    """

    rule_ids = _rule_ids(alerts)
    sources = _sources(alerts)

    web_scan_rules = {"WEB-SCAN-001"}
    web_exploit_rules = {"WEB-SQLI-001", "WEB-XSS-001", "WEB-PATH-001"}
    ssh_failed_rules = {"SSH-FAIL-001"}
    ssh_bruteforce_rules = {"SSH-BRUTEFORCE-001"}
    ssh_success_rules = {"SSH-SUCCESS-001"}

    has_web_scan = _has_any(rule_ids, web_scan_rules)
    has_web_exploit = _has_any(rule_ids, web_exploit_rules)
    has_ssh_failed = _has_any(rule_ids, ssh_failed_rules)
    has_ssh_bruteforce = _has_any(rule_ids, ssh_bruteforce_rules)
    has_ssh_success = _has_any(rule_ids, ssh_success_rules)
    has_multi_source = len({source for source in sources if source}) >= 2

    score = 0
    reasons = []
    observed_stages = []

    if has_web_scan:
        score += 10
        observed_stages.append("web_scan")
        reasons.append("Web scanner activity was observed.")

    if has_web_exploit:
        score += 25
        observed_stages.append("web_exploitation_attempt")
        reasons.append("Web exploitation attempts were observed.")

    if has_ssh_failed:
        score += 15
        observed_stages.append("ssh_failed_login")
        reasons.append("SSH failed login activity was observed.")

    if has_ssh_bruteforce:
        score += 65
        observed_stages.append("ssh_bruteforce")
        reasons.append("SSH brute force threshold was exceeded.")

    if has_ssh_success:
        score += 25
        observed_stages.append("ssh_successful_login")
        reasons.append("SSH successful login was observed.")

    if has_multi_source:
        score += 15
        reasons.append("Multiple log sources were correlated for the same source IP.")

    if has_ssh_bruteforce and has_ssh_success:
        score += 25
        reasons.append("Successful SSH login occurred after brute force-like activity.")

    if has_web_exploit and has_ssh_bruteforce and has_ssh_success:
        score += 30
        reasons.append(
            "Possible compromise sequence detected: web exploitation attempts were followed by SSH brute force and successful login."
        )

    if has_web_scan and has_web_exploit:
        score += 10
        reasons.append("Web scanning was followed by exploitation attempts.")

    confidence_score = min(score, 100)

    if confidence_score >= 85:
        severity = "critical"
    elif confidence_score >= 65:
        severity = "high"
    elif confidence_score >= 35:
        severity = "medium"
    else:
        severity = "low"

    return {
        "severity": severity,
        "confidence_score": confidence_score,
        "observed_stages": observed_stages,
        "scoring_reasons": reasons,
    }
