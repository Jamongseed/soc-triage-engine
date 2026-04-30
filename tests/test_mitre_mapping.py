from app.scoring.mitre import enrich_mitre_context


def test_enrich_mitre_context_maps_techniques_to_tactics():
    result = enrich_mitre_context(["T1595", "T1190", "T1110", "T1078"])

    assert "T1595" in result["techniques"]
    assert "T1190" in result["techniques"]
    assert "T1110" in result["techniques"]
    assert "T1078" in result["techniques"]

    assert "Reconnaissance" in result["tactics"]
    assert "Initial Access" in result["tactics"]
    assert "Credential Access" in result["tactics"]
    assert "Defense Evasion" in result["tactics"]
    assert "Persistence" in result["tactics"]
    assert "Privilege Escalation" in result["tactics"]

    details = {item["technique"]: item for item in result["technique_details"]}

    assert details["T1595"]["name"] == "Active Scanning"
    assert details["T1190"]["name"] == "Exploit Public-Facing Application"
    assert details["T1110"]["name"] == "Brute Force"
    assert details["T1078"]["name"] == "Valid Accounts"


def test_enrich_mitre_context_handles_unknown_technique():
    result = enrich_mitre_context(["T9999"])

    assert result["techniques"] == ["T9999"]
    assert result["tactics"] == ["Unknown"]
    assert result["technique_details"][0]["name"] == "Unknown Technique"
