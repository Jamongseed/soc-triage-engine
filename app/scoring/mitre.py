from typing import Any


MITRE_TECHNIQUE_MAP: dict[str, dict[str, Any]] = {
    "T1595": {
        "name": "Active Scanning",
        "tactics": ["Reconnaissance"],
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactics": ["Initial Access"],
    },
    "T1110": {
        "name": "Brute Force",
        "tactics": ["Credential Access"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactics": [
            "Defense Evasion",
            "Initial Access",
            "Persistence",
            "Privilege Escalation",
        ],
    },
}


def enrich_mitre_context(techniques: list[str]) -> dict[str, Any]:
    """
    Enrich MITRE ATT&CK technique IDs with tactic and technique name metadata.
    """
    technique_details = []
    tactics = set()

    for technique in sorted(set(techniques)):
        info = MITRE_TECHNIQUE_MAP.get(
            technique,
            {
                "name": "Unknown Technique",
                "tactics": ["Unknown"],
            },
        )

        detail = {
            "technique": technique,
            "name": info["name"],
            "tactics": info["tactics"],
        }

        technique_details.append(detail)
        tactics.update(info["tactics"])

    return {
        "techniques": sorted(set(techniques)),
        "tactics": sorted(tactics),
        "technique_details": technique_details,
    }
