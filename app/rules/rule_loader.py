from pathlib import Path

import yaml


def load_rule(file_path: str | Path) -> dict:
    """
    Load one YAML detection rule.
    """
    with open(file_path, "r", encoding="utf-8") as file:
        rule = yaml.safe_load(file)

    required_fields = ["id", "title", "source", "severity", "conditions"]

    for field in required_fields:
        if field not in rule:
            raise ValueError(f"Missing required rule field '{field}' in {file_path}")

    return rule


def load_rules(rules_dir: str | Path) -> list[dict]:
    """
    Load all .yml/.yaml detection rules from a directory.
    """
    rules_path = Path(rules_dir)
    rules = []

    for rule_file in sorted(rules_path.glob("*.yml")):
        rules.append(load_rule(rule_file))

    for rule_file in sorted(rules_path.glob("*.yaml")):
        rules.append(load_rule(rule_file))

    return rules
