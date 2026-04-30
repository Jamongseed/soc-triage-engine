from pathlib import Path
from typing import Any

import yaml


REQUIRED_FIELDS = ["id", "title", "source", "severity", "conditions"]


def _validate_rule(rule: dict[str, Any], file_path: Path) -> None:
    for field in REQUIRED_FIELDS:
        if field not in rule:
            raise ValueError(f"Missing required rule field '{field}' in {file_path}")


def load_rule(file_path: str | Path) -> dict[str, Any]:
    """
    Load a single YAML rule file.

    This function is kept for compatibility with tests or code that expects
    one rule per file.
    """
    path = Path(file_path)

    with open(path, "r", encoding="utf-8") as file:
        rule = yaml.safe_load(file)

    if not isinstance(rule, dict):
        raise ValueError(f"Expected a single rule object in {path}")

    _validate_rule(rule, path)
    return rule


def load_rules(file_path: str | Path) -> list[dict[str, Any]]:
    """
    Load rules from a directory or a single YAML file.

    Supported YAML formats:
    1. Single-rule file:
       id: WEB-SQLI-001
       title: SQL Injection Attempt
       ...

    2. Multi-rule file:
       - id: IDS-SQLI-001
         title: IDS SQL Injection Alert
         ...
       - id: IDS-XSS-001
         title: IDS Cross-Site Scripting Alert
         ...
    """
    path = Path(file_path)

    rule_files = []

    if path.is_dir():
        rule_files = sorted(
            list(path.glob("*.yml")) + list(path.glob("*.yaml"))
        )
    else:
        rule_files = [path]

    rules: list[dict[str, Any]] = []

    for rule_file in rule_files:
        with open(rule_file, "r", encoding="utf-8") as file:
            loaded = yaml.safe_load(file)

        if loaded is None:
            continue

        if isinstance(loaded, list):
            for rule in loaded:
                if not isinstance(rule, dict):
                    raise ValueError(f"Invalid rule entry in {rule_file}")

                _validate_rule(rule, rule_file)
                rules.append(rule)

        elif isinstance(loaded, dict):
            _validate_rule(loaded, rule_file)
            rules.append(loaded)

        else:
            raise ValueError(f"Invalid rule format in {rule_file}")

    return rules
