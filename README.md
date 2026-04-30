# SOC Alert Triage Engine

SOC Alert Triage Engine is a log-based security analysis project that parses multi-source security logs, detects suspicious activity with YAML-based rules, suppresses known false positives, deduplicates repeated alerts, correlates alerts into incidents, reconstructs attack timelines, and generates analyst-friendly incident reports.

This project is not a simple log viewer or SIEM dashboard. It focuses on reducing analyst workload by converting noisy raw alerts into incident-level findings.

## Key Features

- Nginx `access.log` parsing
- Linux `auth.log` parsing
- YAML-based detection rules
- SQL Injection, XSS, and Path Traversal detection
- SSH failed/successful login detection
- Allowlist-based false positive suppression
- Alert deduplication by source IP and rule ID
- Incident correlation by source IP
- Attack timeline reconstruction
- Markdown incident report generation

## Architecture

```text
Sample Logs
  ├─ Nginx access.log
  └─ Linux auth.log
        ↓
Normalized Events
        ↓
YAML Detection Rules
        ↓
Raw Alerts
        ↓
Allowlist Suppression
        ↓
Deduplicated Alerts
        ↓
Incident Correlation
        ↓
Attack Timeline
        ↓
Markdown Incident Report
```

## Project Structure

```text
soc-triage-engine/
├─ app/
│  ├─ correlation/
│  │  ├─ correlator.py
│  │  ├─ dedup.py
│  │  ├─ suppress.py
│  │  └─ timeline.py
│  ├─ parsers/
│  │  ├─ authlog_parser.py
│  │  └─ nginx_parser.py
│  ├─ report/
│  │  └─ markdown_report.py
│  ├─ rules/
│  │  ├─ matcher.py
│  │  └─ rule_loader.py
│  └─ main.py
├─ config/
│  └─ allowlist.yml
├─ examples/
│  ├─ sample_alerts.json
│  ├─ sample_suppressed_alerts.json
│  ├─ sample_deduped_alerts.json
│  ├─ sample_incidents.json
│  └─ sample_incident_report.md
├─ rules/
│  ├─ ssh_failed_login.yml
│  ├─ ssh_success_login.yml
│  ├─ web_path_traversal.yml
│  ├─ web_sqli.yml
│  └─ web_xss.yml
├─ samples/
│  ├─ auth.log
│  └─ nginx_access.log
└─ README.md
```

## Detection Rules

Detection rules are written in a simplified Sigma-like YAML format.

```yaml
id: WEB-SQLI-001
title: SQL Injection Attempt
source: nginx
severity: high
mitre:
  - T1190
conditions:
  url_contains:
    - "' OR '1'='1"
    - "UNION SELECT"
    - "sleep("
    - "benchmark("
  user_agent_contains:
    - "sqlmap"
dedup:
  key:
    - src_ip
    - rule_id
  window_minutes: 10
```

## Sample Scenario

The included sample logs simulate the following activity from `45.12.33.10`:

1. Path traversal attempt
2. SQL Injection attempts
3. XSS attempt
4. SSH brute force attempts
5. SSH successful login after repeated failures

A known administrator login from `203.0.113.77` is suppressed by the allowlist.

## Sample Result

```text
[+] Parsed nginx events: 7
[+] Parsed auth events: 6
[+] Parsed total events: 13
[+] Loaded rules: 5
[+] Generated raw alerts: 11
[+] Suppressed alerts: 1
[+] Deduped alerts: 5
[+] Alert reduction rate: 54.55%
[+] Generated incidents: 1
```

The engine reduced noisy raw alerts into one correlated critical incident.

## Generated Incident Timeline

```text
INC-000001 45.12.33.10 CRITICAL alerts=5 rules=5
    - Path Traversal Attempt
    - SQL Injection Attempt
    - Cross-Site Scripting Attempt
    - SSH Failed Login
    - SSH Successful Login
```

## Example Outputs

Sample outputs are included under the `examples/` directory.

- `examples/sample_alerts.json`
- `examples/sample_suppressed_alerts.json`
- `examples/sample_deduped_alerts.json`
- `examples/sample_incidents.json`
- `examples/sample_incident_report.md`

## Installation

```bash
git clone https://github.com/Jamongseed/soc-triage-engine.git
cd soc-triage-engine

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## Usage

```bash
python app/main.py
```

Output files are generated under `outputs/`.

```text
outputs/
├─ alerts.json
├─ suppressed_alerts.json
├─ deduped_alerts.json
├─ incidents.json
└─ incident_report.md
```

## Current Detection Coverage

| Category | Rule ID | Description |
|---|---|---|
| Web Attack | WEB-SQLI-001 | SQL Injection attempt |
| Web Attack | WEB-XSS-001 | Cross-Site Scripting attempt |
| Web Attack | WEB-PATH-001 | Path Traversal attempt |
| SSH/Auth | SSH-FAIL-001 | SSH failed login |
| SSH/Auth | SSH-SUCCESS-001 | SSH successful login |

## Security Notes

This project uses synthetic sample logs for safe local testing.

It does not perform scanning, exploitation, brute force, or any offensive action against real systems.

## Roadmap

- Add rule-level dedup window support
- Add SSH brute force threshold rule
- Add Streamlit dashboard
- Add test cases for parsers, rules, dedup, and suppression
- Add Suricata EVE JSON parser
- Add MITRE ATT&CK tactic mapping
- Add severity scoring based on event sequence


## Dashboard

Run the analysis pipeline first:

python app/main.py

Then start the Streamlit dashboard:

streamlit run app/dashboard/streamlit_app.py

The dashboard provides:

- Overview metrics
- Incident list
- Incident detail view
- Attack timeline table
- Deduped alert table
- Suppressed alert table
- Markdown report preview
