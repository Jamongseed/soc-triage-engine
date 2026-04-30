# SOC Alert Triage Engine

한국어 | [English](README.md)

![Tests](https://github.com/Jamongseed/soc-triage-engine/actions/workflows/test.yml/badge.svg)

Nginx access.log, Linux auth.log, Suricata EVE JSON을 통합 분석하여 보안 이벤트를 탐지하고, suppression, deduplication, incident correlation, MITRE ATT&CK 매핑, 공격 타임라인 재구성을 수행하는 SOC 보안관제용 로그 분석 프로젝트입니다.

이 프로젝트는 단순 로그 파서가 아니라, 여러 로그 소스에서 발생한 이벤트를 하나의 incident 단위로 묶고, 반복 알림과 알려진 정상 이벤트를 줄여 분석가가 우선적으로 봐야 할 사건을 정리하는 것을 목표로 합니다.

## 대시보드 미리보기

### Executive Overview

![Dashboard Overview](docs/dashboard_overview.png)

### Incident Explorer

![Incident Explorer](docs/incident_explorer.png)

### Alert Analytics

![Alert Analytics](docs/alert_analytics.png)

## 주요 결과

Synthetic demo dataset 기준 결과입니다.

| 항목 | 값 |
|---|---:|
| Total Events | 10,000 |
| Nginx access.log | 7,400 |
| Linux auth.log | 1,600 |
| Suricata EVE JSON | 1,000 |
| Raw Alerts | 7,206 |
| Suppressed Alerts | 1,598 |
| Deduped Alerts | 368 |
| Incidents | 20 |
| Alert Reduction Rate | 94.89% |
| Tests | 35 passed |

Incident severity 분포는 단일 CRITICAL 중심이 아니라, 여러 공격 시나리오를 분리하여 생성했습니다.

| Severity | Count |
|---|---:|
| Critical | 4 |
| High | 5 |
| Medium | 4 |
| Low | 7 |

## 프로젝트 특징

- Nginx access.log, Linux auth.log, Suricata eve.json 멀티소스 분석
- YAML 기반 탐지 룰 로딩
- Web 공격 탐지
  - SQL Injection
  - Cross-Site Scripting
  - Path Traversal
  - Web Scanner Activity
- SSH 인증 이벤트 탐지
  - Failed Login
  - Successful Login
  - Brute Force Threshold
- Suricata IDS 이벤트 탐지
  - IDS SQL Injection Alert
  - IDS Cross-Site Scripting Alert
  - IDS Directory Traversal Alert
  - IDS SSH Brute Force Alert
  - IDS Network Scan Alert
- Policy-based suppression engine
- Rule-specific deduplication window
- Sequence-based severity scoring
- MITRE ATT&CK technique/tactic mapping
- Incident-level attack timeline reconstruction
- Streamlit 기반 대시보드
- Markdown incident report 생성
- Synthetic SOC demo log generator
- GitHub Actions 기반 테스트 자동화

## 분석 파이프라인

```text
Nginx access.log
Linux auth.log
Suricata eve.json
        ↓
Parser / Normalizer
        ↓
Rule Matching + Threshold Detection
        ↓
Suppression Policy Engine
        ↓
Rule-specific Deduplication
        ↓
Incident Correlation by Source IP
        ↓
Sequence-based Severity Scoring
        ↓
MITRE ATT&CK Mapping
        ↓
Dashboard / JSON Output / Markdown Report
```

## 디렉터리 구조

```text
soc-triage-engine/
├─ app/
│  ├─ correlation/
│  │  ├─ correlator.py
│  │  ├─ dedup.py
│  │  ├─ suppress.py
│  │  └─ timeline.py
│  ├─ dashboard/
│  │  └─ streamlit_app.py
│  ├─ parsers/
│  │  ├─ authlog_parser.py
│  │  ├─ nginx_parser.py
│  │  └─ suricata_parser.py
│  ├─ report/
│  │  └─ markdown_report.py
│  ├─ rules/
│  │  ├─ matcher.py
│  │  ├─ rule_loader.py
│  │  └─ threshold.py
│  ├─ scoring/
│  │  ├─ mitre.py
│  │  └─ sequence.py
│  └─ main.py
├─ config/
│  └─ allowlist.yml
├─ docs/
│  ├─ dashboard_overview.png
│  ├─ incident_explorer.png
│  └─ alert_analytics.png
├─ examples/
├─ outputs/
├─ rules/
│  ├─ web.yml
│  ├─ auth.yml
│  └─ suricata.yml
├─ samples/
│  ├─ nginx_access.log
│  ├─ auth.log
│  └─ suricata_eve.json
├─ scripts/
│  └─ generate_demo_logs.py
├─ tests/
├─ README.md
└─ README.ko.md
```

## 설치

```bash
git clone https://github.com/Jamongseed/soc-triage-engine.git
cd soc-triage-engine

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## Synthetic Demo Logs 생성

기본 샘플 로그를 생성합니다.

```bash
python scripts/generate_demo_logs.py --events 10000
```

생성되는 파일:

```text
samples/nginx_access.log
samples/auth.log
samples/suricata_eve.json
config/allowlist.yml
```

생성 데이터는 단순 반복 로그가 아니라 아래 시나리오가 섞이도록 설계했습니다.

- 정상 웹 트래픽
- 내부 스캐너 / 모니터링 / 헬스체크
- Web exploitation
- SSH brute force
- SSH successful login
- Suricata IDS alert
- Low-signal suspicious activity
- Maintenance window 기반 suppress 대상 이벤트

## 분석 실행

기본 실행:

```bash
python app/main.py
```

CLI 옵션을 사용한 실행:

```bash
python app/main.py \
  --nginx-log samples/nginx_access.log \
  --auth-log samples/auth.log \
  --suricata-log samples/suricata_eve.json \
  --rules-dir rules \
  --allowlist config/allowlist.yml \
  --output-dir outputs
```

추가 옵션:

```bash
python app/main.py \
  --ssh-threshold 4 \
  --ssh-window-minutes 10 \
  --dedup-window-minutes 10 \
  --auth-year 2026
```

출력 파일:

```text
outputs/alerts.json
outputs/suppressed_alerts.json
outputs/deduped_alerts.json
outputs/incidents.json
outputs/incident_report.md
```

## 대시보드 실행

```bash
streamlit run app/dashboard/streamlit_app.py
```

대시보드 주요 기능:

- Raw / Suppressed / Deduped / Incident KPI
- Incident Summary
- Severity Distribution
- Top Rules
- Incident Explorer
- Attack Stepper
- Timeline Table
- Deduplicated Alerts
- Alerts by Severity
- Alerts by Source
- Alerts by Source IP
- Suppressed Alerts Table
- Markdown Report Preview

## 탐지 룰

탐지 룰은 YAML 파일로 관리합니다.

예시:

```yaml
id: WEB-SQLI-001
title: SQL Injection Attempt
source: nginx
severity: high
mitre:
  - T1190
conditions:
  user_agent_contains:
    - sqlmap
  url_contains:
    - "' OR '1'='1"
    - "UNION SELECT"
dedup:
  key:
    - src_ip
    - rule_id
  window_minutes: 10
```

Suricata 룰은 하나의 YAML 파일에 여러 룰을 list 형태로 정의할 수 있습니다.

```yaml
- id: IDS-SQLI-001
  title: IDS SQL Injection Alert
  source: suricata
  severity: high
  mitre:
    - T1190
  conditions:
    signature_contains:
      - SQL Injection
      - SQLi
  dedup:
    key:
      - src_ip
      - rule_id
    window_minutes: 10
```

## Suppression Policy Engine

`config/allowlist.yml`에서 알려진 정상 이벤트와 오탐 가능성이 높은 이벤트를 제거합니다.

지원 정책:

- 정상 SSH 로그인 allowlist
- 특정 rule_id + src_ip suppress
- User-Agent 기반 suppress
- Path 기반 suppress
- Trusted service 기반 suppress
- Trusted network 기반 suppress
- Maintenance window 기반 suppress

예시:

```yaml
allowed_ssh_logins:
  - src_ip: 203.0.113.77
    user: jamong
    reason: Known administrator login from trusted IP

suppressed_user_agents:
  - user_agent_contains: Uptime-Kuma
    rule_id: WEB-SCAN-001
    reason: Internal uptime monitoring probe

trusted_services:
  - src_ip: 198.51.100.50
    user_agent_contains: GitHub-Hookshot
    reason: Known CI/CD webhook source

maintenance_windows:
  - start: "2026-04-30T04:00:00"
    end: "2026-04-30T04:30:00"
    suppress_rule_ids:
      - WEB-SCAN-001
    reason: Scheduled web assessment window
```

## Deduplication

반복적으로 발생하는 alert를 같은 incident 분석 단위로 줄이기 위해 rule별 dedup window를 적용합니다.

예시:

```yaml
dedup:
  key:
    - src_ip
    - rule_id
  window_minutes: 30
```

이를 통해 같은 IP에서 짧은 시간 동안 반복되는 Web Scan, SQLi, SSH brute force alert가 하나의 대표 alert로 병합됩니다.

## Sequence-based Severity Scoring

단일 alert의 severity만 보지 않고, 동일 src_ip에서 관측된 공격 흐름을 기반으로 incident severity와 confidence score를 계산합니다.

예시:

```text
web scan
+ web exploitation attempt
+ ssh failed login
+ ssh brute force
+ ssh successful login
= CRITICAL incident
```

시나리오별 결과:

| Scenario | Expected Severity |
|---|---|
| Web exploit + SSH brute force + SSH success + IDS | Critical |
| SSH brute force only | High |
| Web exploitation + IDS | Medium / High |
| Scan-only activity | Low / Medium |
| Low-signal suspicious activity | Low |

## MITRE ATT&CK Mapping

탐지 룰의 technique ID를 기반으로 MITRE context를 incident에 추가합니다.

예시:

| Technique | Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1110 | Brute Force | Credential Access |
| T1078 | Valid Accounts | Initial Access / Persistence / Privilege Escalation |
| T1595 | Active Scanning | Reconnaissance |

보고서와 대시보드에서는 각 incident에 대해 MITRE Techniques, MITRE Tactics, Technique Details를 확인할 수 있습니다.

## Incident Report

분석 결과는 Markdown report로 생성됩니다.

```text
outputs/incident_report.md
```

보고서 포함 항목:

- Report Metadata
- Executive Summary
- Incident Details
- Sources
- Triage Verdict
- Why This Matters
- Evidence Summary
- MITRE Context
- Scoring Reasons
- Recommended Actions
- Attack Timeline
- Analyst Notes

## 테스트

로컬 테스트:

```bash
python -m pytest -q
```

현재 테스트 구성:

- Nginx parser
- auth.log parser
- Suricata parser
- rule matcher
- deduplication
- suppression policy
- MITRE mapping
- markdown report
- Suricata rule matching

현재 기준:

```text
35 passed
```

GitHub Actions에서도 push / pull request 시 자동으로 테스트가 실행됩니다.

## 핵심 구현 성과

- 단일 로그 파서가 아니라 Nginx, auth.log, Suricata EVE JSON을 통합한 multi-source SOC triage pipeline 구현
- 반복 alert와 known-benign 이벤트를 줄이기 위한 suppression + deduplication 구조 설계
- rule_id, src_ip, user-agent, path, trusted service, trusted network, maintenance window 기반 policy suppression 구현
- 같은 src_ip에서 발생한 웹 공격, IDS alert, SSH 인증 이벤트를 하나의 incident로 correlation
- sequence-based severity scoring을 통해 공격 흐름 기반으로 Critical / High / Medium / Low 분류
- MITRE ATT&CK technique/tactic context를 incident와 report에 반영
- Streamlit 대시보드에서 Attack Stepper, Source별 alert, Top Rules, Suppressed Alerts를 시각화
- GitHub Actions CI를 통해 테스트 자동화

## 향후 개선 가능성

- 실제 Suricata EVE JSON 샘플과 공개 PCAP 기반 데이터셋 호환성 테스트
- Sigma rule 변환 지원
- CSV / HTML report export
- Source별 필터와 기간 필터 강화
- Rule coverage dashboard 추가
- Docker Compose 기반 실행 환경 구성
- SQLite 또는 DuckDB 기반 분석 결과 저장
- Slack / Discord notification 연동
