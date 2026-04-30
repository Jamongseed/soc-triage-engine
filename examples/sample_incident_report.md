# SOC Alert Triage Report

## Report Metadata

- Generated At: `2026-05-01T01:19:55`
- Total Incidents: `12`
- Raw Alerts: `395`
- Deduped Alerts: `39`
- Alert Reduction Rate: `90.13%`

## Executive Summary

- Critical Incidents: `6`
- High Incidents: `2`
- Medium Incidents: `1`
- Low Incidents: `3`

The engine grouped raw security alerts into incident-level findings, suppressed known false positives, deduplicated repeated alerts, reconstructed attack timelines, enriched MITRE ATT&CK context, and applied sequence-based severity scoring for analyst review.

## Incident Details

### INC-000001 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `45.12.33.10` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T09:45:00+09:00` |
| Last Seen | `2026-04-30T09:53:11` |
| Alert Count | `7` |
| Unique Rule Count | `7` |
| MITRE Techniques | `T1078, T1110, T1190, T1595` |
| MITRE Tactics | `Credential Access, Defense Evasion, Initial Access, Persistence, Privilege Escalation, Reconnaissance` |
| Observed Stages | `web_scan, web_exploitation_attempt, ssh_failed_login, ssh_bruteforce, ssh_successful_login` |

#### Triage Verdict

Possible compromise sequence detected. The same source IP performed web exploitation attempts, triggered SSH brute force behavior, and later achieved successful SSH login.

#### Why This Matters

- Web scanning often appears before exploitation attempts and may indicate target discovery activity.
- Web exploitation attempts may indicate attempts to access sensitive files, inject payloads, or abuse vulnerable endpoints.
- SSH brute force activity indicates repeated credential guessing and increases account compromise risk.
- A successful SSH login after suspicious activity should be treated as high-risk until validated.
- Multiple MITRE ATT&CK tactics were observed, suggesting this is more than a single isolated alert.

#### Evidence Summary

- Path Traversal Attempt (HIGH) matched `url=../` and merged 8 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 8 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 8 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`

#### MITRE Context

- `T1078` Valid Accounts → Defense Evasion, Initial Access, Persistence, Privilege Escalation
- `T1110` Brute Force → Credential Access
- `T1190` Exploit Public-Facing Application → Initial Access
- `T1595` Active Scanning → Reconnaissance

#### Scoring Reasons

- Web scanner activity was observed.
- Web exploitation attempts were observed.
- SSH failed login activity was observed.
- SSH brute force threshold was exceeded.
- SSH successful login was observed.
- Multiple log sources were correlated for the same source IP.
- Successful SSH login occurred after brute force-like activity.
- Possible compromise sequence detected: web exploitation attempts were followed by SSH brute force and successful login.
- Web scanning was followed by exploitation attempts.

#### Recommended Actions

1. Immediately review the successful SSH session and associated user account.
2. Rotate credentials for the affected user and check for unauthorized SSH keys.
3. Review shell history, process execution, and file modifications around the login time.
4. Review web server logs around the first exploitation attempt.
5. Validate whether the targeted endpoints are vulnerable or exposed unintentionally.
6. Check application logs for errors, unusual parameters, or suspicious response patterns.
7. Check whether the source IP performed broader reconnaissance across other endpoints.
8. Consider blocking scanner-like traffic if it is not part of an approved assessment.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T09:45:00+09:00` | `high` | Path Traversal Attempt | `8` | `url=../` |
| `2026-04-30T09:45:00+09:00` | `medium` | Web Scanner Activity | `8` | `user_agent=curl` |
| `2026-04-30T09:47:00+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T09:50:00+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T09:51:00` | `medium` | SSH Failed Login | `8` | `event_type=ssh_failed_login` |
| `2026-04-30T09:51:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T09:53:11` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000002 - LOW

| Field | Value |
|---|---|
| Source IP | `198.51.100.23` |
| Severity | `low` |
| Confidence Score | `25` |
| Containment Priority | `P4 - Low priority review` |
| First Seen | `2026-04-30T10:05:00+09:00` |
| Last Seen | `2026-04-30T10:05:00+09:00` |
| Alert Count | `1` |
| Unique Rule Count | `1` |
| MITRE Techniques | `T1190` |
| MITRE Tactics | `Initial Access` |
| Observed Stages | `web_exploitation_attempt` |

#### Triage Verdict

Web exploitation activity detected. Review target endpoints and response codes.

#### Why This Matters

- Web exploitation attempts may indicate attempts to access sensitive files, inject payloads, or abuse vulnerable endpoints.

#### Evidence Summary

- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 34 repeated alerts

#### MITRE Context

- `T1190` Exploit Public-Facing Application → Initial Access

#### Scoring Reasons

- Web exploitation attempts were observed.

#### Recommended Actions

1. Review web server logs around the first exploitation attempt.
2. Validate whether the targeted endpoints are vulnerable or exposed unintentionally.
3. Check application logs for errors, unusual parameters, or suspicious response patterns.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T10:05:00+09:00` | `high` | SQL Injection Attempt | `34` | `user_agent=sqlmap` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000003 - LOW

| Field | Value |
|---|---|
| Source IP | `192.0.2.44` |
| Severity | `low` |
| Confidence Score | `25` |
| Containment Priority | `P4 - Low priority review` |
| First Seen | `2026-04-30T10:22:00+09:00` |
| Last Seen | `2026-04-30T10:22:00+09:00` |
| Alert Count | `1` |
| Unique Rule Count | `1` |
| MITRE Techniques | `T1190` |
| MITRE Tactics | `Initial Access` |
| Observed Stages | `web_exploitation_attempt` |

#### Triage Verdict

Web exploitation activity detected. Review target endpoints and response codes.

#### Why This Matters

- Web exploitation attempts may indicate attempts to access sensitive files, inject payloads, or abuse vulnerable endpoints.

#### Evidence Summary

- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 28 repeated alerts

#### MITRE Context

- `T1190` Exploit Public-Facing Application → Initial Access

#### Scoring Reasons

- Web exploitation attempts were observed.

#### Recommended Actions

1. Review web server logs around the first exploitation attempt.
2. Validate whether the targeted endpoints are vulnerable or exposed unintentionally.
3. Check application logs for errors, unusual parameters, or suspicious response patterns.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T10:22:00+09:00` | `medium` | Cross-Site Scripting Attempt | `28` | `url=<script>` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000004 - MEDIUM

| Field | Value |
|---|---|
| Source IP | `203.0.113.88` |
| Severity | `medium` |
| Confidence Score | `45` |
| Containment Priority | `P3 - Review and monitor` |
| First Seen | `2026-04-30T10:38:00+09:00` |
| Last Seen | `2026-04-30T10:38:00+09:00` |
| Alert Count | `2` |
| Unique Rule Count | `2` |
| MITRE Techniques | `T1190, T1595` |
| MITRE Tactics | `Initial Access, Reconnaissance` |
| Observed Stages | `web_scan, web_exploitation_attempt` |

#### Triage Verdict

Web exploitation activity detected. Review target endpoints and response codes.

#### Why This Matters

- Web scanning often appears before exploitation attempts and may indicate target discovery activity.
- Web exploitation attempts may indicate attempts to access sensitive files, inject payloads, or abuse vulnerable endpoints.

#### Evidence Summary

- Path Traversal Attempt (HIGH) matched `url=../` and merged 26 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 26 repeated alerts

#### MITRE Context

- `T1190` Exploit Public-Facing Application → Initial Access
- `T1595` Active Scanning → Reconnaissance

#### Scoring Reasons

- Web scanner activity was observed.
- Web exploitation attempts were observed.
- Web scanning was followed by exploitation attempts.

#### Recommended Actions

1. Review web server logs around the first exploitation attempt.
2. Validate whether the targeted endpoints are vulnerable or exposed unintentionally.
3. Check application logs for errors, unusual parameters, or suspicious response patterns.
4. Check whether the source IP performed broader reconnaissance across other endpoints.
5. Consider blocking scanner-like traffic if it is not part of an approved assessment.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T10:38:00+09:00` | `high` | Path Traversal Attempt | `26` | `url=../` |
| `2026-04-30T10:38:00+09:00` | `medium` | Web Scanner Activity | `26` | `user_agent=curl` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000005 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `91.240.118.22` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T10:52:00+09:00` |
| Last Seen | `2026-04-30T11:00:00` |
| Alert Count | `6` |
| Unique Rule Count | `6` |
| MITRE Techniques | `T1110, T1190, T1595` |
| MITRE Tactics | `Credential Access, Initial Access, Reconnaissance` |
| Observed Stages | `web_scan, web_exploitation_attempt, ssh_failed_login, ssh_bruteforce` |

#### Triage Verdict

SSH brute force behavior detected. Credential attack activity should be reviewed.

#### Why This Matters

- Web scanning often appears before exploitation attempts and may indicate target discovery activity.
- Web exploitation attempts may indicate attempts to access sensitive files, inject payloads, or abuse vulnerable endpoints.
- SSH brute force activity indicates repeated credential guessing and increases account compromise risk.
- Multiple MITRE ATT&CK tactics were observed, suggesting this is more than a single isolated alert.

#### Evidence Summary

- Path Traversal Attempt (HIGH) matched `url=../` and merged 8 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 8 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 14 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`

#### MITRE Context

- `T1110` Brute Force → Credential Access
- `T1190` Exploit Public-Facing Application → Initial Access
- `T1595` Active Scanning → Reconnaissance

#### Scoring Reasons

- Web scanner activity was observed.
- Web exploitation attempts were observed.
- SSH failed login activity was observed.
- SSH brute force threshold was exceeded.
- Multiple log sources were correlated for the same source IP.
- Web scanning was followed by exploitation attempts.

#### Recommended Actions

1. Rate-limit or block the source IP at the firewall or SSH access layer.
2. Review authentication logs for additional failed login bursts from related IP ranges.
3. Verify whether password authentication should be disabled in favor of key-based access.
4. Review web server logs around the first exploitation attempt.
5. Validate whether the targeted endpoints are vulnerable or exposed unintentionally.
6. Check application logs for errors, unusual parameters, or suspicious response patterns.
7. Check whether the source IP performed broader reconnaissance across other endpoints.
8. Consider blocking scanner-like traffic if it is not part of an approved assessment.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T10:52:00+09:00` | `high` | Path Traversal Attempt | `8` | `url=../` |
| `2026-04-30T10:52:00+09:00` | `medium` | Web Scanner Activity | `8` | `user_agent=curl` |
| `2026-04-30T10:54:00+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T10:57:00+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T11:00:00` | `medium` | SSH Failed Login | `14` | `event_type=ssh_failed_login` |
| `2026-04-30T11:00:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000006 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `104.248.90.77` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T11:08:00+09:00` |
| Last Seen | `2026-04-30T11:15:00` |
| Alert Count | `3` |
| Unique Rule Count | `3` |
| MITRE Techniques | `T1110, T1190` |
| MITRE Tactics | `Credential Access, Initial Access` |
| Observed Stages | `web_exploitation_attempt, ssh_failed_login, ssh_bruteforce` |

#### Triage Verdict

SSH brute force behavior detected. Credential attack activity should be reviewed.

#### Why This Matters

- Web exploitation attempts may indicate attempts to access sensitive files, inject payloads, or abuse vulnerable endpoints.
- SSH brute force activity indicates repeated credential guessing and increases account compromise risk.

#### Evidence Summary

- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 22 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 9 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`

#### MITRE Context

- `T1110` Brute Force → Credential Access
- `T1190` Exploit Public-Facing Application → Initial Access

#### Scoring Reasons

- Web exploitation attempts were observed.
- SSH failed login activity was observed.
- SSH brute force threshold was exceeded.
- Multiple log sources were correlated for the same source IP.

#### Recommended Actions

1. Rate-limit or block the source IP at the firewall or SSH access layer.
2. Review authentication logs for additional failed login bursts from related IP ranges.
3. Verify whether password authentication should be disabled in favor of key-based access.
4. Review web server logs around the first exploitation attempt.
5. Validate whether the targeted endpoints are vulnerable or exposed unintentionally.
6. Check application logs for errors, unusual parameters, or suspicious response patterns.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T11:08:00+09:00` | `high` | SQL Injection Attempt | `22` | `user_agent=sqlmap` |
| `2026-04-30T11:15:00` | `medium` | SSH Failed Login | `9` | `event_type=ssh_failed_login` |
| `2026-04-30T11:15:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000007 - LOW

| Field | Value |
|---|---|
| Source IP | `45.155.205.111` |
| Severity | `low` |
| Confidence Score | `25` |
| Containment Priority | `P4 - Low priority review` |
| First Seen | `2026-04-30T11:21:00+09:00` |
| Last Seen | `2026-04-30T11:21:00+09:00` |
| Alert Count | `1` |
| Unique Rule Count | `1` |
| MITRE Techniques | `T1190` |
| MITRE Tactics | `Initial Access` |
| Observed Stages | `web_exploitation_attempt` |

#### Triage Verdict

Web exploitation activity detected. Review target endpoints and response codes.

#### Why This Matters

- Web exploitation attempts may indicate attempts to access sensitive files, inject payloads, or abuse vulnerable endpoints.

#### Evidence Summary

- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 18 repeated alerts

#### MITRE Context

- `T1190` Exploit Public-Facing Application → Initial Access

#### Scoring Reasons

- Web exploitation attempts were observed.

#### Recommended Actions

1. Review web server logs around the first exploitation attempt.
2. Validate whether the targeted endpoints are vulnerable or exposed unintentionally.
3. Check application logs for errors, unusual parameters, or suspicious response patterns.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T11:21:00+09:00` | `medium` | Cross-Site Scripting Attempt | `18` | `url=<script>` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000008 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `185.220.101.15` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T11:35:00+09:00` |
| Last Seen | `2026-04-30T11:45:00` |
| Alert Count | `4` |
| Unique Rule Count | `4` |
| MITRE Techniques | `T1110, T1190, T1595` |
| MITRE Tactics | `Credential Access, Initial Access, Reconnaissance` |
| Observed Stages | `web_scan, web_exploitation_attempt, ssh_failed_login, ssh_bruteforce` |

#### Triage Verdict

SSH brute force behavior detected. Credential attack activity should be reviewed.

#### Why This Matters

- Web scanning often appears before exploitation attempts and may indicate target discovery activity.
- Web exploitation attempts may indicate attempts to access sensitive files, inject payloads, or abuse vulnerable endpoints.
- SSH brute force activity indicates repeated credential guessing and increases account compromise risk.
- Multiple MITRE ATT&CK tactics were observed, suggesting this is more than a single isolated alert.

#### Evidence Summary

- Path Traversal Attempt (HIGH) matched `url=../` and merged 20 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 20 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 18 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`

#### MITRE Context

- `T1110` Brute Force → Credential Access
- `T1190` Exploit Public-Facing Application → Initial Access
- `T1595` Active Scanning → Reconnaissance

#### Scoring Reasons

- Web scanner activity was observed.
- Web exploitation attempts were observed.
- SSH failed login activity was observed.
- SSH brute force threshold was exceeded.
- Multiple log sources were correlated for the same source IP.
- Web scanning was followed by exploitation attempts.

#### Recommended Actions

1. Rate-limit or block the source IP at the firewall or SSH access layer.
2. Review authentication logs for additional failed login bursts from related IP ranges.
3. Verify whether password authentication should be disabled in favor of key-based access.
4. Review web server logs around the first exploitation attempt.
5. Validate whether the targeted endpoints are vulnerable or exposed unintentionally.
6. Check application logs for errors, unusual parameters, or suspicious response patterns.
7. Check whether the source IP performed broader reconnaissance across other endpoints.
8. Consider blocking scanner-like traffic if it is not part of an approved assessment.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T11:35:00+09:00` | `high` | Path Traversal Attempt | `20` | `url=../` |
| `2026-04-30T11:35:00+09:00` | `medium` | Web Scanner Activity | `20` | `user_agent=curl` |
| `2026-04-30T11:45:00` | `medium` | SSH Failed Login | `18` | `event_type=ssh_failed_login` |
| `2026-04-30T11:45:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000009 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `167.99.42.31` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T11:51:00+09:00` |
| Last Seen | `2026-04-30T12:02:59` |
| Alert Count | `7` |
| Unique Rule Count | `7` |
| MITRE Techniques | `T1078, T1110, T1190, T1595` |
| MITRE Tactics | `Credential Access, Defense Evasion, Initial Access, Persistence, Privilege Escalation, Reconnaissance` |
| Observed Stages | `web_scan, web_exploitation_attempt, ssh_failed_login, ssh_bruteforce, ssh_successful_login` |

#### Triage Verdict

Possible compromise sequence detected. The same source IP performed web exploitation attempts, triggered SSH brute force behavior, and later achieved successful SSH login.

#### Why This Matters

- Web scanning often appears before exploitation attempts and may indicate target discovery activity.
- Web exploitation attempts may indicate attempts to access sensitive files, inject payloads, or abuse vulnerable endpoints.
- SSH brute force activity indicates repeated credential guessing and increases account compromise risk.
- A successful SSH login after suspicious activity should be treated as high-risk until validated.
- Multiple MITRE ATT&CK tactics were observed, suggesting this is more than a single isolated alert.

#### Evidence Summary

- Path Traversal Attempt (HIGH) matched `url=../` and merged 8 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 8 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 12 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`

#### MITRE Context

- `T1078` Valid Accounts → Defense Evasion, Initial Access, Persistence, Privilege Escalation
- `T1110` Brute Force → Credential Access
- `T1190` Exploit Public-Facing Application → Initial Access
- `T1595` Active Scanning → Reconnaissance

#### Scoring Reasons

- Web scanner activity was observed.
- Web exploitation attempts were observed.
- SSH failed login activity was observed.
- SSH brute force threshold was exceeded.
- SSH successful login was observed.
- Multiple log sources were correlated for the same source IP.
- Successful SSH login occurred after brute force-like activity.
- Possible compromise sequence detected: web exploitation attempts were followed by SSH brute force and successful login.
- Web scanning was followed by exploitation attempts.

#### Recommended Actions

1. Immediately review the successful SSH session and associated user account.
2. Rotate credentials for the affected user and check for unauthorized SSH keys.
3. Review shell history, process execution, and file modifications around the login time.
4. Review web server logs around the first exploitation attempt.
5. Validate whether the targeted endpoints are vulnerable or exposed unintentionally.
6. Check application logs for errors, unusual parameters, or suspicious response patterns.
7. Check whether the source IP performed broader reconnaissance across other endpoints.
8. Consider blocking scanner-like traffic if it is not part of an approved assessment.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T11:51:00+09:00` | `high` | Path Traversal Attempt | `8` | `url=../` |
| `2026-04-30T11:51:00+09:00` | `medium` | Web Scanner Activity | `8` | `user_agent=curl` |
| `2026-04-30T11:53:00+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T11:56:00+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T12:00:00` | `medium` | SSH Failed Login | `12` | `event_type=ssh_failed_login` |
| `2026-04-30T12:00:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T12:02:59` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000010 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `198.51.100.200` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T12:08:00` |
| Last Seen | `2026-04-30T12:10:35` |
| Alert Count | `3` |
| Unique Rule Count | `3` |
| MITRE Techniques | `T1078, T1110` |
| MITRE Tactics | `Credential Access, Defense Evasion, Initial Access, Persistence, Privilege Escalation` |
| Observed Stages | `ssh_failed_login, ssh_bruteforce, ssh_successful_login` |

#### Triage Verdict

Possible credential compromise detected. SSH brute force behavior was followed by successful login.

#### Why This Matters

- SSH brute force activity indicates repeated credential guessing and increases account compromise risk.
- A successful SSH login after suspicious activity should be treated as high-risk until validated.
- Multiple MITRE ATT&CK tactics were observed, suggesting this is more than a single isolated alert.

#### Evidence Summary

- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 10 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`

#### MITRE Context

- `T1078` Valid Accounts → Defense Evasion, Initial Access, Persistence, Privilege Escalation
- `T1110` Brute Force → Credential Access

#### Scoring Reasons

- SSH failed login activity was observed.
- SSH brute force threshold was exceeded.
- SSH successful login was observed.
- Successful SSH login occurred after brute force-like activity.

#### Recommended Actions

1. Immediately review the successful SSH session and associated user account.
2. Rotate credentials for the affected user and check for unauthorized SSH keys.
3. Review shell history, process execution, and file modifications around the login time.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T12:08:00` | `medium` | SSH Failed Login | `10` | `event_type=ssh_failed_login` |
| `2026-04-30T12:08:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T12:10:35` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000011 - HIGH

| Field | Value |
|---|---|
| Source IP | `203.0.113.90` |
| Severity | `high` |
| Confidence Score | `80` |
| Containment Priority | `P2 - Investigate and contain during active response window` |
| First Seen | `2026-04-30T12:20:00` |
| Last Seen | `2026-04-30T12:20:00` |
| Alert Count | `2` |
| Unique Rule Count | `2` |
| MITRE Techniques | `T1110` |
| MITRE Tactics | `Credential Access` |
| Observed Stages | `ssh_failed_login, ssh_bruteforce` |

#### Triage Verdict

SSH brute force behavior detected. Credential attack activity should be reviewed.

#### Why This Matters

- SSH brute force activity indicates repeated credential guessing and increases account compromise risk.

#### Evidence Summary

- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 6 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`

#### MITRE Context

- `T1110` Brute Force → Credential Access

#### Scoring Reasons

- SSH failed login activity was observed.
- SSH brute force threshold was exceeded.

#### Recommended Actions

1. Rate-limit or block the source IP at the firewall or SSH access layer.
2. Review authentication logs for additional failed login bursts from related IP ranges.
3. Verify whether password authentication should be disabled in favor of key-based access.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T12:20:00` | `medium` | SSH Failed Login | `6` | `event_type=ssh_failed_login` |
| `2026-04-30T12:20:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000012 - HIGH

| Field | Value |
|---|---|
| Source IP | `203.0.113.91` |
| Severity | `high` |
| Confidence Score | `80` |
| Containment Priority | `P2 - Investigate and contain during active response window` |
| First Seen | `2026-04-30T12:27:00` |
| Last Seen | `2026-04-30T12:27:00` |
| Alert Count | `2` |
| Unique Rule Count | `2` |
| MITRE Techniques | `T1110` |
| MITRE Tactics | `Credential Access` |
| Observed Stages | `ssh_failed_login, ssh_bruteforce` |

#### Triage Verdict

SSH brute force behavior detected. Credential attack activity should be reviewed.

#### Why This Matters

- SSH brute force activity indicates repeated credential guessing and increases account compromise risk.

#### Evidence Summary

- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 5 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`

#### MITRE Context

- `T1110` Brute Force → Credential Access

#### Scoring Reasons

- SSH failed login activity was observed.
- SSH brute force threshold was exceeded.

#### Recommended Actions

1. Rate-limit or block the source IP at the firewall or SSH access layer.
2. Review authentication logs for additional failed login bursts from related IP ranges.
3. Verify whether password authentication should be disabled in favor of key-based access.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T12:27:00` | `medium` | SSH Failed Login | `5` | `event_type=ssh_failed_login` |
| `2026-04-30T12:27:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.
