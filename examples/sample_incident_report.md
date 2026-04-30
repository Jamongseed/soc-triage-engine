# SOC Alert Triage Report

## Report Metadata

- Generated At: `2026-05-01T01:36:46`
- Total Incidents: `20`
- Raw Alerts: `7021`
- Deduped Alerts: `412`
- Alert Reduction Rate: `94.13%`

## Executive Summary

- Critical Incidents: `20`
- High Incidents: `0`
- Medium Incidents: `0`
- Low Incidents: `0`

The engine grouped raw security alerts into incident-level findings, suppressed known false positives, deduplicated repeated alerts, reconstructed attack timelines, enriched MITRE ATT&CK context, and applied sequence-based severity scoring for analyst review.

## Incident Details

### INC-000001 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `45.12.33.10` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T11:00:00+09:00` |
| Last Seen | `2026-04-30T21:18:46+09:00` |
| Alert Count | `26` |
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

- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 34 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=javascript:` and merged 11 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 36 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 11 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 35 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 5 repeated alerts

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
| `2026-04-30T11:00:00+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T11:00:00+09:00` | `medium` | Web Scanner Activity | `34` | `user_agent=curl` |
| `2026-04-30T11:00:36+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T11:01:16+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T11:10:21+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T11:11:01+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T11:11:40+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T13:00:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T13:00:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T13:04:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T14:40:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T16:03:20+09:00` | `medium` | Cross-Site Scripting Attempt | `11` | `url=javascript:` |
| `2026-04-30T16:03:31+09:00` | `medium` | Web Scanner Activity | `36` | `user_agent=python-requests` |
| `2026-04-30T16:04:10+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T16:04:48+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T16:13:28+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |
| `2026-04-30T16:14:33+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T16:15:15+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T16:20:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T21:06:40+09:00` | `high` | SQL Injection Attempt | `11` | `user_agent=sqlmap` |
| `2026-04-30T21:07:03+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T21:07:45+09:00` | `medium` | Web Scanner Activity | `35` | `user_agent=python-requests` |
| `2026-04-30T21:08:21+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T21:16:48+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T21:17:30+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T21:18:46+09:00` | `high` | Path Traversal Attempt | `5` | `url=../` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000002 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `198.51.100.23` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T11:15:33+09:00` |
| Last Seen | `2026-04-30T21:33:03+09:00` |
| Alert Count | `23` |
| Unique Rule Count | `6` |
| MITRE Techniques | `T1078, T1110, T1190` |
| MITRE Tactics | `Credential Access, Defense Evasion, Initial Access, Persistence, Privilege Escalation` |
| Observed Stages | `web_exploitation_attempt, ssh_failed_login, ssh_bruteforce, ssh_successful_login` |

#### Triage Verdict

Possible compromise sequence detected. The same source IP performed web exploitation attempts, triggered SSH brute force behavior, and later achieved successful SSH login.

#### Why This Matters

- Web exploitation attempts may indicate attempts to access sensitive files, inject payloads, or abuse vulnerable endpoints.
- SSH brute force activity indicates repeated credential guessing and increases account compromise risk.
- A successful SSH login after suspicious activity should be treated as high-risk until validated.
- Multiple MITRE ATT&CK tactics were observed, suggesting this is more than a single isolated alert.

#### Evidence Summary

- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 4 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 11 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 5 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts

#### MITRE Context

- `T1078` Valid Accounts → Defense Evasion, Initial Access, Persistence, Privilege Escalation
- `T1110` Brute Force → Credential Access
- `T1190` Exploit Public-Facing Application → Initial Access

#### Scoring Reasons

- Web exploitation attempts were observed.
- SSH failed login activity was observed.
- SSH brute force threshold was exceeded.
- SSH successful login was observed.
- Multiple log sources were correlated for the same source IP.
- Successful SSH login occurred after brute force-like activity.
- Possible compromise sequence detected: web exploitation attempts were followed by SSH brute force and successful login.

#### Recommended Actions

1. Immediately review the successful SSH session and associated user account.
2. Rotate credentials for the affected user and check for unauthorized SSH keys.
3. Review shell history, process execution, and file modifications around the login time.
4. Review web server logs around the first exploitation attempt.
5. Validate whether the targeted endpoints are vulnerable or exposed unintentionally.
6. Check application logs for errors, unusual parameters, or suspicious response patterns.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T11:15:33+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T11:16:15+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T11:16:51+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T11:26:00+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T11:26:36+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T11:27:16+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |
| `2026-04-30T13:05:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T13:05:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T14:45:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T14:49:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T16:18:30+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T16:19:46+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T16:20:25+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T16:25:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T16:28:51+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T16:30:10+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T16:30:48+09:00` | `high` | SQL Injection Attempt | `4` | `user_agent=sqlmap` |
| `2026-04-30T21:21:50+09:00` | `high` | Path Traversal Attempt | `11` | `url=../` |
| `2026-04-30T21:22:01+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T21:22:40+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T21:31:58+09:00` | `high` | Path Traversal Attempt | `5` | `url=../` |
| `2026-04-30T21:32:25+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T21:33:03+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000003 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `192.0.2.44` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T11:30:20+09:00` |
| Last Seen | `2026-04-30T21:48:40+09:00` |
| Alert Count | `26` |
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

- Cross-Site Scripting Attempt (MEDIUM) matched `url=javascript:` and merged 11 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 36 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 11 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 35 repeated alerts
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 5 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 34 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts

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
| `2026-04-30T11:30:20+09:00` | `medium` | Cross-Site Scripting Attempt | `11` | `url=javascript:` |
| `2026-04-30T11:30:31+09:00` | `medium` | Web Scanner Activity | `36` | `user_agent=python-requests` |
| `2026-04-30T11:31:10+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T11:31:48+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T11:40:28+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |
| `2026-04-30T11:41:33+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T11:42:15+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T13:10:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T13:10:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T14:50:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T16:30:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T16:33:40+09:00` | `high` | SQL Injection Attempt | `11` | `user_agent=sqlmap` |
| `2026-04-30T16:34:03+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T16:34:45+09:00` | `medium` | Web Scanner Activity | `35` | `user_agent=python-requests` |
| `2026-04-30T16:34:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T16:35:21+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T16:43:48+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T16:44:30+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T16:45:46+09:00` | `high` | Path Traversal Attempt | `5` | `url=../` |
| `2026-04-30T21:37:00+09:00` | `medium` | Web Scanner Activity | `34` | `user_agent=curl` |
| `2026-04-30T21:37:00+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T21:37:36+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T21:38:16+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T21:47:21+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T21:48:01+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T21:48:40+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000004 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `203.0.113.88` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T11:45:30+09:00` |
| Last Seen | `2026-04-30T22:04:16+09:00` |
| Alert Count | `25` |
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

- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 36 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 4 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 34 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 11 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 5 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 35 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts

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
| `2026-04-30T11:45:30+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T11:46:06+09:00` | `medium` | Web Scanner Activity | `36` | `user_agent=python-requests` |
| `2026-04-30T11:46:46+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T11:47:25+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T11:55:51+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T11:57:10+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T11:57:48+09:00` | `high` | SQL Injection Attempt | `4` | `user_agent=sqlmap` |
| `2026-04-30T13:15:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T13:15:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T14:55:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T16:35:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T16:48:50+09:00` | `medium` | Web Scanner Activity | `34` | `user_agent=curl` |
| `2026-04-30T16:48:50+09:00` | `high` | Path Traversal Attempt | `11` | `url=../` |
| `2026-04-30T16:49:01+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T16:49:40+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T16:58:58+09:00` | `high` | Path Traversal Attempt | `5` | `url=../` |
| `2026-04-30T16:59:25+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T17:00:03+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T21:52:10+09:00` | `medium` | Web Scanner Activity | `35` | `user_agent=python-requests` |
| `2026-04-30T21:52:33+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T21:53:15+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T21:53:51+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T22:03:00+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T22:03:36+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T22:04:16+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |

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
| First Seen | `2026-04-30T12:00:40+09:00` |
| Last Seen | `2026-04-30T22:19:15+09:00` |
| Alert Count | `26` |
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

- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 11 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 35 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 5 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 34 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=javascript:` and merged 11 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 36 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts

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
| `2026-04-30T12:00:40+09:00` | `high` | SQL Injection Attempt | `11` | `user_agent=sqlmap` |
| `2026-04-30T12:01:03+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T12:01:45+09:00` | `medium` | Web Scanner Activity | `35` | `user_agent=python-requests` |
| `2026-04-30T12:02:21+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T12:10:48+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T12:11:30+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T12:12:46+09:00` | `high` | Path Traversal Attempt | `5` | `url=../` |
| `2026-04-30T13:20:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T13:20:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T15:00:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T15:04:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T16:40:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T17:04:00+09:00` | `medium` | Web Scanner Activity | `34` | `user_agent=curl` |
| `2026-04-30T17:04:00+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T17:04:36+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T17:05:16+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T17:14:21+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T17:15:01+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T17:15:40+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T22:07:20+09:00` | `medium` | Cross-Site Scripting Attempt | `11` | `url=javascript:` |
| `2026-04-30T22:07:31+09:00` | `medium` | Web Scanner Activity | `36` | `user_agent=python-requests` |
| `2026-04-30T22:08:10+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T22:08:48+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T22:17:28+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |
| `2026-04-30T22:18:33+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T22:19:15+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |

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
| First Seen | `2026-04-30T12:15:50+09:00` |
| Last Seen | `2026-04-30T22:32:51+09:00` |
| Alert Count | `24` |
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

- Path Traversal Attempt (HIGH) matched `url=../` and merged 11 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 34 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 5 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 35 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 24 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 2 repeated alerts

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
| `2026-04-30T12:15:50+09:00` | `high` | Path Traversal Attempt | `11` | `url=../` |
| `2026-04-30T12:15:50+09:00` | `medium` | Web Scanner Activity | `34` | `user_agent=curl` |
| `2026-04-30T12:16:01+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T12:16:40+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T12:25:58+09:00` | `high` | Path Traversal Attempt | `5` | `url=../` |
| `2026-04-30T12:26:25+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T12:27:03+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T13:25:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T13:25:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T15:05:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T16:45:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T16:49:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T17:19:10+09:00` | `medium` | Web Scanner Activity | `35` | `user_agent=python-requests` |
| `2026-04-30T17:19:33+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T17:20:15+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T17:20:51+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T17:30:00+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T17:30:36+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T17:31:16+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |
| `2026-04-30T22:22:30+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T22:23:06+09:00` | `medium` | Web Scanner Activity | `24` | `user_agent=python-requests` |
| `2026-04-30T22:23:46+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T22:24:25+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T22:32:51+09:00` | `medium` | Cross-Site Scripting Attempt | `2` | `url=<script>` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000007 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `45.155.205.111` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T12:31:00+09:00` |
| Last Seen | `2026-04-30T17:46:15+09:00` |
| Alert Count | `19` |
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

- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 34 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=javascript:` and merged 11 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 36 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts

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
| `2026-04-30T12:31:00+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T12:31:00+09:00` | `medium` | Web Scanner Activity | `34` | `user_agent=curl` |
| `2026-04-30T12:31:36+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T12:32:16+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T12:41:21+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T12:42:01+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T12:42:40+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T13:30:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T13:30:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T13:34:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T15:10:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T16:50:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T17:34:20+09:00` | `medium` | Cross-Site Scripting Attempt | `11` | `url=javascript:` |
| `2026-04-30T17:34:31+09:00` | `medium` | Web Scanner Activity | `36` | `user_agent=python-requests` |
| `2026-04-30T17:35:10+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T17:35:48+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T17:44:28+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |
| `2026-04-30T17:45:33+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T17:46:15+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |

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
| First Seen | `2026-04-30T12:46:10+09:00` |
| Last Seen | `2026-04-30T18:01:48+09:00` |
| Alert Count | `19` |
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

- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 35 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 36 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 4 repeated alerts

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
| `2026-04-30T12:46:10+09:00` | `medium` | Web Scanner Activity | `35` | `user_agent=python-requests` |
| `2026-04-30T12:46:33+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T12:47:15+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T12:47:51+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T12:57:00+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T12:57:36+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T12:58:16+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |
| `2026-04-30T13:35:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T13:35:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T15:15:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T15:19:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T16:55:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T17:49:30+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T17:50:06+09:00` | `medium` | Web Scanner Activity | `36` | `user_agent=python-requests` |
| `2026-04-30T17:50:46+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T17:51:25+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T17:59:51+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T18:01:10+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T18:01:48+09:00` | `high` | SQL Injection Attempt | `4` | `user_agent=sqlmap` |

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
| First Seen | `2026-04-30T13:01:20+09:00` |
| Last Seen | `2026-04-30T18:16:46+09:00` |
| Alert Count | `19` |
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

- Cross-Site Scripting Attempt (MEDIUM) matched `url=javascript:` and merged 11 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 36 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 11 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 35 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 5 repeated alerts

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
| `2026-04-30T13:01:20+09:00` | `medium` | Cross-Site Scripting Attempt | `11` | `url=javascript:` |
| `2026-04-30T13:01:31+09:00` | `medium` | Web Scanner Activity | `36` | `user_agent=python-requests` |
| `2026-04-30T13:02:10+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T13:02:48+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T13:11:28+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |
| `2026-04-30T13:12:33+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T13:13:15+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T13:40:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T13:40:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T15:20:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T17:00:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T17:04:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T18:04:40+09:00` | `high` | SQL Injection Attempt | `11` | `user_agent=sqlmap` |
| `2026-04-30T18:05:03+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T18:05:45+09:00` | `medium` | Web Scanner Activity | `35` | `user_agent=python-requests` |
| `2026-04-30T18:06:21+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T18:14:48+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T18:15:30+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T18:16:46+09:00` | `high` | Path Traversal Attempt | `5` | `url=../` |

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
| First Seen | `2026-04-30T13:16:30+09:00` |
| Last Seen | `2026-04-30T18:31:03+09:00` |
| Alert Count | `17` |
| Unique Rule Count | `6` |
| MITRE Techniques | `T1078, T1110, T1190` |
| MITRE Tactics | `Credential Access, Defense Evasion, Initial Access, Persistence, Privilege Escalation` |
| Observed Stages | `web_exploitation_attempt, ssh_failed_login, ssh_bruteforce, ssh_successful_login` |

#### Triage Verdict

Possible compromise sequence detected. The same source IP performed web exploitation attempts, triggered SSH brute force behavior, and later achieved successful SSH login.

#### Why This Matters

- Web exploitation attempts may indicate attempts to access sensitive files, inject payloads, or abuse vulnerable endpoints.
- SSH brute force activity indicates repeated credential guessing and increases account compromise risk.
- A successful SSH login after suspicious activity should be treated as high-risk until validated.
- Multiple MITRE ATT&CK tactics were observed, suggesting this is more than a single isolated alert.

#### Evidence Summary

- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 4 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 11 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 5 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts

#### MITRE Context

- `T1078` Valid Accounts → Defense Evasion, Initial Access, Persistence, Privilege Escalation
- `T1110` Brute Force → Credential Access
- `T1190` Exploit Public-Facing Application → Initial Access

#### Scoring Reasons

- Web exploitation attempts were observed.
- SSH failed login activity was observed.
- SSH brute force threshold was exceeded.
- SSH successful login was observed.
- Multiple log sources were correlated for the same source IP.
- Successful SSH login occurred after brute force-like activity.
- Possible compromise sequence detected: web exploitation attempts were followed by SSH brute force and successful login.

#### Recommended Actions

1. Immediately review the successful SSH session and associated user account.
2. Rotate credentials for the affected user and check for unauthorized SSH keys.
3. Review shell history, process execution, and file modifications around the login time.
4. Review web server logs around the first exploitation attempt.
5. Validate whether the targeted endpoints are vulnerable or exposed unintentionally.
6. Check application logs for errors, unusual parameters, or suspicious response patterns.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T13:16:30+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T13:17:46+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T13:18:25+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T13:26:51+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T13:28:10+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T13:28:48+09:00` | `high` | SQL Injection Attempt | `4` | `user_agent=sqlmap` |
| `2026-04-30T13:45:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T13:45:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T13:49:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T15:25:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T17:05:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T18:19:50+09:00` | `high` | Path Traversal Attempt | `11` | `url=../` |
| `2026-04-30T18:20:01+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T18:20:40+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T18:29:58+09:00` | `high` | Path Traversal Attempt | `5` | `url=../` |
| `2026-04-30T18:30:25+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T18:31:03+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000011 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `203.0.113.90` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T13:31:40+09:00` |
| Last Seen | `2026-04-30T18:46:40+09:00` |
| Alert Count | `18` |
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

- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 11 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 35 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 5 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 34 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts

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
| `2026-04-30T13:31:40+09:00` | `high` | SQL Injection Attempt | `11` | `user_agent=sqlmap` |
| `2026-04-30T13:32:03+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T13:32:45+09:00` | `medium` | Web Scanner Activity | `35` | `user_agent=python-requests` |
| `2026-04-30T13:33:21+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T13:41:48+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T13:42:30+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T13:43:46+09:00` | `high` | Path Traversal Attempt | `5` | `url=../` |
| `2026-04-30T13:50:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T13:50:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T15:30:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T17:10:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T18:35:00+09:00` | `medium` | Web Scanner Activity | `34` | `user_agent=curl` |
| `2026-04-30T18:35:00+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T18:35:36+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T18:36:16+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T18:45:21+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T18:46:01+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T18:46:40+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000012 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `203.0.113.91` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T13:46:50+09:00` |
| Last Seen | `2026-04-30T19:02:16+09:00` |
| Alert Count | `18` |
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

- Path Traversal Attempt (HIGH) matched `url=../` and merged 11 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 34 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- Path Traversal Attempt (HIGH) matched `url=../` and merged 5 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 35 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts

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
| `2026-04-30T13:46:50+09:00` | `high` | Path Traversal Attempt | `11` | `url=../` |
| `2026-04-30T13:46:50+09:00` | `medium` | Web Scanner Activity | `34` | `user_agent=curl` |
| `2026-04-30T13:47:01+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T13:47:40+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T13:55:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T13:55:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T13:56:58+09:00` | `high` | Path Traversal Attempt | `5` | `url=../` |
| `2026-04-30T13:57:25+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T13:58:03+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T15:35:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T17:15:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T18:50:10+09:00` | `medium` | Web Scanner Activity | `35` | `user_agent=python-requests` |
| `2026-04-30T18:50:33+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T18:51:15+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T18:51:51+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T19:01:00+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T19:01:36+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T19:02:16+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000013 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `64.227.18.90` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T14:00:00` |
| Last Seen | `2026-04-30T19:17:15+09:00` |
| Alert Count | `19` |
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

- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 34 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=javascript:` and merged 11 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 36 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts

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
| `2026-04-30T14:00:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T14:00:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T14:02:00+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T14:02:00+09:00` | `medium` | Web Scanner Activity | `34` | `user_agent=curl` |
| `2026-04-30T14:02:36+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T14:03:16+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T14:04:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T14:12:21+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T14:13:01+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T14:13:40+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T15:40:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T17:20:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T19:05:20+09:00` | `medium` | Cross-Site Scripting Attempt | `11` | `url=javascript:` |
| `2026-04-30T19:05:31+09:00` | `medium` | Web Scanner Activity | `36` | `user_agent=python-requests` |
| `2026-04-30T19:06:10+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T19:06:48+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T19:15:28+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |
| `2026-04-30T19:16:33+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T19:17:15+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000014 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `143.198.77.21` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T14:05:00` |
| Last Seen | `2026-04-30T19:32:48+09:00` |
| Alert Count | `19` |
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

- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 35 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 36 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 4 repeated alerts

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
| `2026-04-30T14:05:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T14:05:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T14:17:10+09:00` | `medium` | Web Scanner Activity | `35` | `user_agent=python-requests` |
| `2026-04-30T14:17:33+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T14:18:15+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T14:18:51+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T14:28:00+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T14:28:36+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T14:29:16+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |
| `2026-04-30T15:45:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T15:49:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T17:25:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T19:20:30+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T19:21:06+09:00` | `medium` | Web Scanner Activity | `36` | `user_agent=python-requests` |
| `2026-04-30T19:21:46+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T19:22:25+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T19:30:51+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T19:32:10+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T19:32:48+09:00` | `high` | SQL Injection Attempt | `4` | `user_agent=sqlmap` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000015 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `178.128.94.18` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T14:10:00` |
| Last Seen | `2026-04-30T19:47:46+09:00` |
| Alert Count | `19` |
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

- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- Cross-Site Scripting Attempt (MEDIUM) matched `url=javascript:` and merged 11 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 36 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 11 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 35 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 5 repeated alerts

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
| `2026-04-30T14:10:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T14:10:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T14:32:20+09:00` | `medium` | Cross-Site Scripting Attempt | `11` | `url=javascript:` |
| `2026-04-30T14:32:31+09:00` | `medium` | Web Scanner Activity | `36` | `user_agent=python-requests` |
| `2026-04-30T14:33:10+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T14:33:48+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T14:42:28+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |
| `2026-04-30T14:43:33+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T14:44:15+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T15:50:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T17:30:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T17:34:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T19:35:40+09:00` | `high` | SQL Injection Attempt | `11` | `user_agent=sqlmap` |
| `2026-04-30T19:36:03+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T19:36:45+09:00` | `medium` | Web Scanner Activity | `35` | `user_agent=python-requests` |
| `2026-04-30T19:37:21+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T19:45:48+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T19:46:30+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T19:47:46+09:00` | `high` | Path Traversal Attempt | `5` | `url=../` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000016 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `159.65.203.44` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T14:15:00` |
| Last Seen | `2026-04-30T20:02:03+09:00` |
| Alert Count | `19` |
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

- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 36 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 4 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 34 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 11 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 5 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts

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
| `2026-04-30T14:15:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T14:15:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T14:19:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T14:47:30+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T14:48:06+09:00` | `medium` | Web Scanner Activity | `36` | `user_agent=python-requests` |
| `2026-04-30T14:48:46+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T14:49:25+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T14:57:51+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T14:59:10+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T14:59:48+09:00` | `high` | SQL Injection Attempt | `4` | `user_agent=sqlmap` |
| `2026-04-30T15:55:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T17:35:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T19:50:50+09:00` | `medium` | Web Scanner Activity | `34` | `user_agent=curl` |
| `2026-04-30T19:50:50+09:00` | `high` | Path Traversal Attempt | `11` | `url=../` |
| `2026-04-30T19:51:01+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T19:51:40+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T20:00:58+09:00` | `high` | Path Traversal Attempt | `5` | `url=../` |
| `2026-04-30T20:01:25+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T20:02:03+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000017 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `139.59.12.88` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T14:20:00` |
| Last Seen | `2026-04-30T20:17:40+09:00` |
| Alert Count | `19` |
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

- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 11 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 35 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 5 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 34 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts

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
| `2026-04-30T14:20:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T14:20:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T15:02:40+09:00` | `high` | SQL Injection Attempt | `11` | `user_agent=sqlmap` |
| `2026-04-30T15:03:03+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T15:03:45+09:00` | `medium` | Web Scanner Activity | `35` | `user_agent=python-requests` |
| `2026-04-30T15:04:21+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T15:12:48+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T15:13:30+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T15:14:46+09:00` | `high` | Path Traversal Attempt | `5` | `url=../` |
| `2026-04-30T16:00:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T16:04:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T17:40:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T20:06:00+09:00` | `medium` | Web Scanner Activity | `34` | `user_agent=curl` |
| `2026-04-30T20:06:00+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T20:06:36+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T20:07:16+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T20:16:21+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T20:17:01+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T20:17:40+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000018 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `206.189.45.19` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T14:25:00` |
| Last Seen | `2026-04-30T20:33:16+09:00` |
| Alert Count | `19` |
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

- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- Path Traversal Attempt (HIGH) matched `url=../` and merged 11 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 34 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 5 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 35 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts

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
| `2026-04-30T14:25:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T14:25:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T15:17:50+09:00` | `high` | Path Traversal Attempt | `11` | `url=../` |
| `2026-04-30T15:17:50+09:00` | `medium` | Web Scanner Activity | `34` | `user_agent=curl` |
| `2026-04-30T15:18:01+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T15:18:40+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T15:27:58+09:00` | `high` | Path Traversal Attempt | `5` | `url=../` |
| `2026-04-30T15:28:25+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T15:29:03+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T16:05:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T17:45:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T17:49:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T20:21:10+09:00` | `medium` | Web Scanner Activity | `35` | `user_agent=python-requests` |
| `2026-04-30T20:21:33+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T20:22:15+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T20:22:51+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T20:32:00+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T20:32:36+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T20:33:16+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000019 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `188.166.21.70` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T14:30:00` |
| Last Seen | `2026-04-30T20:48:15+09:00` |
| Alert Count | `19` |
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

- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=curl` and merged 34 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=javascript:` and merged 11 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 36 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts

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
| `2026-04-30T14:30:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T14:30:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T14:34:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T15:33:00+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T15:33:00+09:00` | `medium` | Web Scanner Activity | `34` | `user_agent=curl` |
| `2026-04-30T15:33:36+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T15:34:16+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T15:43:21+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T15:44:01+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T15:44:40+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T16:10:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T17:50:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T20:36:20+09:00` | `medium` | Cross-Site Scripting Attempt | `11` | `url=javascript:` |
| `2026-04-30T20:36:31+09:00` | `medium` | Web Scanner Activity | `36` | `user_agent=python-requests` |
| `2026-04-30T20:37:10+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T20:37:48+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T20:46:28+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |
| `2026-04-30T20:47:33+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T20:48:15+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.

### INC-000020 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `157.245.33.10` |
| Severity | `critical` |
| Confidence Score | `100` |
| Containment Priority | `P1 - Immediate containment recommended` |
| First Seen | `2026-04-30T14:35:00` |
| Last Seen | `2026-04-30T21:03:48+09:00` |
| Alert Count | `19` |
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

- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- SSH Brute Force Threshold (HIGH) matched `failed_login_count=>=4 failures within 10 minutes`
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 35 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 6 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 5 repeated alerts
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 24 repeated alerts
- SSH Successful Login (HIGH) matched `event_type=ssh_success_login`
- SSH Failed Login (MEDIUM) matched `event_type=ssh_failed_login` and merged 25 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 12 repeated alerts
- Web Scanner Activity (MEDIUM) matched `user_agent=python-requests` and merged 36 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 12 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 12 repeated alerts
- Cross-Site Scripting Attempt (MEDIUM) matched `url=<script>` and merged 6 repeated alerts
- Path Traversal Attempt (HIGH) matched `url=../` and merged 6 repeated alerts
- SQL Injection Attempt (HIGH) matched `user_agent=sqlmap` and merged 4 repeated alerts

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
| `2026-04-30T14:35:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T14:35:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T15:48:10+09:00` | `medium` | Web Scanner Activity | `35` | `user_agent=python-requests` |
| `2026-04-30T15:48:33+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T15:49:15+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T15:49:51+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T15:59:00+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T15:59:36+09:00` | `high` | SQL Injection Attempt | `6` | `user_agent=sqlmap` |
| `2026-04-30T16:00:16+09:00` | `medium` | Cross-Site Scripting Attempt | `5` | `url=<script>` |
| `2026-04-30T16:15:00` | `medium` | SSH Failed Login | `24` | `event_type=ssh_failed_login` |
| `2026-04-30T16:19:48` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |
| `2026-04-30T17:55:00` | `medium` | SSH Failed Login | `25` | `event_type=ssh_failed_login` |
| `2026-04-30T20:51:30+09:00` | `medium` | Cross-Site Scripting Attempt | `12` | `url=<script>` |
| `2026-04-30T20:52:06+09:00` | `medium` | Web Scanner Activity | `36` | `user_agent=python-requests` |
| `2026-04-30T20:52:46+09:00` | `high` | Path Traversal Attempt | `12` | `url=../` |
| `2026-04-30T20:53:25+09:00` | `high` | SQL Injection Attempt | `12` | `user_agent=sqlmap` |
| `2026-04-30T21:01:51+09:00` | `medium` | Cross-Site Scripting Attempt | `6` | `url=<script>` |
| `2026-04-30T21:03:10+09:00` | `high` | Path Traversal Attempt | `6` | `url=../` |
| `2026-04-30T21:03:48+09:00` | `high` | SQL Injection Attempt | `4` | `user_agent=sqlmap` |

#### Analyst Notes

- Confirm whether the source IP is external, internal, trusted, or already blocked.
- Validate whether the related user account, endpoint, or web application is expected to receive this traffic.
- Review raw logs and surrounding events before closing or escalating the incident.
