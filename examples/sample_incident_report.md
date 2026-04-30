# SOC Alert Triage Report

- Generated At: `2026-04-30T23:46:14`
- Total Incidents: `12`
- Raw Alerts: `395`
- Deduped Alerts: `39`
- Alert Reduction Rate: `90.13%`

## Executive Summary

- Critical Incidents: `6`
- High Incidents: `4`
- Medium Incidents: `2`
- Low Incidents: `0`

The engine grouped raw security alerts into incident-level findings, deduplicated repeated alerts, and reconstructed attack timelines for analyst review.

## Incident Details

### INC-000001 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `45.12.33.10` |
| Severity | `critical` |
| First Seen | `2026-04-30T09:45:00+09:00` |
| Last Seen | `2026-04-30T09:53:11` |
| Alert Count | `7` |
| Unique Rule Count | `7` |
| MITRE Techniques | `T1078, T1110, T1190, T1595` |

#### Summary

45.12.33.10 triggered multiple suspicious activities: Cross-Site Scripting Attempt, Path Traversal Attempt, SQL Injection Attempt, SSH Brute Force Threshold, SSH Failed Login, SSH Successful Login, Web Scanner Activity.

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

- Review whether the source IP should be blocked or monitored.
- Check whether similar requests were observed from nearby IP ranges.
- Validate whether the target endpoint was vulnerable or successfully accessed.

### INC-000002 - HIGH

| Field | Value |
|---|---|
| Source IP | `198.51.100.23` |
| Severity | `high` |
| First Seen | `2026-04-30T10:05:00+09:00` |
| Last Seen | `2026-04-30T10:05:00+09:00` |
| Alert Count | `1` |
| Unique Rule Count | `1` |
| MITRE Techniques | `T1190` |

#### Summary

198.51.100.23 triggered SQL Injection Attempt.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T10:05:00+09:00` | `high` | SQL Injection Attempt | `34` | `user_agent=sqlmap` |

#### Analyst Notes

- Review whether the source IP should be blocked or monitored.
- Check whether similar requests were observed from nearby IP ranges.
- Validate whether the target endpoint was vulnerable or successfully accessed.

### INC-000003 - MEDIUM

| Field | Value |
|---|---|
| Source IP | `192.0.2.44` |
| Severity | `medium` |
| First Seen | `2026-04-30T10:22:00+09:00` |
| Last Seen | `2026-04-30T10:22:00+09:00` |
| Alert Count | `1` |
| Unique Rule Count | `1` |
| MITRE Techniques | `T1190` |

#### Summary

192.0.2.44 triggered Cross-Site Scripting Attempt.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T10:22:00+09:00` | `medium` | Cross-Site Scripting Attempt | `28` | `url=<script>` |

#### Analyst Notes

- Review whether the source IP should be blocked or monitored.
- Check whether similar requests were observed from nearby IP ranges.
- Validate whether the target endpoint was vulnerable or successfully accessed.

### INC-000004 - HIGH

| Field | Value |
|---|---|
| Source IP | `203.0.113.88` |
| Severity | `high` |
| First Seen | `2026-04-30T10:38:00+09:00` |
| Last Seen | `2026-04-30T10:38:00+09:00` |
| Alert Count | `2` |
| Unique Rule Count | `2` |
| MITRE Techniques | `T1190, T1595` |

#### Summary

203.0.113.88 triggered multiple suspicious activities: Path Traversal Attempt, Web Scanner Activity.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T10:38:00+09:00` | `high` | Path Traversal Attempt | `26` | `url=../` |
| `2026-04-30T10:38:00+09:00` | `medium` | Web Scanner Activity | `26` | `user_agent=curl` |

#### Analyst Notes

- Review whether the source IP should be blocked or monitored.
- Check whether similar requests were observed from nearby IP ranges.
- Validate whether the target endpoint was vulnerable or successfully accessed.

### INC-000005 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `91.240.118.22` |
| Severity | `critical` |
| First Seen | `2026-04-30T10:52:00+09:00` |
| Last Seen | `2026-04-30T11:00:00` |
| Alert Count | `6` |
| Unique Rule Count | `6` |
| MITRE Techniques | `T1110, T1190, T1595` |

#### Summary

91.240.118.22 triggered multiple suspicious activities: Cross-Site Scripting Attempt, Path Traversal Attempt, SQL Injection Attempt, SSH Brute Force Threshold, SSH Failed Login, Web Scanner Activity.

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

- Review whether the source IP should be blocked or monitored.
- Check whether similar requests were observed from nearby IP ranges.
- Validate whether the target endpoint was vulnerable or successfully accessed.

### INC-000006 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `104.248.90.77` |
| Severity | `critical` |
| First Seen | `2026-04-30T11:08:00+09:00` |
| Last Seen | `2026-04-30T11:15:00` |
| Alert Count | `3` |
| Unique Rule Count | `3` |
| MITRE Techniques | `T1110, T1190` |

#### Summary

104.248.90.77 triggered multiple suspicious activities: SQL Injection Attempt, SSH Brute Force Threshold, SSH Failed Login.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T11:08:00+09:00` | `high` | SQL Injection Attempt | `22` | `user_agent=sqlmap` |
| `2026-04-30T11:15:00` | `medium` | SSH Failed Login | `9` | `event_type=ssh_failed_login` |
| `2026-04-30T11:15:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |

#### Analyst Notes

- Review whether the source IP should be blocked or monitored.
- Check whether similar requests were observed from nearby IP ranges.
- Validate whether the target endpoint was vulnerable or successfully accessed.

### INC-000007 - MEDIUM

| Field | Value |
|---|---|
| Source IP | `45.155.205.111` |
| Severity | `medium` |
| First Seen | `2026-04-30T11:21:00+09:00` |
| Last Seen | `2026-04-30T11:21:00+09:00` |
| Alert Count | `1` |
| Unique Rule Count | `1` |
| MITRE Techniques | `T1190` |

#### Summary

45.155.205.111 triggered Cross-Site Scripting Attempt.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T11:21:00+09:00` | `medium` | Cross-Site Scripting Attempt | `18` | `url=<script>` |

#### Analyst Notes

- Review whether the source IP should be blocked or monitored.
- Check whether similar requests were observed from nearby IP ranges.
- Validate whether the target endpoint was vulnerable or successfully accessed.

### INC-000008 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `185.220.101.15` |
| Severity | `critical` |
| First Seen | `2026-04-30T11:35:00+09:00` |
| Last Seen | `2026-04-30T11:45:00` |
| Alert Count | `4` |
| Unique Rule Count | `4` |
| MITRE Techniques | `T1110, T1190, T1595` |

#### Summary

185.220.101.15 triggered multiple suspicious activities: Path Traversal Attempt, SSH Brute Force Threshold, SSH Failed Login, Web Scanner Activity.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T11:35:00+09:00` | `high` | Path Traversal Attempt | `20` | `url=../` |
| `2026-04-30T11:35:00+09:00` | `medium` | Web Scanner Activity | `20` | `user_agent=curl` |
| `2026-04-30T11:45:00` | `medium` | SSH Failed Login | `18` | `event_type=ssh_failed_login` |
| `2026-04-30T11:45:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |

#### Analyst Notes

- Review whether the source IP should be blocked or monitored.
- Check whether similar requests were observed from nearby IP ranges.
- Validate whether the target endpoint was vulnerable or successfully accessed.

### INC-000009 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `167.99.42.31` |
| Severity | `critical` |
| First Seen | `2026-04-30T11:51:00+09:00` |
| Last Seen | `2026-04-30T12:02:59` |
| Alert Count | `7` |
| Unique Rule Count | `7` |
| MITRE Techniques | `T1078, T1110, T1190, T1595` |

#### Summary

167.99.42.31 triggered multiple suspicious activities: Cross-Site Scripting Attempt, Path Traversal Attempt, SQL Injection Attempt, SSH Brute Force Threshold, SSH Failed Login, SSH Successful Login, Web Scanner Activity.

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

- Review whether the source IP should be blocked or monitored.
- Check whether similar requests were observed from nearby IP ranges.
- Validate whether the target endpoint was vulnerable or successfully accessed.

### INC-000010 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `198.51.100.200` |
| Severity | `critical` |
| First Seen | `2026-04-30T12:08:00` |
| Last Seen | `2026-04-30T12:10:35` |
| Alert Count | `3` |
| Unique Rule Count | `3` |
| MITRE Techniques | `T1078, T1110` |

#### Summary

198.51.100.200 triggered multiple suspicious activities: SSH Brute Force Threshold, SSH Failed Login, SSH Successful Login.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T12:08:00` | `medium` | SSH Failed Login | `10` | `event_type=ssh_failed_login` |
| `2026-04-30T12:08:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |
| `2026-04-30T12:10:35` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |

#### Analyst Notes

- Review whether the source IP should be blocked or monitored.
- Check whether similar requests were observed from nearby IP ranges.
- Validate whether the target endpoint was vulnerable or successfully accessed.

### INC-000011 - HIGH

| Field | Value |
|---|---|
| Source IP | `203.0.113.90` |
| Severity | `high` |
| First Seen | `2026-04-30T12:20:00` |
| Last Seen | `2026-04-30T12:20:00` |
| Alert Count | `2` |
| Unique Rule Count | `2` |
| MITRE Techniques | `T1110` |

#### Summary

203.0.113.90 triggered multiple suspicious activities: SSH Brute Force Threshold, SSH Failed Login.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T12:20:00` | `medium` | SSH Failed Login | `6` | `event_type=ssh_failed_login` |
| `2026-04-30T12:20:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |

#### Analyst Notes

- Review whether the source IP should be blocked or monitored.
- Check whether similar requests were observed from nearby IP ranges.
- Validate whether the target endpoint was vulnerable or successfully accessed.

### INC-000012 - HIGH

| Field | Value |
|---|---|
| Source IP | `203.0.113.91` |
| Severity | `high` |
| First Seen | `2026-04-30T12:27:00` |
| Last Seen | `2026-04-30T12:27:00` |
| Alert Count | `2` |
| Unique Rule Count | `2` |
| MITRE Techniques | `T1110` |

#### Summary

203.0.113.91 triggered multiple suspicious activities: SSH Brute Force Threshold, SSH Failed Login.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T12:27:00` | `medium` | SSH Failed Login | `5` | `event_type=ssh_failed_login` |
| `2026-04-30T12:27:00` | `high` | SSH Brute Force Threshold | `1` | `failed_login_count=>=4 failures within 10 minutes` |

#### Analyst Notes

- Review whether the source IP should be blocked or monitored.
- Check whether similar requests were observed from nearby IP ranges.
- Validate whether the target endpoint was vulnerable or successfully accessed.
