# SOC Alert Triage Report

- Generated At: `2026-04-30T19:05:56`
- Total Incidents: `1`
- Raw Alerts: `11`
- Deduped Alerts: `5`
- Alert Reduction Rate: `54.55%`

## Executive Summary

- Critical Incidents: `1`
- High Incidents: `0`
- Medium Incidents: `0`
- Low Incidents: `0`

The engine grouped raw security alerts into incident-level findings, deduplicated repeated alerts, and reconstructed attack timelines for analyst review.

## Incident Details

### INC-000001 - CRITICAL

| Field | Value |
|---|---|
| Source IP | `45.12.33.10` |
| Severity | `critical` |
| First Seen | `2026-04-30T10:29:03+09:00` |
| Last Seen | `2026-04-30T10:36:52` |
| Alert Count | `5` |
| Unique Rule Count | `5` |
| MITRE Techniques | `T1078, T1110, T1190` |

#### Summary

45.12.33.10 triggered multiple suspicious activities: Cross-Site Scripting Attempt, Path Traversal Attempt, SQL Injection Attempt, SSH Failed Login, SSH Successful Login.

#### Attack Timeline

| Time | Severity | Rule | Duplicates | Evidence |
|---|---|---|---:|---|
| `2026-04-30T10:29:03+09:00` | `high` | Path Traversal Attempt | `1` | `url=../` |
| `2026-04-30T10:31:02+09:00` | `high` | SQL Injection Attempt | `3` | `user_agent=sqlmap` |
| `2026-04-30T10:33:44+09:00` | `medium` | Cross-Site Scripting Attempt | `1` | `url=<script>` |
| `2026-04-30T10:35:10` | `medium` | SSH Failed Login | `4` | `event_type=ssh_failed_login` |
| `2026-04-30T10:36:52` | `high` | SSH Successful Login | `1` | `event_type=ssh_success_login` |

#### Analyst Notes

- Review whether the source IP should be blocked or monitored.
- Check whether similar requests were observed from nearby IP ranges.
- Validate whether the target endpoint was vulnerable or successfully accessed.
