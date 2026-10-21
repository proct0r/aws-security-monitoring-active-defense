# Forensic timeline

All times are **UTC**, taken from CloudTrail, the CloudWatch alarm email and the Secrets Manager console. Times shown in the email client's own header (e.g. "Mon, Sep 7, 8:20 PM") are in the viewer's local time zone and are not used for correlation.

| Time (UTC) | Source | Event |
|---|---|---|
| 2026-09-07 17:00:00 | Secrets Manager (Fig. 3) | Honeytoken `Production_Database_Credentials` created |
| 2026-09-07 (evening) | Email (Fig. 5, first message) | First Flow 1 alarm from the initial test run |
| 2026-09-08 05:47:00 | Alarm datapoint (Fig. 5) | 1-minute bucket containing a honeytoken read (value 1.0) |
| 2026-09-08 05:48:45 | CloudWatch alarm (Fig. 5) | `OK → ALARM`, SNS Flow 1 email sent |
| 2026-09-08 06:22:06 | CloudTrail (Fig. 7) | Victim `GetSecretValue`, `errorCode: null` (success) |
| 2026-09-08 06:50:05 | CloudTrail (Fig. 7) | Victim `GetSecretValue`, success |
| 2026-09-08 07:09:32 | CloudTrail (Fig. 7) | Victim `GetSecretValue`, success |
| 2026-09-08 07:46:11 | CloudTrail (Fig. 7) | Victim `GetSecretValue`, success |
| 2026-09-08 (before 09:35) | CloudTrail (Fig. 7, partly hidden) | Victim `GetSecretValue`, success — the read that triggered the final quarantine run |
| 2026-09-08 (before 09:35) | SSM / IAM | `SoloGaurd-QuarantineVictim` executes; boundary attached |
| **2026-09-08 09:35:15** | CloudTrail (Fig. 4, 7) + CLI (Fig. 6) | Victim `GetSecretValue` → **`AccessDenied`**, explicit deny in `SoloGaurd-QuarantineBoundary` |

The several successful reads between 06:22 and 07:46 correspond to repeated test runs during the session — the kill-switch run and the re-runs made while the Automation target input was being corrected.

## Rebuilding the timeline

```bash
./scripts/collect-evidence.sh evidence
jq -r '.[] | [.eventTime, .userName, (.errorCode // "OK")] | @tsv' evidence/cloudtrail-getsecretvalue.json
```

Or in **CloudTrail Lake** / Athena:

```sql
SELECT eventTime, userIdentity.userName, eventName, errorCode, errorMessage
FROM   <event_data_store>
WHERE  eventSource = 'secretsmanager.amazonaws.com'
  AND  eventName   = 'GetSecretValue'
  AND  userIdentity.userName = 'Victim'
  AND  eventTime BETWEEN '2026-09-07 00:00:00' AND '2026-09-09 00:00:00'
ORDER BY eventTime;
```

## Chain-of-custody notes

- Original, unredacted screenshots were retained by the author; this repository holds redacted copies only.
- CloudTrail log-file validation was enabled, so delivered log files can be checked with `aws cloudtrail validate-logs`.
- The source IP is redacted in every published artefact.
