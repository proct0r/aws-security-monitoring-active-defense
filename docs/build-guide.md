# Build guide (console walk-through)

This is the manual, click-by-click version of [`scripts/deploy.sh`](../scripts/deploy.sh), with the reason for each setting. Work in **Africa (Cape Town) `af-south-1`** in a sandbox account.

## 0. Prerequisites

- An account where `af-south-1` is enabled (*Account → AWS Regions → Enable*).
- An admin identity for building. The `Victim` user is created later and is the only identity used for testing.
- An email inbox for the SNS subscriptions.

## 1. Plant the honeytoken

**Secrets Manager → Store a new secret → Other type of secret**

| Setting | Value | Why |
|---|---|---|
| Key/value | `username=db_admin_DECOY`, `password=<random>` | Looks real, is worthless |
| Encryption key | `aws/secretsmanager` | Default is fine for a decoy |
| Name | `Production_Database_Credentials` | An attractive name an attacker would go for |
| Description | Controlled security monitoring honeytoken… | Documents intent for other admins |
| Rotation | Off | Nothing consumes it |

Because nothing legitimate reads this secret, **one read is a high-confidence alert**.

## 2. Audit: CloudTrail trail

**CloudTrail → Trails → Create trail**

| Setting | Value | Why |
|---|---|---|
| Name | `SoloGaurd-Trail` | |
| Storage | New S3 bucket; SSE enabled | Durable archive |
| Log file validation | Enabled | Detects tampering with delivered logs |
| CloudWatch Logs | Enabled, new log group, new role | Required for Flow 1 |
| Event type | Management events, **Read and Write** | `GetSecretValue` is a **read** event — Write-only would miss it |
| Multi-Region | Yes (default for console trails) | Catches activity in any Region |

Then on the trail bucket: **Properties → Server access logging → Enable**, target a *separate* bucket. Block public access on both buckets.

## 3. Notification: SNS topics

Create two **Standard** topics: `SoloGaurd-SecurityAlert-Flow1` and `SoloGaurd-SecurityAlert-Flow2`. Add an **Email** subscription to each and **click the confirmation link in both emails** — unconfirmed subscriptions receive nothing.

For Flow 2, the topic access policy must allow `events.amazonaws.com` to publish ([`config/iam/sns-topic-policy-flow2.json`](../config/iam/sns-topic-policy-flow2.json)). The console adds this automatically when you pick the topic as a rule target.

## 4. Flow 1: metric filter and alarm

**CloudWatch → Log groups → (trail log group) → Metric filters → Create**

```text
{ ($.eventSource = "secretsmanager.amazonaws.com") && ($.eventName = "GetSecretValue") && ($.requestParameters.secretId = "*Production_Database_Credentials*") }
```

Use **Test pattern** against recent events. Metric namespace `SoloGaurd/Security`, metric name `SensitiveSecretAccess`, value `1`, default value `0`.

**Create alarm** on the metric:

| Setting | Value | Why |
|---|---|---|
| Statistic / period | Sum / 1 minute | Count of reads per minute |
| Condition | ≥ 1 | Any read is suspicious |
| Datapoints to alarm | 1 of 1 | Fire on the first occurrence |
| Missing data | Treat as good (not breaching) | No reads = OK |
| Action | In alarm → `SoloGaurd-SecurityAlert-Flow1` | |
| Name | `SoloGaurd-SensitiveSecretAccess-Alarm` | |

## 5. Flow 2: EventBridge alert rule

**EventBridge → Rules → Create rule** on the `default` bus, type *Rule with an event pattern*. Paste [`config/eventbridge/flow2-alert-pattern.json`](../config/eventbridge/flow2-alert-pattern.json). Target: SNS topic `SoloGaurd-SecurityAlert-Flow2`. Name: `SoloGaurd-SensitiveSecretAccess-EventBridge`.

> **Important:** after creating it, set the rule to **"Enabled with CloudTrail read-only management events"** (CLI state `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`). Plain *Enabled* does not deliver read-only events such as `GetSecretValue`.

## 6. Test identity: `Victim`

1. **IAM → Users → Create user** `Victim`, no console access.
2. Add the inline policy [`config/iam/victim-identity-policy.json`](../config/iam/victim-identity-policy.json).
3. **Security credentials → Create access key** (CLI). In CloudShell: `aws configure --profile sologuard-victim`.
4. Create managed policy **`SoloGaurd-QuarantineBoundary`** from [`config/iam/quarantine-boundary-policy.json`](../config/iam/quarantine-boundary-policy.json). Do **not** attach it yet.

## 7. Response roles (least privilege)

| Role | Trusted by | Permissions file |
|---|---|---|
| `SoloGaurd-SSMAutomationRole` | `ssm.amazonaws.com` | [`ssm-automation-role-policy.json`](../config/iam/ssm-automation-role-policy.json) |
| `SoloGaurd-EventBridgeInvokeSSMRole` | `events.amazonaws.com` | [`eventbridge-invoke-ssm-role-policy.json`](../config/iam/eventbridge-invoke-ssm-role-policy.json) |

The automation role can only attach **this** boundary to **this** user (`iam:PermissionsBoundary` condition), so a compromised runbook could not, for example, remove a boundary or target an administrator.

## 8. Runbooks

**Systems Manager → Documents → Create document → Automation**, YAML editor:

- `SoloGaurd-QuarantineVictim` ← [`config/ssm/SoloGaurd-QuarantineVictim.yaml`](../config/ssm/SoloGaurd-QuarantineVictim.yaml)
- `SoloGaurd-DisableVictimAccessKey` ← [`config/ssm/SoloGaurd-DisableVictimAccessKey.yaml`](../config/ssm/SoloGaurd-DisableVictimAccessKey.yaml)

Replace `<ACCOUNT_ID>`. You can test the quarantine runbook manually with `UserName=Victim`, then run `scripts/reset-victim.sh`.

## 9. Active-defense rules

Create two rules from [`config/eventbridge/active-defense-pattern.json`](../config/eventbridge/active-defense-pattern.json) (successful `GetSecretValue` by `Victim` on the honeytoken):

| Rule | Target | Input transformer | State |
|---|---|---|---|
| `SoloGaurd-SensitiveAccess-Quarantine` | SSM Automation `SoloGaurd-QuarantineVictim` | [`quarantine-target-input-transformer.json`](../config/eventbridge/quarantine-target-input-transformer.json) | Enabled **with read-only management events** |
| `SoloGaurd-SensitiveAccess-KillSwitch` | SSM Automation `SoloGaurd-DisableVictimAccessKey` | [`killswitch-target-input-transformer.json`](../config/eventbridge/killswitch-target-input-transformer.json) | Disabled (enable only for the kill-switch test) |

Execution role for both: `SoloGaurd-EventBridgeInvokeSSMRole`. Run **one response rule at a time** — with both enabled, the key would be disabled and you would not get the `AccessDenied` evidence.

## 10. Test

```bash
./scripts/simulate-access.sh
```

Expected: attempt 1 succeeds → two emails arrive → SSM execution `Success` → Victim shows the boundary → attempt 2 returns `AccessDeniedException … explicit deny in a permissions boundary`. Then run `./scripts/collect-evidence.sh`.
