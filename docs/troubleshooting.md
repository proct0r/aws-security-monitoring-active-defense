# Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Flow 2 / active-defense rule never fires | Rule state is plain *Enabled*; `GetSecretValue` is a **read-only** management event | Set state to *Enabled with CloudTrail read-only management events* (`ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`) |
| Flow 1 alarm never fires | Trail logs Write events only, or isn't sending to CloudWatch Logs | Trail → Management events **Read + Write**; check the log group receives events |
| Metric filter shows no data | Pattern doesn't match how the secret was referenced (name vs ARN) | Use the `*Production_Database_Credentials*` wildcard; use *Test pattern* on real events |
| No emails at all | SNS subscriptions not confirmed | Click the confirmation link; check spam |
| Flow 2 email missing, rule shows invocations | SNS topic policy doesn't allow `events.amazonaws.com` | Apply `config/iam/sns-topic-policy-flow2.json` |
| Rule matches but SSM never starts (`FailedInvocations` metric) | Target role lacks `ssm:StartAutomationExecution` or `iam:PassRole` | Apply `eventbridge-invoke-ssm-role-policy.json`; target ARN must end in `:$DEFAULT` |
| SSM execution fails on parameters | Input not shaped as lists of strings | Template must be `{"UserName": [<userName>]}` — this was the target-input fix made during the lab |
| SSM step `AccessDenied` on `PutUserPermissionsBoundary` | Boundary ARN differs from the role's condition | Make the runbook default and the role condition use the same ARN |
| Second attempt still succeeds | Not enough wait (delivery + execution + IAM propagation) | Wait longer (2–5 min) and check the SSM execution status first |
| Automation runs again after the denial | Pattern doesn't exclude failed calls | Keep `"errorCode": [{"exists": false}]` in the pattern |
| Second attempt fails with `InvalidClientTokenId` instead of `AccessDenied` | Kill-switch rule is also enabled and disabled the key | Disable the KillSwitch rule; run `scripts/reset-victim.sh` |
