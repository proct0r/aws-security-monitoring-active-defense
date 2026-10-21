# From lab to production

The lab proves the loop in one account, one Region, one secret and one user. A production deployment — for example in a bank — needs the following.

## Visibility

- **Organization trail** in AWS Organizations, delivered to a dedicated **log-archive account**; S3 **Object Lock** and SSE-KMS on the bucket; log-file validation on.
- **Delegated security account** owning EventBridge rules, runbooks and alerting, with cross-account event buses.
- **Amazon GuardDuty** (anomalous credential use, known-bad IPs), **AWS Security Hub** (aggregation, CIS / AWS FSBP controls), **IAM Access Analyzer** (external and unused access).
- Cover **all** secrets and other credential stores (SSM Parameter Store `GetParameter` with decryption, KMS `Decrypt`), not just one honeytoken. Keep honeytokens as a high-signal tripwire alongside them.

## Containment that actually contains

- **Roles and existing sessions.** Most production access is via roles and temporary credentials. A boundary or key deactivation does not revoke STS sessions already issued; add an inline deny conditioned on `aws:TokenIssueTime` (what the IAM console's *Revoke active sessions* does).
- **Multiple paths.** Consider also: deactivating all keys, removing console login profile, and an SCP or resource policy deny on the secret itself.
- **Guardrails on automation.** Allow-list of principals never auto-quarantined (break-glass, automation roles), rate limiting, and a human approval step (`aws:approve` in SSM) for high-impact actions.
- **Failure handling.** EventBridge target dead-letter queue and retry policy; alarm on `FailedInvocations` and on SSM execution failures.

## Response operations

- Send alerts to a SIEM / SOAR and a ticketing or paging tool rather than raw email; attach severity, owner and runbook link.
- Enrich alerts (principal owner, recent activity, geo-IP) — a Lambda step fits here.
- Document reversal, post-incident review, and periodic **purple-team tests** of the pipeline.

## Governance

- Everything as code (CloudFormation / Terraform / CDK) with peer review.
- Map detections and responses to a framework (NIST CSF 2.0, NIST SP 800-53 AU/IR/SI families, CIS AWS Foundations).
- Measure: mean time to detect, mean time to contain, false-positive rate.
