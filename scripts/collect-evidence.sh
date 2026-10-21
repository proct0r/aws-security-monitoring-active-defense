#!/usr/bin/env bash
# Pull the forensic evidence used in the report into ./evidence/ (gitignored).
set -euo pipefail
REGION="${AWS_REGION:-af-south-1}"
OUT="${1:-evidence}"; mkdir -p "$OUT"
aws() { command aws --region "$REGION" "$@"; }

echo "==> CloudTrail: every GetSecretValue by Victim (last 24h)"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time "$(date -u -d '-24 hours' +%FT%TZ)" \
  --query 'Events[].CloudTrailEvent' --output json \
| jq '[.[] | fromjson | select(.userIdentity.userName=="Victim") | {
      eventTime, userName: .userIdentity.userName, eventName,
      secretId: .requestParameters.secretId, errorCode, errorMessage,
      sourceIPAddress: "[REDACTED]", readOnly }] | sort_by(.eventTime)' \
| tee "$OUT/cloudtrail-getsecretvalue.json"

echo "==> IAM: Victim boundary + key state"
aws iam get-user --user-name Victim --query 'User.PermissionsBoundary' | tee "$OUT/victim-boundary.json"
aws iam list-access-keys --user-name Victim --query 'AccessKeyMetadata[].{Status:Status,Created:CreateDate}' \
  | tee "$OUT/victim-keys.json"

echo "==> SSM: recent automation executions"
aws ssm describe-automation-executions \
  --filters Key=DocumentNamePrefix,Values=SoloGaurd- \
  --query 'AutomationExecutionMetadataList[].{Doc:DocumentName,Status:AutomationExecutionStatus,Start:ExecutionStartTime,End:ExecutionEndTime}' \
  | tee "$OUT/ssm-executions.json"

echo "==> CloudWatch: alarm history"
aws cloudwatch describe-alarm-history --alarm-name SoloGaurd-SensitiveSecretAccess-Alarm \
  --history-item-type StateUpdate --max-records 10 \
  --query 'AlarmHistoryItems[].{Time:Timestamp,Summary:HistorySummary}' | tee "$OUT/alarm-history.json"

echo "Saved to $OUT/ — review and redact before sharing."
