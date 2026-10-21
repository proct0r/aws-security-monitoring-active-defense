#!/usr/bin/env bash
# Remove every lab resource. Buckets are emptied first; this is irreversible.
set -uo pipefail
REGION="${AWS_REGION:-af-south-1}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
aws() { command aws --region "$REGION" "$@"; }
read -r -p "Delete ALL SoloGaurd resources in account ${ACCOUNT_ID}? Type 'yes': " ok; [ "$ok" = yes ] || exit 1

for r in SoloGaurd-SensitiveSecretAccess-EventBridge SoloGaurd-SensitiveAccess-Quarantine SoloGaurd-SensitiveAccess-KillSwitch; do
  ids=$(aws events list-targets-by-rule --rule "$r" --query 'Targets[].Id' --output text 2>/dev/null)
  [ -n "$ids" ] && aws events remove-targets --rule "$r" --ids $ids
  aws events delete-rule --name "$r"
done
aws ssm delete-document --name SoloGaurd-QuarantineVictim
aws ssm delete-document --name SoloGaurd-DisableVictimAccessKey
aws cloudwatch delete-alarms --alarm-names SoloGaurd-SensitiveSecretAccess-Alarm
aws logs delete-metric-filter --log-group-name aws-cloudtrail-logs-sologaurd --filter-name SoloGaurd-SensitiveSecretAccess-Filter
for t in Flow1 Flow2; do aws sns delete-topic --topic-arn "arn:aws:sns:${REGION}:${ACCOUNT_ID}:SoloGaurd-SecurityAlert-${t}"; done
aws cloudtrail delete-trail --name SoloGaurd-Trail
aws logs delete-log-group --log-group-name aws-cloudtrail-logs-sologaurd

aws iam delete-user-permissions-boundary --user-name Victim 2>/dev/null
for k in $(aws iam list-access-keys --user-name Victim --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
  aws iam delete-access-key --user-name Victim --access-key-id "$k"; done
aws iam delete-user-policy --user-name Victim --policy-name ReadHoneytokenOnly
aws iam delete-user --user-name Victim
aws iam delete-policy --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/SoloGaurd-QuarantineBoundary"
for pair in SoloGaurd-SSMAutomationRole:QuarantineVictim SoloGaurd-EventBridgeInvokeSSMRole:StartSoloGaurdRunbooks SoloGaurd-CloudTrailToCWLRole:CloudTrailToCWL; do
  aws iam delete-role-policy --role-name "${pair%%:*}" --policy-name "${pair##*:}"; aws iam delete-role --role-name "${pair%%:*}"; done

aws secretsmanager delete-secret --secret-id Production_Database_Credentials --force-delete-without-recovery
for b in "sologaurd-cloudtrail-${ACCOUNT_ID}" "sologaurd-s3-access-logs-${ACCOUNT_ID}"; do
  aws s3 rm "s3://$b" --recursive && aws s3api delete-bucket --bucket "$b"; done
echo "Teardown complete."
