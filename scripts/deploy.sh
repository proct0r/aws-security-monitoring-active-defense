#!/usr/bin/env bash
# SoloGaurd — rebuild the whole lab with the AWS CLI (run from AWS CloudShell
# or any shell with admin credentials for a *sandbox* account).
#
#   ALERT_EMAIL=you@example.com ./scripts/deploy.sh
#
# Every resource name matches the one used in the report, including the
# original "SoloGaurd" spelling, so the screenshots and the code line up.
set -euo pipefail

REGION="${AWS_REGION:-af-south-1}"
ALERT_EMAIL="${ALERT_EMAIL:?set ALERT_EMAIL to the address that should receive alerts}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Fill the <ACCOUNT_ID> placeholder in a config file and print the temp path.
render() { sed "s/<ACCOUNT_ID>/${ACCOUNT_ID}/g" "$HERE/$1" > "$TMP/$(basename "$1")"; echo "$TMP/$(basename "$1")"; }
aws() { command aws --region "$REGION" "$@"; }

TRAIL_BUCKET="sologaurd-cloudtrail-${ACCOUNT_ID}"
ACCESSLOG_BUCKET="sologaurd-s3-access-logs-${ACCOUNT_ID}"
LOG_GROUP="aws-cloudtrail-logs-sologaurd"

echo "==> 1. Honeytoken secret"
aws secretsmanager create-secret \
  --name Production_Database_Credentials \
  --description "Controlled security monitoring honeytoken for SoloGaurd Cloud Security Semester Project" \
  --secret-string '{"username":"db_admin_DECOY","password":"this-is-a-honeytoken-not-a-real-credential"}' \
  >/dev/null || echo "   (secret already exists)"

echo "==> 2. S3 buckets for the CloudTrail archive and its access logs"
for b in "$ACCESSLOG_BUCKET" "$TRAIL_BUCKET"; do
  aws s3api create-bucket --bucket "$b" \
    --create-bucket-configuration LocationConstraint="$REGION" >/dev/null 2>&1 || true
  aws s3api put-public-access-block --bucket "$b" --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
done
cat > "$TMP/accesslog-policy.json" <<EOF
{"Version":"2012-10-17","Statement":[{"Sid":"S3ServerAccessLogs","Effect":"Allow",
 "Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject",
 "Resource":"arn:aws:s3:::${ACCESSLOG_BUCKET}/*",
 "Condition":{"StringEquals":{"aws:SourceAccount":"${ACCOUNT_ID}"}}}]}
EOF
aws s3api put-bucket-policy --bucket "$ACCESSLOG_BUCKET" --policy "file://$TMP/accesslog-policy.json"
aws s3api put-bucket-logging --bucket "$TRAIL_BUCKET" --bucket-logging-status \
  "{\"LoggingEnabled\":{\"TargetBucket\":\"${ACCESSLOG_BUCKET}\",\"TargetPrefix\":\"cloudtrail-bucket/\"}}"
cat > "$TMP/trail-bucket-policy.json" <<EOF
{"Version":"2012-10-17","Statement":[
 {"Sid":"AWSCloudTrailAclCheck","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},
  "Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::${TRAIL_BUCKET}",
  "Condition":{"StringEquals":{"aws:SourceArn":"arn:aws:cloudtrail:${REGION}:${ACCOUNT_ID}:trail/SoloGaurd-Trail"}}},
 {"Sid":"AWSCloudTrailWrite","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},
  "Action":"s3:PutObject","Resource":"arn:aws:s3:::${TRAIL_BUCKET}/AWSLogs/${ACCOUNT_ID}/*",
  "Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control",
   "aws:SourceArn":"arn:aws:cloudtrail:${REGION}:${ACCOUNT_ID}:trail/SoloGaurd-Trail"}}}]}
EOF
aws s3api put-bucket-policy --bucket "$TRAIL_BUCKET" --policy "file://$TMP/trail-bucket-policy.json"

echo "==> 3. CloudWatch Logs group + delivery role for CloudTrail"
aws logs create-log-group --log-group-name "$LOG_GROUP" 2>/dev/null || true
aws logs put-retention-policy --log-group-name "$LOG_GROUP" --retention-in-days 90
cat > "$TMP/ct-trust.json" <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"sts:AssumeRole"}]}
EOF
cat > "$TMP/ct-cwl.json" <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:CreateLogStream","logs:PutLogEvents"],
 "Resource":"arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP}:log-stream:*"}]}
EOF
aws iam create-role --role-name SoloGaurd-CloudTrailToCWLRole \
  --assume-role-policy-document "file://$TMP/ct-trust.json" >/dev/null 2>&1 || true
aws iam put-role-policy --role-name SoloGaurd-CloudTrailToCWLRole \
  --policy-name CloudTrailToCWL --policy-document "file://$TMP/ct-cwl.json"
sleep 10   # IAM propagation

echo "==> 4. Multi-Region CloudTrail trail (management events, read + write)"
aws cloudtrail create-trail --cli-input-json "file://$(render config/cloudtrail/trail.json)" >/dev/null 2>&1 \
  || aws cloudtrail update-trail --cli-input-json "file://$(render config/cloudtrail/trail.json)" >/dev/null
aws cloudtrail put-event-selectors --trail-name SoloGaurd-Trail \
  --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true}]' >/dev/null
aws cloudtrail start-logging --name SoloGaurd-Trail

echo "==> 5. SNS topics (Flow 1 and Flow 2) + email subscriptions"
T1=$(aws sns create-topic --name SoloGaurd-SecurityAlert-Flow1 --query TopicArn --output text)
T2=$(aws sns create-topic --name SoloGaurd-SecurityAlert-Flow2 --query TopicArn --output text)
aws sns set-topic-attributes --topic-arn "$T2" --attribute-name Policy \
  --attribute-value "file://$(render config/iam/sns-topic-policy-flow2.json)"
aws sns subscribe --topic-arn "$T1" --protocol email --notification-endpoint "$ALERT_EMAIL" >/dev/null
aws sns subscribe --topic-arn "$T2" --protocol email --notification-endpoint "$ALERT_EMAIL" >/dev/null
echo "   -> confirm BOTH subscription emails sent to $ALERT_EMAIL"

echo "==> 6. Flow 1: metric filter + 1-minute alarm"
aws logs put-metric-filter --cli-input-json "file://$(render config/cloudwatch/metric-filter.json)"
aws cloudwatch put-metric-alarm --cli-input-json "file://$(render config/cloudwatch/alarm.json)"

echo "==> 7. Flow 2: EventBridge rule (must receive READ-ONLY management events)"
aws events put-rule --name SoloGaurd-SensitiveSecretAccess-EventBridge \
  --event-pattern "file://$HERE/config/eventbridge/flow2-alert-pattern.json" \
  --state ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS >/dev/null
aws events put-targets --rule SoloGaurd-SensitiveSecretAccess-EventBridge \
  --targets "Id=flow2-sns,Arn=${T2}" >/dev/null

echo "==> 8. Victim user (controlled test identity)"
aws iam create-user --user-name Victim >/dev/null 2>&1 || true
aws iam put-user-policy --user-name Victim --policy-name ReadHoneytokenOnly \
  --policy-document "file://$(render config/iam/victim-identity-policy.json)"
aws iam create-policy --policy-name SoloGaurd-QuarantineBoundary \
  --description "Deny-all emergency quarantine boundary" \
  --policy-document "file://$HERE/config/iam/quarantine-boundary-policy.json" >/dev/null 2>&1 || true
echo "   -> create an access key for Victim yourself and store it as CLI profile 'sologuard-victim':"
echo "      aws iam create-access-key --user-name Victim   &&   aws configure --profile sologuard-victim"

echo "==> 9. Response roles (least privilege)"
aws iam create-role --role-name SoloGaurd-SSMAutomationRole \
  --assume-role-policy-document "file://$(render config/iam/ssm-automation-role-trust.json)" >/dev/null 2>&1 || true
aws iam put-role-policy --role-name SoloGaurd-SSMAutomationRole --policy-name QuarantineVictim \
  --policy-document "file://$(render config/iam/ssm-automation-role-policy.json)"
cat > "$TMP/events-trust.json" <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole",
 "Condition":{"StringEquals":{"aws:SourceAccount":"${ACCOUNT_ID}"}}}]}
EOF
aws iam create-role --role-name SoloGaurd-EventBridgeInvokeSSMRole \
  --assume-role-policy-document "file://$TMP/events-trust.json" >/dev/null 2>&1 || true
aws iam put-role-policy --role-name SoloGaurd-EventBridgeInvokeSSMRole --policy-name StartSoloGaurdRunbooks \
  --policy-document "file://$(render config/iam/eventbridge-invoke-ssm-role-policy.json)"
sleep 10

echo "==> 10. SSM Automation runbooks"
for doc in SoloGaurd-QuarantineVictim SoloGaurd-DisableVictimAccessKey; do
  aws ssm create-document --name "$doc" --document-type Automation --document-format YAML \
    --content "file://$(render config/ssm/$doc.yaml)" >/dev/null 2>&1 \
  || aws ssm update-document --name "$doc" --document-version '$LATEST' --document-format YAML \
       --content "file://$(render config/ssm/$doc.yaml)" >/dev/null 2>&1 || true
done

echo "==> 11. Active-defense rules (Quarantine ENABLED, KillSwitch DISABLED — run one at a time)"
EB_ROLE="arn:aws:iam::${ACCOUNT_ID}:role/SoloGaurd-EventBridgeInvokeSSMRole"
SSM_ARN="arn:aws:ssm:${REGION}:${ACCOUNT_ID}:automation-definition"
aws events put-rule --name SoloGaurd-SensitiveAccess-Quarantine \
  --description "Applies quarantine permissions boundary to Victim after sensitive secret access" \
  --event-pattern "file://$HERE/config/eventbridge/active-defense-pattern.json" \
  --state ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS >/dev/null
aws events put-targets --rule SoloGaurd-SensitiveAccess-Quarantine --targets "[{
  \"Id\":\"quarantine\",\"Arn\":\"${SSM_ARN}/SoloGaurd-QuarantineVictim:\$DEFAULT\",\"RoleArn\":\"${EB_ROLE}\",
  \"InputTransformer\":$(cat "$HERE/config/eventbridge/quarantine-target-input-transformer.json")}]" >/dev/null
aws events put-rule --name SoloGaurd-SensitiveAccess-KillSwitch \
  --description "Automatically disables the Victim IAM access key after sensitive secret access" \
  --event-pattern "file://$HERE/config/eventbridge/active-defense-pattern.json" \
  --state DISABLED >/dev/null
aws events put-targets --rule SoloGaurd-SensitiveAccess-KillSwitch --targets "[{
  \"Id\":\"killswitch\",\"Arn\":\"${SSM_ARN}/SoloGaurd-DisableVictimAccessKey:\$DEFAULT\",\"RoleArn\":\"${EB_ROLE}\",
  \"InputTransformer\":$(cat "$HERE/config/eventbridge/killswitch-target-input-transformer.json")}]" >/dev/null

echo
echo "Done. Next: confirm the two SNS emails, create the Victim key, then run ./scripts/simulate-access.sh"
