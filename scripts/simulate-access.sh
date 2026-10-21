#!/usr/bin/env bash
# Controlled honeytoken test, as the Victim identity.
#   1st call  -> should SUCCEED (and trigger Flow 1, Flow 2 and the active-defense rule)
#   wait      -> CloudTrail -> EventBridge -> SSM Automation -> boundary attached
#   2nd call  -> should FAIL with AccessDeniedException (explicit deny in boundary)
set -uo pipefail
REGION="${AWS_REGION:-af-south-1}"
PROFILE="${VICTIM_PROFILE:-sologuard-victim}"
WAIT="${WAIT_SECONDS:-180}"

call() {
  aws secretsmanager get-secret-value \
    --secret-id Production_Database_Credentials \
    --profile "$PROFILE" --region "$REGION" \
    --query 'Name' --output text
}

echo "[$(date -u +%FT%TZ)] Attempt 1 (expect success):"
call && echo "   -> secret was readable (this is the detection trigger)"

echo "[$(date -u +%FT%TZ)] Waiting ${WAIT}s for CloudTrail delivery, EventBridge and SSM Automation..."
sleep "$WAIT"

echo "[$(date -u +%FT%TZ)] Attempt 2 (expect AccessDeniedException):"
if call; then
  echo "   !! still allowed — check the rule state, the SSM execution and the boundary (see docs/troubleshooting.md)"
  exit 1
fi
echo "   -> denied as expected"
