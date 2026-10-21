#!/usr/bin/env bash
# Return the Victim user to its pre-incident state so the test can be re-run.
set -euo pipefail
aws iam delete-user-permissions-boundary --user-name Victim 2>/dev/null && echo "boundary removed" || echo "no boundary attached"
for k in $(aws iam list-access-keys --user-name Victim --query 'AccessKeyMetadata[?Status==`Inactive`].AccessKeyId' --output text); do
  aws iam update-access-key --user-name Victim --access-key-id "$k" --status Active && echo "re-activated key ${k:0:4}****"
done
echo "Victim reset. Wait ~10s for IAM propagation before testing again."
