#!/bin/sh
# Container entrypoint.
#
# GCP Secret Manager integration point: if running on a GCP VM with an
# appropriate service account, replace this stub with gcloud/curl calls
# to populate env vars before exec. Example VM startup script approach:
#
#   for secret in stealthops-auth-user stealthops-auth-pass \
#     virustotal-api-key shodan-api-key ...; do
#     val=$(gcloud secrets versions access latest --secret="$secret" \
#           --project="$GCLOUD_PROJECT" 2>/dev/null)
#     [ -n "$val" ] && echo "$(echo $secret | tr '-' '_' | tr '[:lower:]' '[:upper:]')=$val"
#   done > /etc/stealthops.env
#
# Then docker-compose.yml uses: env_file: /etc/stealthops.env
set -e
exec "$@"
