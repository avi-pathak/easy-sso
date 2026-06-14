#!/usr/bin/env bash
#
# Browser-free end-to-end test: fetch a real Microsoft token via the
# client-credentials grant and validate it with @easy-sso/node.
#
# Usage:  ./curl-test.sh        (reads CLIENT_ID / CLIENT_SECRET / TENANT_GUID from .env)
#
set -euo pipefail
cd "$(dirname "$0")"

# Load .env
set -a; . ./.env; set +a
: "${CLIENT_ID:?set CLIENT_ID in .env}"
: "${CLIENT_SECRET:?set CLIENT_SECRET in .env}"
: "${TENANT_GUID:?set TENANT_GUID in .env}"

echo "▶ Requesting an app-only token from Microsoft (no browser)…"
TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/${TENANT_GUID}/oauth2/v2.0/token" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "client_secret=${CLIENT_SECRET}" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "scope=${CLIENT_ID}/.default" \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);if(j.error){console.error(j.error_description);process.exit(1);}process.stdout.write(j.access_token);})')

echo "▶ Validating the token with @easy-sso/node (live JWKS)…"
echo
# v1.0 app-only tokens carry a tenant-specific issuer → validate against the GUID.
VALIDATE_TENANT="${TENANT_GUID}" npx tsx src/validate-cli.ts "$TOKEN"
