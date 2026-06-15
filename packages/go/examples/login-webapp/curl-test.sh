#!/usr/bin/env bash
#
# Browser-free end-to-end test: fetch a real Microsoft token via the
# client-credentials grant and validate it with the easy-sso Go package.
#
# Usage:  ./curl-test.sh        (reads CLIENT_ID / CLIENT_SECRET / TENANT_GUID from .env)
#
set -euo pipefail
cd "$(dirname "$0")"

# Load .env (fall back to the Node demo's .env so one configured file serves both)
ENV_FILE="./.env"
[ -f "$ENV_FILE" ] || ENV_FILE="../../../../examples/login-webapp/.env"
set -a; . "$ENV_FILE"; set +a
: "${CLIENT_ID:?set CLIENT_ID in .env}"
: "${CLIENT_SECRET:?set CLIENT_SECRET in .env}"
: "${TENANT_GUID:?set TENANT_GUID in .env}"

echo "▶ Requesting an app-only token from Microsoft (no browser)…"
RESPONSE=$(curl -s -X POST "https://login.microsoftonline.com/${TENANT_GUID}/oauth2/v2.0/token" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "client_secret=${CLIENT_SECRET}" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "scope=${CLIENT_ID}/.default")

# Extract access_token from the compact JSON response (no jq dependency).
TOKEN=$(printf '%s' "$RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
if [ -z "$TOKEN" ]; then
  echo "❌ Failed to obtain a token:" >&2
  printf '%s\n' "$RESPONSE" | sed -n 's/.*"error_description":"\([^"]*\)".*/\1/p' >&2
  exit 1
fi

echo "▶ Validating the token with easy-sso (Go) against live JWKS…"
echo
# v1.0 app-only tokens carry a tenant-specific issuer → validate against the GUID.
VALIDATE_TENANT="${TENANT_GUID}" go run ./validate "$TOKEN"
