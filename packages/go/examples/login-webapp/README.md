# Login with Microsoft — full-stack demo (Go)

A minimal server-side web app that signs a user in with Microsoft Entra ID and
**validates the returned ID token with the easy-sso Go package**. No frontend
build, no SPA — just `net/http`, the OIDC authorization-code flow, and
`microsoft.Provider` doing the token validation.

This is the Go twin of [`examples/login-webapp`](../../../../examples/login-webapp)
(Node). It reads the **same env var names**, so you can reuse the same `.env` and
the same app registration / redirect URI.

```
Browser ──/auth/login──▶ Microsoft sign-in
        ◀──code──────── /auth/callback
                         │  exchange code → id_token
                         │  provider.Authenticate(id_token)   ← easy-sso (Go)
                         ▼  session cookie → profile page
```

## One-time Entra setup

Same as the Node demo — if you already did it, you're done. Otherwise:

1. **Add the redirect URI** `http://localhost:7070/auth/callback` under
   Portal → your app → **Manage → Authentication** → *Web* platform.
2. **Create a client secret** under **Manage → Certificates & secrets** and copy
   the **Value**.

## Run

```bash
cd packages/go/examples/login-webapp

# Reuse the Node demo's .env automatically, or make a local one:
cp .env.example .env        # then paste CLIENT_SECRET / confirm CLIENT_ID

go run .
```

> If you already configured `examples/login-webapp/.env` (the Node demo), you can
> skip the copy — this app falls back to loading that file.

Open <http://localhost:7070>, click **Login with Microsoft**, sign in, and you'll
land on a profile page rendered from the validated token claims.

> The Node and Go demos both default to port **7070** and the same redirect URI,
> so run one at a time.

## What each piece proves

- `provider.Authenticate(ctx, id_token, nil)` is the package validating signature,
  issuer (resolved from the real `tid`), audience (`= CLIENT_ID`), `exp`/`nbf`,
  and the tenant policy — against Microsoft's live JWKS, cached with single-flight
  dedup.
- `GET /api/me` shows the same validated `AuthUser` as JSON.
- `nonce` from the ID token is checked against the login request (replay defense).

## Browser-free verification (curl)

Prove the package validates a **real** Microsoft token without any interactive
sign-in, using the client-credentials grant:

```bash
# with CLIENT_ID, CLIENT_SECRET, TENANT_GUID set in .env
./curl-test.sh
```

This fetches an app-only token from
`https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`
(`scope=<client-id>/.default`) and runs it through the Go package, which fetches
Microsoft's live JWKS, verifies the RS256 signature, issuer, audience, `exp`/`nbf`,
and tenant. Verified output looks like:

```
✅ VALID — verified by easy-sso (Go) against live Microsoft JWKS
{ "id": "…", "tenantId": "a272645c-…", "provider": "microsoft", "claims": { … } }
```

Validate an arbitrary token directly:

```bash
VALIDATE_TENANT=<tenant-guid> go run ./validate "<token>"
```

> Note: this is **app-to-app** auth (no user). The interactive **Login with
> Microsoft** flow above is what authenticates an actual person — and that step
> genuinely requires a browser; it can't be driven by curl.

## Notes

- `.env` holds a secret — it is gitignored; never commit it.
- Set `TENANT` to your tenant GUID to restrict logins to only your tenant.
- This is a confidential-client (secret) flow. For a browser-only SPA you'd use
  MSAL.js + PKCE and send the token to a provider-protected API instead
  (see [`examples/api`](../api)).
