# Login with Microsoft / Google — full-stack demo

A minimal server-side web app that signs a user in with **Microsoft Entra ID
and/or Google** and **validates the returned ID token with `@easy-sso/node`**. No
frontend build, no SPA — just `express`, the OIDC authorization-code flow, and our
package doing the token validation.

Each provider is **optional**: it's enabled when its client id + secret are set in
`.env`, and the home page shows a button per enabled provider. Configure one or
both.

```
Browser ──/auth/<p>/login──▶ provider sign-in        (p = microsoft | google)
        ◀──code──────────── /auth/<p>/callback
                             │  exchange code → id_token
                             │  provider.authenticate(id_token)   ← @easy-sso/node
                             ▼  session cookie → profile page
```

> Routes: Microsoft uses `/auth/login` + `/auth/callback` (unchanged, so your
> existing Entra redirect URI keeps working); Google uses `/auth/google/login` +
> `/auth/google/callback`.

## One-time Google setup

1. **Google Cloud Console** → *APIs & Services* → *Credentials* → *Create
   credentials* → **OAuth client ID** → type **Web application**.
2. Under **Authorized redirect URIs**, add:

   ```
   http://localhost:7070/auth/google/callback
   ```

3. Copy the **Client ID** and **Client secret** into `.env` as `GOOGLE_CLIENT_ID`
   / `GOOGLE_CLIENT_SECRET`.

## One-time Entra setup (your `New_Test_Easy_SSO` app)

1. **Add the redirect URI.** Portal → your app → **Manage → Authentication** →
   *Add a platform* (or edit the **Web** platform) → add:

   ```
   http://localhost:7070/auth/callback
   ```

   (`http://localhost` is allowed for the Web platform. Keep your existing
   `https://localhost:7070` too if you like — this demo just needs the callback URL.)

2. **Create a client secret.** Portal → **Manage → Certificates & secrets** →
   *New client secret* → copy the **Value** (shown once).

## Run

```bash
# from the repo root
npm install
npm run build --workspace=@easy-sso/node

cp examples/login-webapp/.env.example examples/login-webapp/.env
#   then fill in the providers you want: Microsoft (CLIENT_ID + CLIENT_SECRET)
#   and/or Google (GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET)

npm run start --workspace=@easy-sso/example-login-webapp
```

Open <http://localhost:7070>, click **Login with Microsoft** or **Login with
Google**, sign in, and you'll land on a profile page rendered from the validated
token claims (the `provider` field shows which one authenticated you).

## What each piece proves

- `provider.authenticate(id_token)` is the package validating signature, issuer
  (resolved from the real `tid`), audience (`= CLIENT_ID`), `exp`/`nbf`, and the
  `organizations` tenant policy — against Microsoft's live JWKS, cached with
  single-flight dedup.
- `GET /api/me` shows the same validated `AuthUser` as JSON.
- `nonce` from the ID token is checked against the login request (replay defense).

## Browser-free verification (curl)

You can prove the package validates a **real** Microsoft token without any
interactive sign-in, using the client-credentials grant:

```bash
# with CLIENT_ID, CLIENT_SECRET, TENANT_GUID set in .env
npm run curl-test --workspace=@easy-sso/example-login-webapp
```

This fetches an app-only token from `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`
(`scope=<client-id>/.default`) and runs it through `@easy-sso/node`, which fetches
Microsoft's live JWKS, verifies the RS256 signature, issuer, audience, `exp`/`nbf`,
and tenant. Verified output looks like:

```
✅ VALID — verified by @easy-sso/node against live Microsoft JWKS
{ "id": "…", "tenantId": "a272645c-…", "provider": "microsoft", "claims": { … } }
```

Validate an arbitrary token directly:

```bash
VALIDATE_TENANT=<tenant-guid> npm run validate --workspace=@easy-sso/example-login-webapp -- "<token>"
```

> Note: this is **app-to-app** auth (no user). The interactive **Login with
> Microsoft** flow above is what authenticates an actual person — and that step
> genuinely requires a browser; it can't be driven by curl.

## Notes

- `.env` holds a secret — it is gitignored; never commit it.
- Set `TENANT` to your tenant GUID (`a272645c-…`) to restrict logins to only your
  tenant instead of any organization.
- This is a confidential-client (secret) flow. For a browser-only SPA you'd use
  MSAL.js + PKCE and send the token to a `microsoftAuth()`-protected API instead
  (see `examples/express`).
