# Multi-tenant example — `@easy-sso/node`

A SaaS-style API that accepts work/school accounts from **any** tenant
(`tenantId: "organizations"`) but restricts access to an explicit allow-list of
onboarded customer tenants, and demonstrates **custom claim mapping**.

## Run

```bash
# from the repo root
npm install
npm run build --workspace=@easy-sso/node

CLIENT_ID=<your-app-id> \
ALLOWED_TENANTS=11111111-1111-1111-1111-111111111111,22222222-2222-2222-2222-222222222222 \
  npm run start --workspace=@easy-sso/example-multi-tenant
```

Leave `ALLOWED_TENANTS` unset to accept every organizational tenant.

## What it shows

- **Tenant allow-listing** — tokens from tenants outside `ALLOWED_TENANTS` are
  rejected with `401 invalid_issuer`, even though they're valid Entra tokens.
- **Per-tenant partitioning** — `req.user.tenantId` is the cryptographically
  validated `tid`, safe to use as a data partition key.
- **Custom claim mapping** — `groups` are mapped onto `roles`, and the email is
  resolved from a prioritized claim list.

## Routes

| Route            | Result                                              |
| ---------------- | --------------------------------------------------- |
| `/health`        | public; echoes the configured allow-list            |
| `/whoami`        | the validated id, tenant, and roles                 |
| `/tenant/notes`  | data scoped to the caller's validated tenant        |
