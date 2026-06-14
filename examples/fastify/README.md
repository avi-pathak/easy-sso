# Fastify example — `@easy-sso/node`

Shows the **provider-agnostic core** working outside Express. There is no Express
adapter here — the Fastify hook calls the `AuthProvider` interface directly and
reuses the same normalized `AuthUser`, errors, and bearer parsing.

## Run

```bash
# from the repo root
npm install
npm run build --workspace=@easy-sso/node

CLIENT_ID=<your-app-id> TENANT_ID=common \
  npm run start --workspace=@easy-sso/example-fastify
```

> Requires Node 18+ (examples run via `tsx`).

## Routes

| Route      | Protection                  | Result                         |
| ---------- | --------------------------- | ------------------------------ |
| `/health`  | none                        | always `200`                   |
| `/profile` | `requireAuth`               | `401` without a valid token    |
| `/admin`   | `requireRole("Admin")`      | `403` without the `Admin` role |
