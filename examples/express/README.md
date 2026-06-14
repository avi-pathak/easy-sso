# Express example — `@easy-sso/node`

A minimal Express API protected by Microsoft Entra ID.

## Run

```bash
# from the repo root
npm install
npm run build --workspace=@easy-sso/node

cp examples/express/.env.example examples/express/.env   # then edit values
CLIENT_ID=<your-app-id> TENANT_ID=common \
  npm run start --workspace=@easy-sso/example-express
```

> Requires Node 18+ (examples run via `tsx`).

## Routes

| Route      | Protection                       | Result                      |
| ---------- | -------------------------------- | --------------------------- |
| `/health`  | none                             | always `200`                |
| `/profile` | `requireAuth()`                  | `401` without a valid token |
| `/admin`   | `requireAuth()` + `requireRole`  | `403` without the `Admin` role |

## Try it

```bash
curl http://localhost:3000/health
curl -H "Authorization: Bearer <access-token>" http://localhost:3000/profile
```

Get an access token for your app from the Microsoft identity platform (e.g. via
the Azure CLI `az account get-access-token --resource api://<client-id>` or your
SPA's MSAL flow).
