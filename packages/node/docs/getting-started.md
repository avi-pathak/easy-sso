# Getting started with `@easy-sso/node`

This guide takes you from an empty project to protected routes with a typed,
normalized `req.user` — using Microsoft Entra ID or Google as the identity
provider. No provider lock-in: your route code depends only on the
`AuthProvider` / `AuthUser` seam.

- [1. Install](#1-install)
- [2. Choose a provider](#2-choose-a-provider)
- [3. Add the middleware](#3-add-the-middleware)
- [4. Protect routes](#4-protect-routes)
- [5. Handle auth errors](#5-handle-auth-errors)
- [6. Read the user](#6-read-the-user)
- [7. Without Express](#7-without-express)
- [Troubleshooting](#troubleshooting)
- [Next steps](#next-steps)

## 1. Install

```bash
npm install @easy-sso/node
# express is an optional peer dependency — install it if you use the middleware
npm install express
```

Requires **Node 18+**. The package ships dual ESM + CJS builds with `.d.ts`
types, so `import` and `require` both work.

## 2. Choose a provider

Two providers ship built in. Pick the one that issues the tokens your API
receives:

| Provider | Factory | Validates | Expected `aud` |
| --- | --- | --- | --- |
| Microsoft Entra ID | `microsoftAuth` | Entra access tokens | client ID / `api://<client-id>` |
| Google | `googleAuth` | Google OIDC **ID tokens** | your OAuth client ID |

You need, at minimum:

- **Microsoft** — an [Entra app registration](https://entra.microsoft.com)
  (*App registrations → New registration*) and its **Application (client) ID**.
- **Google** — an OAuth 2.0 **client ID** from the
  [Google Cloud console](https://console.cloud.google.com/apis/credentials).

## 3. Add the middleware

The auth middleware validates a bearer token **if one is present** and attaches
a typed `req.user`. A request with no token continues as anonymous, so public
routes keep working; a request with an *invalid* token is always rejected.

```ts
import express from "express";
import { microsoftAuth } from "@easy-sso/node";

const app = express();

app.use(
  microsoftAuth({
    clientId: process.env.CLIENT_ID!,
    tenantId: "common", // common | organizations | consumers | <tenant-guid>
  }),
);
```

Google is a drop-in swap — only this block changes, never your routes:

```ts
import { googleAuth } from "@easy-sso/node";

app.use(
  googleAuth({
    clientId: process.env.GOOGLE_CLIENT_ID!,
    hostedDomains: ["yourcompany.com"], // optional: restrict to a Workspace domain
  }),
);
```

## 4. Protect routes

- `requireAuth()` → **401** unless a valid user is attached.
- `requireRole(role)` → **403** unless the user has that role.
- `requireRoles(roles, { mode })` → `"any"` (default) or `"all"`.

```ts
import { requireAuth, requireRole } from "@easy-sso/node";

app.get("/me", requireAuth(), (req, res) => res.json(req.user));

app.get("/admin", requireAuth(), requireRole("Admin"), (req, res) =>
  res.json({ ok: true }),
);
```

> Google ID tokens carry no application roles, so `roles` defaults to empty.
> Map roles from your own store, or use Microsoft app roles for `requireRole`.

## 5. Handle auth errors

Every failure is a typed `AuthError` with a `statusCode` and a structured
`toJSON()` body. Register one error handler after your routes:

```ts
import { AuthError } from "@easy-sso/node";

app.use((err, _req, res, next) => {
  if (AuthError.isAuthError(err)) {
    return res.status(err.statusCode).json(err.toJSON());
  }
  next(err);
});
```

Or use the shipped `defaultErrorHandler`, which also sets `WWW-Authenticate`.

## 6. Read the user

`req.user` is a normalized `AuthUser` — the same shape regardless of provider:

```ts
interface AuthUser {
  readonly id: string;            // stable subject
  readonly email?: string;
  readonly name?: string;
  readonly roles: readonly string[];
  readonly scopes: readonly string[];
  readonly tenantId?: string;
  readonly provider: string;      // "microsoft" | "google"
  readonly claims: Readonly<RawClaims>; // raw token claims, if you need them
}
```

## 7. Without Express

The core is framework-agnostic. Use a provider directly to validate a token and
get back an `AuthUser`:

```ts
import { MicrosoftProvider } from "@easy-sso/node";

const provider = new MicrosoftProvider({ clientId: process.env.CLIENT_ID! });
const user = await provider.authenticate(bearerToken); // throws AuthError on failure
```

See [`examples/fastify`](../../../examples/fastify) for the core used outside
Express.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `ConfigurationError` at startup | Missing/invalid `clientId` or config — the message names the field. |
| `401 InvalidAudienceError` | Token's `aud` isn't your client ID. Pass `audience` to widen it. |
| `401 InvalidIssuerError` | Wrong `tenantId`, or a Google token hitting the Microsoft provider (or vice-versa). |
| `401 TokenExpiredError` | Token past `exp`. Bump `clockToleranceSec` only for genuine clock skew. |
| Every request is anonymous | No `Authorization: Bearer <token>` header reaching the middleware. |

## Next steps

- Full API reference and config tables: [`../README.md`](../README.md).
- Add Okta / Auth0 / Keycloak: [adding-a-provider.md](./adding-a-provider.md).
- Multi-tenant setup: [`examples/multi-tenant`](../../../examples/multi-tenant).
