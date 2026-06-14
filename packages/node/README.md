# @easy-sso/node

> Provider-agnostic SSO for Node.js. Microsoft Entra ID today; Google, Okta,
> Auth0, Keycloak tomorrow — with zero public-API changes.

[![CI](https://github.com/easy-sso/easy-sso/actions/workflows/ci.yml/badge.svg)](https://github.com/easy-sso/easy-sso/actions/workflows/ci.yml)

`@easy-sso/node` validates OAuth2 / OIDC bearer tokens and gives your routes a
typed, normalized user — without tying your codebase to any one identity
provider. The core knows only an `AuthProvider` interface; Microsoft Entra ID is
the first concrete implementation.

```ts
import { microsoftAuth, requireAuth, requireRole } from "@easy-sso/node";

app.use(microsoftAuth({ clientId: process.env.CLIENT_ID, tenantId: "common" }));

app.get("/profile", requireAuth(), (req, res) => res.json(req.user));
app.get("/admin", requireAuth(), requireRole("Admin"), (req, res) => res.json({ ok: true }));
```

## Why

- **Provider-agnostic by design.** Your app depends on `AuthProvider` /
  `AuthUser`, never on Microsoft. Swapping or adding a provider doesn't touch your
  route code.
- **Secure defaults, non-negotiable.** Signature validation is never
  disable-able. Issuer, audience, `exp`, and `nbf` are always checked. Only
  `RS256` is accepted (`alg: none` and HMAC-confusion are impossible).
- **Production-ready JWKS handling.** In-memory cache with TTL, background
  refresh, key-rotation retry, and **single-flight** dedup so a burst of requests
  triggers exactly one key fetch.
- **Strict TypeScript, zero `any`.** Fully typed public surface, `.d.ts` emitted,
  dual ESM + CJS builds.

## Install

```bash
npm install @easy-sso/node
# express is an optional peer dependency if you use the middleware
npm install express
```

## Quick start

```ts
import express from "express";
import { microsoftAuth, requireAuth, requireRole, AuthError } from "@easy-sso/node";

const app = express();

// Validates a bearer token if present and attaches a typed `req.user`.
app.use(microsoftAuth({ clientId: process.env.CLIENT_ID!, tenantId: "common" }));

app.get("/me", requireAuth(), (req, res) => res.json(req.user));
app.get("/admin", requireAuth(), requireRole("Admin"), (req, res) => res.json({ ok: true }));

// The framework's errors carry `statusCode` and a structured `toJSON()` body.
app.use((err, _req, res, next) => {
  if (AuthError.isAuthError(err)) return res.status(err.statusCode).json(err.toJSON());
  next(err);
});
```

A request with no token continues as anonymous (so public routes work);
`requireAuth()` enforces 401, `requireRole()` enforces 403. A request with an
*invalid* token is always rejected.

## Architecture

```
                        ┌───────────────────────────┐
   HTTP request ──────► │  middleware (Express-shaped) │
                        │  microsoftAuth / requireAuth │
                        └──────────────┬────────────┘
                                       │ depends only on
                                       ▼
                        ┌───────────────────────────┐
                        │   core: AuthProvider        │  ◄── provider-agnostic seam
                        │   AuthUser · AuthContext     │
                        └──────────────┬────────────┘
                                       │ implemented by
                 ┌─────────────────────┼─────────────────────┐
                 ▼                     ▼                     ▼
        MicrosoftProvider        (GoogleProvider)      (OktaProvider)
         ├─ token-validator       …same interface,      …
         ├─ jwks-client            zero API change
         └─ claims-mapper
                 │
                 ▼
        cache: MemoryKeyCache (TTL · single-flight · rotation)
```

- **`core/`** — `AuthProvider`, `AuthUser`, `AuthContext`, claim types. Imports
  nothing from `providers/`.
- **`providers/microsoft/`** — the only place that knows Entra issuer formats,
  JWKS endpoints, and claim names.
- **`middleware/`** — generic `createAuthMiddleware(provider)` plus the
  `microsoftAuth` convenience and the `requireAuth` / `requireRole` guards.
- **`cache/`** — value-generic JWKS cache.
- **`errors/`**, **`config/`**, **`utils/`** — typed errors, fail-fast config
  validation, bearer parsing.

## Microsoft / Entra setup

1. **Register an application** in the [Entra admin center](https://entra.microsoft.com)
   → *App registrations* → *New registration*. Note the **Application (client) ID**.
2. **Pick your tenant mode:**
   - `common` — any Microsoft account (work/school **and** personal).
   - `organizations` — any work/school tenant.
   - `consumers` — personal Microsoft accounts only.
   - `<tenant-guid>` — a single specific tenant.
3. **Expose an API / set the audience.** Access tokens for your API will carry
   `aud = <client-id>` or `api://<client-id>`. Both are accepted by default; pass
   `audience` to override.
4. **(Optional) App roles.** Define roles under *App roles*; assigned roles
   appear in the `roles` claim and drive `requireRole()`.

```ts
microsoftAuth({
  clientId: process.env.CLIENT_ID!,
  tenantId: "organizations",
  audience: [`api://${process.env.CLIENT_ID}`], // optional override
  allowedTenants: ["<tenant-guid-1>", "<tenant-guid-2>"], // optional allow-list
});
```

The issuer is resolved **dynamically** from the token's real `tid` and version —
correct for `common`/`organizations` where the issuer is not a fixed string —
then validated cryptographically.

## API reference

### Middleware

| Export | Signature | Description |
| --- | --- | --- |
| `microsoftAuth` | `(config, options?) => RequestHandler` | Entra provider + middleware in one. |
| `createAuthMiddleware` | `(provider, options?) => RequestHandler` | Generic middleware over any `AuthProvider`. |
| `requireAuth` | `(options?) => RequestHandler` | 401 unless `req.user` is set. |
| `requireRole` | `(role, options?) => RequestHandler` | 403 unless the user has `role`. |
| `requireRoles` | `(roles, options?) => RequestHandler` | `mode: "any"` (default) or `"all"`. |
| `defaultErrorHandler` | `AuthErrorHandler` | JSON + status + `WWW-Authenticate`. |

`AuthMiddlewareOptions`: `{ credentialsRequired?, tokenExtractor?, onError? }`.

### Config (`MicrosoftAuthConfig`)

| Field | Default | Notes |
| --- | --- | --- |
| `clientId` | — (required) | Application (client) ID. |
| `tenantId` | `"common"` | `common` / `organizations` / `consumers` / GUID. |
| `audience` | `[clientId, "api://"+clientId]` | string or string[]. |
| `allowedTenants` | `[]` | extra GUID allow-list. |
| `acceptedVersions` | `["1.0","2.0"]` | accepted token versions. |
| `clockToleranceSec` | `60` | skew tolerance for `exp`/`nbf`. |
| `claims` | Microsoft defaults | custom claim mapping (see below). |
| `jwks` | `{ ttlMs: 3600000 }` | `{ ttlMs?, refreshIntervalMs?, uri? }`. |
| `authorityHost` / `v1IssuerHost` | public cloud | override for sovereign clouds. |

Misconfiguration throws a descriptive `ConfigurationError` at startup.

### Custom claim mapping

```ts
microsoftAuth({
  clientId,
  claims: {
    email: ["email", "preferred_username", "upn"], // first present wins
    name: "name",
    roles: ["roles", "groups"], // arrays or space-delimited strings
  },
});
```

### `AuthUser`

```ts
interface AuthUser {
  readonly id: string;            // oid → sub
  readonly email?: string;
  readonly name?: string;
  readonly roles: readonly string[];
  readonly scopes: readonly string[];
  readonly tenantId?: string;     // tid
  readonly provider: string;      // "microsoft"
  readonly claims: Readonly<RawClaims>;
}
```

### Errors

`AuthError` (base) → `AuthenticationError` · `MissingTokenError` ·
`TokenExpiredError` · `TokenNotYetValidError` · `InvalidAudienceError` ·
`InvalidIssuerError` · `InvalidSignatureError` · `InvalidTokenError` ·
`AuthorizationError` (403) · `ConfigurationError` (500). Each has `code`,
`message`, `statusCode`, and `toJSON()`.

## Adding a provider

See [docs/adding-a-provider.md](../../docs/adding-a-provider.md) for a worked
Google example against the same `AuthProvider` interface.

## License

MIT
