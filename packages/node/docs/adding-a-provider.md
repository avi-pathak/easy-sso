# Adding a provider

> **Microsoft and Google ship built in** (`microsoftAuth` / `googleAuth`). This
> guide is the template for the next one — Okta, Auth0, Keycloak, or any OIDC
> issuer. A provider plugs into the `AuthProvider` seam with **zero changes to
> the public API or to consuming route code**.

- [The contract](#the-contract)
- [Recommended file layout](#recommended-file-layout)
- [A worked provider](#a-worked-provider)
- [Wiring it up](#wiring-it-up)
- [Testing](#testing)
- [Production checklist](#production-checklist)

## The contract

The core never knows provider specifics. A provider is **anything that turns a
raw token into a normalized `AuthUser`** — an implementation of `AuthProvider`:

```ts
interface AuthProvider {
  readonly name: string;
  authenticate(token: string, context?: AuthContext): Promise<AuthUser>;
  initialize?(): Promise<void>;
  dispose?(): Promise<void>;
}
```

Because the middleware (`createAuthMiddleware`, `requireAuth`, `requireRole`)
depends only on this interface, everything downstream keeps working unchanged.

## Recommended file layout

Mirror the built-in providers under `src/providers/`:

```
src/providers/<name>/
  <name>-provider.ts   # implements AuthProvider
  token-validator.ts   # signature + iss/aud/exp/nbf validation
  jwks-client.ts       # reuse the shared MemoryKeyCache
  claims-mapper.ts     # provider claims → AuthUser
  config.ts            # typed config + fail-fast validation
  index.ts
```

You get the JWKS cache (`MemoryKeyCache` — TTL, single-flight dedup, key
rotation) and the typed `AuthError` hierarchy **for free**. Reuse them rather
than reinventing.

## A worked provider

Most modern IdPs publish OIDC discovery at
`https://<issuer>/.well-known/openid-configuration` and a JWKS URL you can pull
signing keys from. The essentials:

```ts
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";
import {
  type AuthProvider,
  type AuthUser,
  MemoryKeyCache,
  MissingTokenError,
  InvalidAudienceError,
  InvalidIssuerError,
  TokenExpiredError,
  AuthenticationError,
} from "@easy-sso/node";

export interface OktaAuthConfig {
  issuer: string;   // e.g. https://dev-123.okta.com/oauth2/default
  clientId: string; // expected `aud`
  jwksUri?: string;
  clockToleranceSec?: number;
}

export class OktaProvider implements AuthProvider {
  public readonly name = "okta";
  private readonly cache: MemoryKeyCache<JSONWebKeySet>;

  public constructor(private readonly config: OktaAuthConfig) {
    if (!config.issuer) throw new AuthenticationError("Okta issuer is required");
    if (!config.clientId) throw new AuthenticationError("Okta clientId is required");
    const uri = config.jwksUri ?? `${config.issuer}/v1/keys`;
    this.cache = new MemoryKeyCache<JSONWebKeySet>({
      ttlMs: 60 * 60 * 1000,
      loader: async () => {
        const res = await fetch(uri);
        if (!res.ok) throw new AuthenticationError("Failed to fetch Okta JWKS");
        return (await res.json()) as JSONWebKeySet;
      },
    });
  }

  public async authenticate(token: string): Promise<AuthUser> {
    if (!token) throw new MissingTokenError();
    const jwks = createLocalJWKSet(await this.cache.get("okta"));
    try {
      const { payload } = await jwtVerify(token, jwks, {
        issuer: this.config.issuer,
        audience: this.config.clientId,
        algorithms: ["RS256"], // never allow `none` or HMAC
        clockTolerance: this.config.clockToleranceSec ?? 60,
      });
      return this.mapUser(payload);
    } catch (err) {
      throw this.mapError(err);
    }
  }

  private mapUser(p: Record<string, unknown>): AuthUser {
    const id = typeof p.sub === "string" ? p.sub : undefined;
    if (!id) throw new AuthenticationError("Okta token missing sub");
    return {
      id,
      email: typeof p.email === "string" ? p.email : undefined,
      name: typeof p.name === "string" ? p.name : undefined,
      roles: Array.isArray(p.groups) ? (p.groups as string[]) : [],
      scopes: typeof p.scp === "object" && Array.isArray(p.scp) ? (p.scp as string[]) : [],
      provider: this.name,
      claims: Object.freeze({ ...p }),
    };
  }

  private mapError(err: unknown): Error {
    const code = (err as { code?: string }).code;
    if (code === "ERR_JWT_EXPIRED") return new TokenExpiredError();
    if (code === "ERR_JWT_CLAIM_VALIDATION_FAILED") {
      const claim = (err as { claim?: string }).claim;
      if (claim === "aud") return new InvalidAudienceError();
      if (claim === "iss") return new InvalidIssuerError();
    }
    return new AuthenticationError("Okta token validation failed");
  }
}
```

## Wiring it up

**No core changes.** Use the generic middleware directly:

```ts
import { createAuthMiddleware, requireAuth } from "@easy-sso/node";
import { OktaProvider } from "./providers/okta";

app.use(createAuthMiddleware(new OktaProvider({ issuer, clientId })));
app.get("/me", requireAuth(), (req, res) => res.json(req.user));
```

…or add an `oktaAuth(config)` convenience factory mirroring `microsoftAuth`:

```ts
import { createAuthMiddleware, type AuthMiddlewareOptions } from "@easy-sso/node";

export function oktaAuth(config: OktaAuthConfig, options?: AuthMiddlewareOptions) {
  return createAuthMiddleware(new OktaProvider(config), options);
}
```

`requireAuth`, `requireRole`, error handling, and every consumer route keep
working unchanged — the whole point of the `AuthProvider` seam.

## Testing

Test against a **locally generated keypair** — never hit live endpoints. Sign a
token with a test private key, serve the matching public JWKS through the
provider's `jwksUri` (or inject a `loader`), and assert both the success path
and each rejection (`exp`, `aud`, `iss`, bad signature). See
`packages/node/tests/` for the pattern used by the built-in providers.

## Production checklist

- [ ] Validate the signature against a cached JWKS (reuse `MemoryKeyCache`).
- [ ] Validate `iss`, `aud`, `exp`, `nbf`; pin `algorithms` (never allow `none`).
- [ ] Map errors onto the typed `AuthError` hierarchy.
- [ ] Normalize claims into `AuthUser` (support config-driven mapping).
- [ ] Fail fast on bad config with a `ConfigurationError`.
- [ ] Tests with a locally generated keypair — success **and** every rejection.
