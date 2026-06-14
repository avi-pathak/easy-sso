# Adding a new provider

The core never knows provider specifics. A provider is **anything that turns a
raw token into a normalized `AuthUser`** — i.e. an implementation of the
`AuthProvider` interface:

```ts
interface AuthProvider {
  readonly name: string;
  authenticate(token: string, context?: AuthContext): Promise<AuthUser>;
  initialize?(): Promise<void>;
  dispose?(): Promise<void>;
}
```

Because the middleware (`createAuthMiddleware`, `requireAuth`, `requireRole`)
depends only on this interface, a new provider plugs in with **zero changes to
the public API or to consuming apps**.

## Recommended file layout

Mirror the Microsoft provider:

```
src/providers/google/
  google-provider.ts    # implements AuthProvider
  token-validator.ts    # signature + iss/aud/exp validation
  jwks-client.ts        # reuse the shared MemoryKeyCache
  claims-mapper.ts      # Google claims → AuthUser
  index.ts
```

You get the JWKS cache (`MemoryKeyCache` — TTL, single-flight, rotation) and the
typed error hierarchy for free; reuse them rather than reinventing.

## A Google provider stub

Google publishes OIDC metadata at
`https://accounts.google.com/.well-known/openid-configuration` and a JWKS at
`https://www.googleapis.com/oauth2/v3/certs`. ID tokens are issued by
`https://accounts.google.com` with `aud = <your OAuth client id>`.

```ts
// src/providers/google/google-provider.ts
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

export interface GoogleAuthConfig {
  clientId: string; // OAuth 2.0 client ID — the expected `aud`
  clockToleranceSec?: number;
  jwksUri?: string;
}

const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];
const DEFAULT_JWKS = "https://www.googleapis.com/oauth2/v3/certs";

export class GoogleProvider implements AuthProvider {
  public readonly name = "google";
  private readonly cache: MemoryKeyCache<JSONWebKeySet>;

  public constructor(private readonly config: GoogleAuthConfig) {
    if (!config.clientId) throw new AuthenticationError("Google clientId is required");
    const uri = config.jwksUri ?? DEFAULT_JWKS;
    this.cache = new MemoryKeyCache<JSONWebKeySet>({
      ttlMs: 60 * 60 * 1000,
      loader: async () => {
        const res = await fetch(uri);
        if (!res.ok) throw new AuthenticationError("Failed to fetch Google JWKS");
        return (await res.json()) as JSONWebKeySet;
      },
    });
  }

  public async authenticate(token: string): Promise<AuthUser> {
    if (!token) throw new MissingTokenError();
    const jwks = createLocalJWKSet(await this.cache.get("google"));
    try {
      const { payload } = await jwtVerify(token, jwks, {
        issuer: GOOGLE_ISSUERS,
        audience: this.config.clientId,
        algorithms: ["RS256"],
        clockTolerance: this.config.clockToleranceSec ?? 60,
      });
      return this.mapUser(payload);
    } catch (err) {
      throw this.mapError(err);
    }
  }

  private mapUser(p: Record<string, unknown>): AuthUser {
    const id = typeof p.sub === "string" ? p.sub : undefined;
    if (!id) throw new AuthenticationError("Google token missing sub");
    return {
      id,
      email: typeof p.email === "string" ? p.email : undefined,
      name: typeof p.name === "string" ? p.name : undefined,
      roles: [], // Google ID tokens have no roles; map from your own store
      scopes: typeof p.scope === "string" ? p.scope.split(" ") : [],
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
    return new AuthenticationError("Google token validation failed");
  }
}
```

## Wiring it up

No core changes. Either use the generic middleware directly:

```ts
import { createAuthMiddleware } from "@easy-sso/node";
import { GoogleProvider } from "@easy-sso/node/google"; // once published

app.use(createAuthMiddleware(new GoogleProvider({ clientId: GOOGLE_CLIENT_ID })));
app.get("/me", requireAuth(), (req, res) => res.json(req.user));
```

...or add a `googleAuth(config)` convenience factory mirroring `microsoftAuth`:

```ts
export function googleAuth(config: GoogleAuthConfig, options?: AuthMiddlewareOptions) {
  return createAuthMiddleware(new GoogleProvider(config), options);
}
```

That's the whole contract. `requireAuth`, `requireRole`, the error handling, and
every consumer route keep working unchanged — which is exactly the point of the
`AuthProvider` seam.

## Checklist for a production provider

- [ ] Validate signature against a cached JWKS (reuse `MemoryKeyCache`).
- [ ] Validate `iss`, `aud`, `exp`, `nbf`; pin `algorithms` (never allow `none`).
- [ ] Map errors onto the typed `AuthError` hierarchy.
- [ ] Normalize claims into `AuthUser` (support config-driven mapping).
- [ ] Fail fast on bad config.
- [ ] Tests with a locally generated keypair — never hit live endpoints.
