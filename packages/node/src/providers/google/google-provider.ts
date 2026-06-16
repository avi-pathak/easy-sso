import { type AuthProvider } from "../../core/auth-provider.js";
import { type AuthContext } from "../../core/auth-context.js";
import { type AuthUser } from "../../core/auth-user.js";
import { MissingTokenError } from "../../errors/index.js";
import { JwksClient } from "../../jwks/jwks-client.js";
import { validateGoogleConfig, type GoogleAuthConfig, type NormalizedGoogleConfig } from "./config.js";
import { GoogleTokenValidator } from "./token-validator.js";
import { mapGoogleClaimsToUser } from "./claims-mapper.js";

/**
 * Google implementation of {@link AuthProvider}.
 *
 * It validates Google-issued OIDC ID tokens against Google's published JWKS and
 * is the only place that knows Google's issuer/claim specifics. The middleware
 * and core never import it directly — they depend on {@link AuthProvider} — which
 * is what lets it sit alongside Microsoft (and future providers) with no
 * public-API change.
 */
export class GoogleProvider implements AuthProvider {
  public readonly name = "google";

  private readonly config: NormalizedGoogleConfig;
  private readonly jwksClient: JwksClient;
  private readonly validator: GoogleTokenValidator;

  public constructor(config: GoogleAuthConfig) {
    // Fail-fast: a bad config throws a descriptive ConfigurationError here, at
    // construction/startup — never deep inside request handling.
    this.config = validateGoogleConfig(config);
    this.jwksClient = new JwksClient({
      jwksUri: this.config.jwksUri,
      ttlMs: this.config.jwksTtlMs,
      refreshIntervalMs: this.config.jwksRefreshIntervalMs,
      fetch: this.config.fetch,
      clock: this.config.clock,
    });
    this.validator = new GoogleTokenValidator(this.config, this.jwksClient);
  }

  public async authenticate(token: string, _context?: AuthContext): Promise<AuthUser> {
    if (typeof token !== "string" || token.length === 0) {
      throw new MissingTokenError();
    }
    const claims = await this.validator.validate(token);
    return mapGoogleClaimsToUser(claims, this.config, this.name);
  }

  /** Eagerly warm the JWKS cache so the first request doesn't pay the fetch. */
  public async initialize(): Promise<void> {
    await this.jwksClient.prime();
  }

  /** Release timers/caches held by the provider. */
  public dispose(): Promise<void> {
    this.jwksClient.dispose();
    return Promise.resolve();
  }
}
