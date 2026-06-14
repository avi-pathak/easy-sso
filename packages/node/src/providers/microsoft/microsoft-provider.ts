import { type AuthProvider } from "../../core/auth-provider.js";
import { type AuthContext } from "../../core/auth-context.js";
import { type AuthUser } from "../../core/auth-user.js";
import { MissingTokenError } from "../../errors/index.js";
import { validateMicrosoftConfig } from "../../config/validate.js";
import { type MicrosoftAuthConfig, type NormalizedMicrosoftConfig } from "../../config/types.js";
import { MicrosoftJwksClient } from "./jwks-client.js";
import { MicrosoftTokenValidator } from "./token-validator.js";
import { mapClaimsToUser } from "./claims-mapper.js";

/**
 * Microsoft Entra ID implementation of {@link AuthProvider}.
 *
 * It is the *only* place in the codebase that ties together Entra-specific issuer
 * resolution, JWKS endpoints, and claim shapes. Everything Microsoft-aware is
 * reachable from here; the middleware and core never import it directly — they
 * depend on the `AuthProvider` interface — which is what lets Google/Okta/Auth0
 * drop in later with no public-API change.
 */
export class MicrosoftProvider implements AuthProvider {
  public readonly name = "microsoft";

  private readonly config: NormalizedMicrosoftConfig;
  private readonly jwksClient: MicrosoftJwksClient;
  private readonly validator: MicrosoftTokenValidator;

  public constructor(config: MicrosoftAuthConfig) {
    // Fail-fast: a bad config throws a descriptive ConfigurationError here, at
    // construction/startup — never deep inside request handling.
    this.config = validateMicrosoftConfig(config);
    this.jwksClient = new MicrosoftJwksClient({
      jwksUri: this.config.jwksUri,
      ttlMs: this.config.jwksTtlMs,
      refreshIntervalMs: this.config.jwksRefreshIntervalMs,
      fetch: this.config.fetch,
      clock: this.config.clock,
    });
    this.validator = new MicrosoftTokenValidator(this.config, this.jwksClient);
  }

  public async authenticate(token: string, _context?: AuthContext): Promise<AuthUser> {
    if (typeof token !== "string" || token.length === 0) {
      throw new MissingTokenError();
    }
    const claims = await this.validator.validate(token);
    return mapClaimsToUser(claims, this.config, this.name);
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
