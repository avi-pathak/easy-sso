import { type AuthContext } from "./auth-context.js";
import { type AuthUser } from "./auth-user.js";

/**
 * The single contract every authentication backend implements.
 *
 * This is the seam that makes the framework provider-agnostic. The middleware,
 * the error layer, and consuming applications all program against `AuthProvider`
 * and never against a concrete provider. Adding Google/Okta/Auth0/Keycloak later
 * means implementing this interface — with **zero** changes to the public API.
 *
 * Contract:
 *  - `authenticate` MUST validate the token fully (signature, issuer, audience,
 *    expiry, …) and either resolve a normalized {@link AuthUser} or reject with
 *    an {@link import("../errors/index.js").AuthError}.
 *  - It MUST NOT return a partially-trusted user. There is no "soft" success.
 *  - Implementations should be safe to share across requests and concurrent-safe.
 */
export interface AuthProvider {
  /**
   * Stable, lowercase identifier for the provider (e.g. `"microsoft"`).
   * Surfaced on {@link AuthUser.provider} and useful for logging/metrics.
   */
  readonly name: string;

  /**
   * Validate a raw bearer token and resolve the authenticated principal.
   *
   * @param token Raw JWT (no `Bearer ` prefix).
   * @param context Optional framework-agnostic request context. Providers may use
   *   it for advanced flows (e.g. nonce binding) but must not require it for the
   *   common bearer-token case.
   * @throws {import("../errors/index.js").AuthError} when the token is missing,
   *   malformed, expired, or otherwise untrustworthy.
   */
  authenticate(token: string, context?: AuthContext): Promise<AuthUser>;

  /**
   * Optional eager initialization (e.g. warm the JWKS cache, fetch OIDC
   * metadata). Adapters may call this at startup; it must be idempotent.
   */
  initialize?(): Promise<void>;

  /**
   * Optional cleanup of provider-held resources (timers, caches). Safe to call
   * multiple times.
   */
  dispose?(): Promise<void>;
}
