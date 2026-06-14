import { type RawClaims } from "./claims.js";

/**
 * The normalized, provider-agnostic representation of an authenticated principal.
 *
 * Every provider — Microsoft today, Google/Okta/Auth0 tomorrow — must map its
 * token into this shape. Consumers of the framework (route handlers, policies)
 * only ever see `AuthUser`; they never branch on which provider produced it.
 */
export interface AuthUser {
  /**
   * Stable, unique identifier for the principal within the issuing directory.
   * Providers map this from their most stable subject claim (Microsoft: `oid`,
   * falling back to `sub`).
   */
  readonly id: string;

  /** Primary email / UPN, if the token carries one. */
  readonly email?: string;

  /** Human-readable display name, if available. */
  readonly name?: string;

  /**
   * Application roles granted to the principal. Always an array (possibly empty)
   * so authorization checks never have to null-guard.
   */
  readonly roles: readonly string[];

  /**
   * OAuth2 scopes / delegated permissions present on the token. Always an array.
   */
  readonly scopes: readonly string[];

  /**
   * Tenant / organization identifier the principal belongs to, when the provider
   * is multi-tenant aware (Microsoft: `tid`).
   */
  readonly tenantId?: string;

  /** Name of the provider that authenticated this user (e.g. `"microsoft"`). */
  readonly provider: string;

  /**
   * The full set of validated claims from the token. Exposed (read-only) so
   * advanced consumers can read provider-specific claims without the framework
   * having to model every one of them.
   */
  readonly claims: Readonly<RawClaims>;
}
