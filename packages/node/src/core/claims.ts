/**
 * JWT claim primitives.
 *
 * These types live in `core` and are intentionally provider-neutral. They model
 * the registered JWT claims from RFC 7519 plus an open map for everything else a
 * provider may emit. No Microsoft/Google/Okta specifics belong here.
 */

/**
 * The registered ("standard") JWT claims defined by RFC 7519, §4.1.
 * All are optional because a raw, unvalidated token may omit any of them — it is
 * the validator's job to assert the ones a given provider requires.
 */
export interface RegisteredClaims {
  /** Issuer — the principal that issued the token. */
  iss?: string;
  /** Subject — the principal the token is about (stable per issuer). */
  sub?: string;
  /** Audience — recipient(s) the token is intended for. */
  aud?: string | string[];
  /** Expiration time (seconds since the Unix epoch). */
  exp?: number;
  /** Not-before time (seconds since the Unix epoch). */
  nbf?: number;
  /** Issued-at time (seconds since the Unix epoch). */
  iat?: number;
  /** JWT ID — a unique identifier for the token. */
  jti?: string;
}

/**
 * A decoded set of JWT claims: the registered claims plus any provider-specific
 * claims (e.g. `tid`, `roles`, `preferred_username`). Unknown claims are typed
 * as `unknown` to force callers to narrow them safely — never `any`.
 */
export type RawClaims = RegisteredClaims & Record<string, unknown>;

/**
 * The protected header of a JWS/JWT (RFC 7515). Only the fields the framework
 * inspects are named; the rest remain accessible but `unknown`.
 */
export interface TokenHeader extends Record<string, unknown> {
  /** Signing algorithm, e.g. `RS256`. */
  alg?: string;
  /** Key ID — selects the verification key from a JWKS. */
  kid?: string;
  /** Token type, e.g. `JWT`. */
  typ?: string;
}
