/**
 * Core abstractions for the easy-sso framework.
 *
 * Everything here is provider-agnostic. No file in `core` may import from
 * `providers/*`. Providers depend on core, never the reverse.
 */
export type { AuthUser } from "./auth-user.js";
export type { AuthProvider } from "./auth-provider.js";
export type { AuthContext } from "./auth-context.js";
export { createAuthContext } from "./auth-context.js";
export type { RawClaims, RegisteredClaims, TokenHeader } from "./claims.js";
