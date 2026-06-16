/**
 * `@easy-sso/node` — a provider-agnostic SSO framework for Node.js.
 *
 * Public surface. The core abstractions ({@link AuthProvider}, {@link AuthUser},
 * {@link AuthContext}) know nothing about any provider; Microsoft Entra ID is one
 * implementation, exported alongside the generic middleware. New providers plug in
 * by implementing {@link AuthProvider} — with zero changes to anything exported here.
 */

import type { AuthUser as _AuthUser } from "./core/index.js";

// --- Core abstractions (provider-agnostic) ---
export type {
  AuthUser,
  AuthProvider,
  AuthContext,
  RawClaims,
  RegisteredClaims,
  TokenHeader,
} from "./core/index.js";
export { createAuthContext } from "./core/index.js";

// --- Errors ---
export {
  AuthError,
  AuthenticationError,
  MissingTokenError,
  TokenExpiredError,
  TokenNotYetValidError,
  InvalidAudienceError,
  InvalidIssuerError,
  InvalidSignatureError,
  InvalidTokenError,
  AuthorizationError,
  ConfigurationError,
} from "./errors/index.js";
export type { AuthErrorCode, AuthErrorJSON } from "./errors/index.js";

// --- JWKS / caching layer ---
export { MemoryKeyCache, systemClock } from "./cache/index.js";
export type { MemoryKeyCacheOptions, CacheLoader, Clock } from "./cache/index.js";

// --- Middleware (generic + Microsoft convenience) ---
export {
  microsoftAuth,
  createAuthMiddleware,
  requireAuth,
  requireRole,
  requireRoles,
  defaultErrorHandler,
  toAuthError,
  googleAuth,
} from "./middleware/index.js";
export type {
  AuthMiddlewareOptions,
  RequireAuthOptions,
  RequireRoleOptions,
  RoleMatchMode,
  AuthAwareRequest,
  AuthAwareResponse,
  AuthErrorHandler,
  NextFunction,
  RequestHandler,
  IncomingHeaders,
} from "./middleware/index.js";

// --- Microsoft provider ---
export {
  MicrosoftProvider,
  MicrosoftTokenValidator,
  MicrosoftJwksClient,
  mapClaimsToUser,
  resolveExpectedIssuer,
  assertTenantAllowed,
  isTenantGuid,
  isValidTenantId,
  PERSONAL_MSA_TENANT_ID,
} from "./providers/microsoft/index.js";
export type { MicrosoftJwksClientOptions } from "./providers/microsoft/index.js";

// --- Google provider ---
export {
  GoogleProvider,
  GoogleTokenValidator,
  mapGoogleClaimsToUser,
  validateGoogleConfig,
  assertHostedDomainAllowed,
  GOOGLE_ISSUERS,
  DEFAULT_GOOGLE_JWKS_URI,
} from "./providers/google/index.js";
export type { GoogleAuthConfig, NormalizedGoogleConfig } from "./providers/google/index.js";

// --- Shared JWKS client ---
export { JwksClient } from "./jwks/jwks-client.js";
export type { JwksClientOptions } from "./jwks/jwks-client.js";

// --- Config ---
export { validateMicrosoftConfig } from "./config/index.js";
export type {
  MicrosoftAuthConfig,
  NormalizedMicrosoftConfig,
  ClaimMappingConfig,
  JwksConfig,
  TokenVersion,
  FetchLike,
} from "./config/index.js";

// --- Utilities ---
export { extractBearerToken } from "./utils/index.js";

// --- Express type augmentation ---
// Mirrors `src/types/express.d.ts` (the canonical standalone declaration). It is
// inlined here so the rolled-up `dist/index.d.ts` ships the augmentation: simply
// importing `@easy-sso/node` gives consumers a typed `req.user`. Declaration
// merging keeps the two copies consistent.
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: _AuthUser;
    }
  }
}
