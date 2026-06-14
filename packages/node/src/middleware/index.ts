export { createAuthMiddleware, microsoftAuth } from "./auth.js";
export type { AuthMiddlewareOptions } from "./auth.js";
export { requireAuth } from "./require-auth.js";
export type { RequireAuthOptions } from "./require-auth.js";
export { requireRole, requireRoles } from "./require-role.js";
export type { RequireRoleOptions, RoleMatchMode } from "./require-role.js";
export { defaultErrorHandler, toAuthError } from "./respond.js";
export type {
  AuthAwareRequest,
  AuthAwareResponse,
  AuthErrorHandler,
  NextFunction,
  RequestHandler,
  IncomingHeaders,
} from "./types.js";
