import { AuthenticationError, AuthorizationError, ConfigurationError } from "../errors/index.js";
import { defaultErrorHandler } from "./respond.js";
import { type AuthErrorHandler, type RequestHandler } from "./types.js";

/** Whether the user must have ANY of the listed roles or ALL of them. */
export type RoleMatchMode = "any" | "all";

/** Options for {@link requireRole} / {@link requireRoles}. */
export interface RequireRoleOptions {
  /** `"any"` (default) passes if the user has ≥1 listed role; `"all"` requires every one. */
  mode?: RoleMatchMode;
  /** Override the 401/403 response. */
  onError?: AuthErrorHandler;
}

/**
 * Gate a route on role membership. Must run after an auth middleware populated
 * `req.user`. Responds 401 if unauthenticated, 403 if authenticated but lacking
 * the required role(s).
 */
export function requireRoles(
  roles: readonly string[],
  options: RequireRoleOptions = {},
): RequestHandler {
  if (roles.length === 0) {
    // Programming error — surfaced eagerly at wire-up, not per request.
    throw new ConfigurationError("requireRoles() requires at least one role");
  }
  const mode = options.mode ?? "any";
  const onError = options.onError ?? defaultErrorHandler;

  return (req, res, next): void => {
    const user = req.user;
    if (user === undefined) {
      onError(
        new AuthenticationError("Authentication is required to access this resource"),
        req,
        res,
        next,
      );
      return;
    }
    const granted = new Set(user.roles);
    const authorized =
      mode === "all"
        ? roles.every((role) => granted.has(role))
        : roles.some((role) => granted.has(role));

    if (authorized) {
      next();
      return;
    }
    onError(
      new AuthorizationError(
        `Access denied: requires ${mode === "all" ? "all" : "one"} of role(s) [${roles.join(", ")}]`,
        { requiredRoles: [...roles], mode },
      ),
      req,
      res,
      next,
    );
  };
}

/** Convenience for a single required role. Equivalent to `requireRoles([role])`. */
export function requireRole(role: string, options?: RequireRoleOptions): RequestHandler {
  return requireRoles([role], options);
}
