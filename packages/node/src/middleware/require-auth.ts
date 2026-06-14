import { AuthenticationError } from "../errors/index.js";
import { defaultErrorHandler } from "./respond.js";
import { type AuthErrorHandler, type RequestHandler } from "./types.js";

/** Options for {@link requireAuth}. */
export interface RequireAuthOptions {
  /** Override the 401 response. Default writes JSON + WWW-Authenticate. */
  onError?: AuthErrorHandler;
}

/**
 * Gate a route on an authenticated principal. Assumes an auth middleware
 * (e.g. {@link microsoftAuth}) ran earlier and populated `req.user`. Responds
 * 401 when no user is present; otherwise calls `next()`.
 */
export function requireAuth(options: RequireAuthOptions = {}): RequestHandler {
  const onError = options.onError ?? defaultErrorHandler;
  return (req, res, next): void => {
    if (req.user !== undefined) {
      next();
      return;
    }
    onError(
      new AuthenticationError("Authentication is required to access this resource"),
      req,
      res,
      next,
    );
  };
}
