import { AuthenticationError, AuthError } from "../errors/index.js";
import {
  type AuthAwareRequest,
  type AuthAwareResponse,
  type AuthErrorHandler,
  type NextFunction,
} from "./types.js";

/** Coerce an unknown thrown value into a typed {@link AuthError}. */
export function toAuthError(error: unknown): AuthError {
  if (AuthError.isAuthError(error)) {
    return error;
  }
  return new AuthenticationError("Authentication failed", {
    cause: error instanceof Error ? error.message : String(error),
  });
}

/**
 * The default error responder: emits the error's structured JSON body with its
 * status code, and a `WWW-Authenticate: Bearer` challenge on 401 responses (per
 * RFC 6750). No-ops if a response has already been sent.
 */
export const defaultErrorHandler: AuthErrorHandler = (
  error: AuthError,
  _req: AuthAwareRequest,
  res: AuthAwareResponse,
  _next: NextFunction,
): void => {
  if (res.headersSent === true) {
    return;
  }
  if (error.statusCode === 401) {
    res.setHeader(
      "WWW-Authenticate",
      `Bearer error="${error.code}", error_description="${error.message}"`,
    );
  }
  res.status(error.statusCode).json(error.toJSON());
};
