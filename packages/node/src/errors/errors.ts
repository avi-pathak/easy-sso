import { AuthError } from "./auth-error.js";

/**
 * Generic authentication failure (HTTP 401). Use for token problems that do not
 * fit a more specific subclass below.
 */
export class AuthenticationError extends AuthError {
  public readonly code = "authentication_error" as const;
  public readonly statusCode = 401;

  public constructor(message = "Authentication failed", details?: Record<string, unknown>) {
    super(message, details);
  }
}

/** The `Authorization` header / bearer token was absent (HTTP 401). */
export class MissingTokenError extends AuthError {
  public readonly code = "missing_token" as const;
  public readonly statusCode = 401;

  public constructor(message = "No bearer token was provided", details?: Record<string, unknown>) {
    super(message, details);
  }
}

/** The token's `exp` claim is in the past (HTTP 401). */
export class TokenExpiredError extends AuthError {
  public readonly code = "token_expired" as const;
  public readonly statusCode = 401;

  public constructor(message = "Token has expired", details?: Record<string, unknown>) {
    super(message, details);
  }
}

/** The token's `nbf` claim is in the future (HTTP 401). */
export class TokenNotYetValidError extends AuthError {
  public readonly code = "token_not_yet_valid" as const;
  public readonly statusCode = 401;

  public constructor(message = "Token is not yet valid", details?: Record<string, unknown>) {
    super(message, details);
  }
}

/** The token's `aud` claim did not match the expected audience (HTTP 401). */
export class InvalidAudienceError extends AuthError {
  public readonly code = "invalid_audience" as const;
  public readonly statusCode = 401;

  public constructor(message = "Token audience is invalid", details?: Record<string, unknown>) {
    super(message, details);
  }
}

/** The token's `iss` claim did not match the expected issuer (HTTP 401). */
export class InvalidIssuerError extends AuthError {
  public readonly code = "invalid_issuer" as const;
  public readonly statusCode = 401;

  public constructor(message = "Token issuer is invalid", details?: Record<string, unknown>) {
    super(message, details);
  }
}

/** The token signature failed verification against the JWKS (HTTP 401). */
export class InvalidSignatureError extends AuthError {
  public readonly code = "invalid_signature" as const;
  public readonly statusCode = 401;

  public constructor(
    message = "Token signature verification failed",
    details?: Record<string, unknown>,
  ) {
    super(message, details);
  }
}

/** The token was malformed or otherwise unparseable (HTTP 401). */
export class InvalidTokenError extends AuthError {
  public readonly code = "invalid_token" as const;
  public readonly statusCode = 401;

  public constructor(message = "Token is invalid", details?: Record<string, unknown>) {
    super(message, details);
  }
}

/**
 * The principal is authenticated but lacks the required role/scope (HTTP 403).
 * Distinct from authentication failures so adapters can respond with 403.
 */
export class AuthorizationError extends AuthError {
  public readonly code = "authorization_error" as const;
  public readonly statusCode = 403;

  public constructor(
    message = "You do not have permission to access this resource",
    details?: Record<string, unknown>,
  ) {
    super(message, details);
  }
}

/**
 * Invalid or missing framework configuration (HTTP 500). Thrown eagerly at setup
 * time — a misconfigured server is a programming error, not a request error.
 */
export class ConfigurationError extends AuthError {
  public readonly code = "configuration_error" as const;
  public readonly statusCode = 500;

  public constructor(message: string, details?: Record<string, unknown>) {
    super(message, details);
  }
}
