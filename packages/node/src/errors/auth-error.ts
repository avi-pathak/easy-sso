/**
 * Stable, machine-readable error codes. These are part of the public API: clients
 * and logs may switch on them, so treat changes as breaking.
 */
export type AuthErrorCode =
  | "authentication_error"
  | "missing_token"
  | "token_expired"
  | "token_not_yet_valid"
  | "invalid_audience"
  | "invalid_issuer"
  | "invalid_signature"
  | "invalid_token"
  | "authorization_error"
  | "configuration_error";

/** Structured, serializable representation of an {@link AuthError}. */
export interface AuthErrorJSON {
  error: AuthErrorCode;
  message: string;
  statusCode: number;
  details?: Readonly<Record<string, unknown>>;
}

/**
 * Base class for every error the framework throws.
 *
 * Carries a stable {@link AuthErrorCode}, a human-readable `message`, and the
 * HTTP `statusCode` an adapter should respond with. Concrete subclasses fix the
 * code/status so call sites can rely on them.
 */
export abstract class AuthError extends Error {
  /** Stable, machine-readable code. */
  public abstract readonly code: AuthErrorCode;

  /** HTTP status an adapter should map this error to. */
  public abstract readonly statusCode: number;

  /** Optional, non-sensitive structured context (e.g. expected vs actual). */
  public readonly details?: Readonly<Record<string, unknown>>;

  protected constructor(message: string, details?: Record<string, unknown>) {
    super(message);
    // Restore prototype chain — required when targeting ES5/ES2015 downlevel and
    // good hygiene generally so `instanceof` works across the hierarchy.
    Object.setPrototypeOf(this, new.target.prototype);
    this.name = new.target.name;
    if (details !== undefined) {
      this.details = Object.freeze({ ...details });
    }
    // Capture a clean stack where supported, omitting this constructor frame.
    if (typeof Error.captureStackTrace === "function") {
      Error.captureStackTrace(this, new.target);
    }
  }

  /** Serialize to a safe, structured payload suitable for an HTTP response body. */
  public toJSON(): AuthErrorJSON {
    return {
      error: this.code,
      message: this.message,
      statusCode: this.statusCode,
      ...(this.details !== undefined ? { details: this.details } : {}),
    };
  }

  /** Type guard usable across module/realm boundaries (duck-typed, not `instanceof`). */
  public static isAuthError(value: unknown): value is AuthError {
    return (
      value instanceof AuthError ||
      (typeof value === "object" &&
        value !== null &&
        "code" in value &&
        "statusCode" in value &&
        value instanceof Error)
    );
  }
}
