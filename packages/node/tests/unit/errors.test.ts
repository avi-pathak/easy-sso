import { describe, expect, it } from "vitest";
import {
  AuthError,
  AuthenticationError,
  AuthorizationError,
  ConfigurationError,
  InvalidAudienceError,
  InvalidIssuerError,
  InvalidSignatureError,
  InvalidTokenError,
  MissingTokenError,
  TokenExpiredError,
  TokenNotYetValidError,
} from "../../src/errors/index.js";

describe("error hierarchy", () => {
  it("each error carries code, message, and statusCode", () => {
    const cases: [AuthError, string, number][] = [
      [new AuthenticationError(), "authentication_error", 401],
      [new MissingTokenError(), "missing_token", 401],
      [new TokenExpiredError(), "token_expired", 401],
      [new TokenNotYetValidError(), "token_not_yet_valid", 401],
      [new InvalidAudienceError(), "invalid_audience", 401],
      [new InvalidIssuerError(), "invalid_issuer", 401],
      [new InvalidSignatureError(), "invalid_signature", 401],
      [new InvalidTokenError(), "invalid_token", 401],
      [new AuthorizationError(), "authorization_error", 403],
      [new ConfigurationError("bad"), "configuration_error", 500],
    ];
    for (const [err, code, status] of cases) {
      expect(err).toBeInstanceOf(AuthError);
      expect(err).toBeInstanceOf(Error);
      expect(err.code).toBe(code);
      expect(err.statusCode).toBe(status);
      expect(typeof err.message).toBe("string");
      expect(err.name).toBe(err.constructor.name);
    }
  });

  it("serializes to a structured JSON body", () => {
    const err = new InvalidAudienceError("nope", { expected: ["a"] });
    expect(err.toJSON()).toEqual({
      error: "invalid_audience",
      message: "nope",
      statusCode: 401,
      details: { expected: ["a"] },
    });
  });

  it("omits details when absent", () => {
    expect(new MissingTokenError().toJSON()).toEqual({
      error: "missing_token",
      message: "No bearer token was provided",
      statusCode: 401,
    });
  });

  it("freezes details to prevent mutation", () => {
    const err = new AuthorizationError("x", { role: "admin" });
    expect(Object.isFrozen(err.details)).toBe(true);
  });

  it("isAuthError recognizes framework errors and rejects others", () => {
    expect(AuthError.isAuthError(new TokenExpiredError())).toBe(true);
    expect(AuthError.isAuthError(new Error("plain"))).toBe(false);
    expect(AuthError.isAuthError("nope")).toBe(false);
    expect(AuthError.isAuthError(null)).toBe(false);
  });

  it("captures a stack trace", () => {
    expect(new AuthenticationError().stack).toContain("AuthenticationError");
  });
});
