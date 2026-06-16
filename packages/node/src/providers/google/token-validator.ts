import { errors as joseErrors, jwtVerify, type JWTPayload } from "jose";
import { type RawClaims } from "../../core/claims.js";
import { type JwksClient } from "../../jwks/jwks-client.js";
import {
  AuthenticationError,
  InvalidAudienceError,
  InvalidIssuerError,
  InvalidSignatureError,
  InvalidTokenError,
  TokenExpiredError,
  TokenNotYetValidError,
  type AuthError,
} from "../../errors/index.js";
import { type NormalizedGoogleConfig } from "./config.js";
import { assertHostedDomainAllowed, GOOGLE_ISSUERS } from "./issuer.js";

/**
 * Only RS256 is accepted. Pinning the algorithm set is a hard security boundary:
 * it blocks `alg: none` and RSA/HMAC confusion attacks. Google signs with RS256.
 */
const ACCEPTED_ALGORITHMS = ["RS256"] as const;

/**
 * Validates Google OIDC ID tokens end-to-end: signature, issuer, audience,
 * expiry (`exp`), not-before (`nbf`), and (optionally) the Workspace hosted
 * domain. No claim is trusted until the signature has been verified.
 */
export class GoogleTokenValidator {
  public constructor(
    private readonly config: NormalizedGoogleConfig,
    private readonly jwksClient: JwksClient,
  ) {}

  public async validate(token: string): Promise<RawClaims> {
    const payload = await this.verifySignatureAndClaims(token);
    const hd = typeof payload.hd === "string" ? payload.hd : undefined;
    assertHostedDomainAllowed(hd, this.config.hostedDomains);
    return payload;
  }

  private async verifySignatureAndClaims(token: string): Promise<JWTPayload> {
    const verifyOptions = {
      issuer: [...GOOGLE_ISSUERS],
      audience: [...this.config.audiences],
      algorithms: [...ACCEPTED_ALGORITHMS],
      clockTolerance: this.config.clockToleranceSec,
      currentDate: new Date(this.config.clock.now()),
    };

    try {
      const resolver = await this.jwksClient.getKeyResolver();
      const { payload } = await jwtVerify(token, resolver, verifyOptions);
      return payload;
    } catch (error) {
      // A missing key id usually means the signing keys rotated since we cached
      // them. Force one refresh and retry before giving up.
      if (error instanceof joseErrors.JWKSNoMatchingKey) {
        try {
          const resolver = await this.jwksClient.refresh();
          const { payload } = await jwtVerify(token, resolver, verifyOptions);
          return payload;
        } catch (retryError) {
          throw this.mapJoseError(retryError);
        }
      }
      throw this.mapJoseError(error);
    }
  }

  /** Translate jose / unknown errors into the framework's typed {@link AuthError}s. */
  private mapJoseError(error: unknown): AuthError {
    if (error instanceof AuthenticationError) return error;

    // NB: JWTExpired extends JWTClaimValidationFailed, so check it first.
    if (error instanceof joseErrors.JWTExpired) {
      return new TokenExpiredError("Token has expired", { claim: "exp" });
    }
    if (error instanceof joseErrors.JWTClaimValidationFailed) {
      switch (error.claim) {
        case "aud":
          return new InvalidAudienceError("Token audience is invalid", {
            expected: this.config.audiences,
          });
        case "iss":
          return new InvalidIssuerError("Token issuer is invalid");
        case "nbf":
          return new TokenNotYetValidError("Token is not yet valid", { claim: "nbf" });
        default:
          return new AuthenticationError(`Token claim '${error.claim}' failed validation`, {
            claim: error.claim,
            reason: error.reason,
          });
      }
    }
    if (error instanceof joseErrors.JWSSignatureVerificationFailed) {
      return new InvalidSignatureError("Token signature verification failed");
    }
    if (error instanceof joseErrors.JWKSNoMatchingKey) {
      return new InvalidSignatureError("No matching signing key was found for the token");
    }
    if (error instanceof joseErrors.JWTInvalid || error instanceof joseErrors.JWSInvalid) {
      return new InvalidTokenError("Token is malformed");
    }
    if (error instanceof joseErrors.JOSEError) {
      return new AuthenticationError("Token validation failed", { code: error.code });
    }
    return new AuthenticationError("Unexpected error during token validation");
  }
}
