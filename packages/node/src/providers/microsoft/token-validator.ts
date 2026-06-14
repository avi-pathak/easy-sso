import { decodeJwt, errors as joseErrors, jwtVerify, type JWTPayload } from "jose";
import { type RawClaims } from "../../core/claims.js";
import { type NormalizedMicrosoftConfig, type TokenVersion } from "../../config/types.js";
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
import { type MicrosoftJwksClient } from "./jwks-client.js";
import { assertTenantAllowed, resolveExpectedIssuer } from "./issuer.js";

/**
 * Only RS256 is accepted. Pinning the algorithm set is a hard security boundary:
 * it blocks `alg: none` and RSA/HMAC confusion attacks. This is intentionally not
 * configurable — Entra signs with RS256.
 */
const ACCEPTED_ALGORITHMS = ["RS256"] as const;

/**
 * Validates Microsoft Entra ID tokens end-to-end: signature, issuer, audience,
 * expiry (`exp`), not-before (`nbf`), tenant, and token version.
 *
 * Flow:
 *  1. Decode (unverified) just enough to read `tid` and `ver` so the correct
 *     issuer can be computed — `common`/`organizations` have no fixed issuer.
 *  2. Cryptographically verify signature + standard claims against the resolved
 *     issuer and configured audience(s) via jose.
 *  3. Assert tenant policy and token-version policy on the *verified* payload.
 *
 * No claim is trusted until after step 2.
 */
export class MicrosoftTokenValidator {
  public constructor(
    private readonly config: NormalizedMicrosoftConfig,
    private readonly jwksClient: MicrosoftJwksClient,
  ) {}

  public async validate(token: string): Promise<RawClaims> {
    // --- Step 1: peek (untrusted) to resolve issuer ------------------------
    const peeked = this.decode(token);
    const version = this.resolveVersion(peeked);
    const tid = this.requireTid(peeked);
    const expectedIssuer = resolveExpectedIssuer(tid, version, this.config);

    // --- Step 2: cryptographic verification --------------------------------
    const payload = await this.verifySignatureAndClaims(token, expectedIssuer);

    // --- Step 3: policy on the verified payload ----------------------------
    const verifiedTid = this.requireTid(payload);
    assertTenantAllowed(verifiedTid, this.config);
    this.assertVersionAccepted(this.resolveVersion(payload));

    return payload;
  }

  // --- internals -----------------------------------------------------------

  private decode(token: string): JWTPayload {
    try {
      return decodeJwt(token);
    } catch (cause) {
      throw new InvalidTokenError("Token could not be decoded", {
        cause: cause instanceof Error ? cause.message : String(cause),
      });
    }
  }

  private resolveVersion(claims: JWTPayload): TokenVersion {
    const ver = claims.ver;
    if (ver === "2.0") return "2.0";
    if (ver === "1.0") return "1.0";
    // Fall back to inferring from the issuer shape when `ver` is absent.
    const iss = typeof claims.iss === "string" ? claims.iss : "";
    if (iss.endsWith("/v2.0")) return "2.0";
    if (iss.includes(this.config.v1IssuerHost)) return "1.0";
    throw new InvalidTokenError("Unable to determine token version", {
      ver: typeof ver === "string" ? ver : null,
    });
  }

  private requireTid(claims: JWTPayload): string {
    const tid = claims.tid;
    if (typeof tid !== "string" || tid.length === 0) {
      throw new InvalidIssuerError("Token is missing the tenant id (tid) claim");
    }
    return tid;
  }

  private assertVersionAccepted(version: TokenVersion): void {
    if (!this.config.acceptedVersions.includes(version)) {
      throw new InvalidTokenError(`Token version ${version} is not accepted`, {
        accepted: this.config.acceptedVersions,
        actual: version,
      });
    }
  }

  private async verifySignatureAndClaims(
    token: string,
    expectedIssuer: string,
  ): Promise<JWTPayload> {
    const verifyOptions = {
      issuer: expectedIssuer,
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
    // Already one of ours (e.g. thrown from the JWKS loader) — pass through.
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
    if (
      error instanceof joseErrors.JWTInvalid ||
      error instanceof joseErrors.JWSInvalid ||
      error instanceof joseErrors.JWTClaimValidationFailed
    ) {
      return new InvalidTokenError("Token is malformed");
    }
    if (error instanceof joseErrors.JOSEError) {
      return new AuthenticationError("Token validation failed", { code: error.code });
    }
    return new AuthenticationError("Unexpected error during token validation");
  }
}
