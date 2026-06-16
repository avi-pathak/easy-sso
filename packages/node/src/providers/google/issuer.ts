import { InvalidIssuerError } from "../../errors/index.js";

/**
 * Accepted `iss` values for Google ID tokens. Google emits both the bare host
 * and the https form; either is valid.
 */
export const GOOGLE_ISSUERS = [
  "https://accounts.google.com",
  "accounts.google.com",
] as const;

/** Google's OAuth2 certs (JWKS) endpoint. */
export const DEFAULT_GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";

/**
 * Enforce the optional Google Workspace domain allow-list against the token's
 * `hd` (hosted domain) claim. Throws {@link InvalidIssuerError} when a non-empty
 * allow-list is configured and the token's `hd` is absent or not a member.
 */
export function assertHostedDomainAllowed(
  hd: string | undefined,
  allowed: readonly string[],
): void {
  if (allowed.length === 0) return;
  if (hd === undefined || !allowed.includes(hd)) {
    throw new InvalidIssuerError("Token hosted domain is not in the allowed list", {
      actual: hd ?? null,
      allowedHostedDomains: [...allowed],
    });
  }
}
