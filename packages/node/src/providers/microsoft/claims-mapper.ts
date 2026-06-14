import { type AuthUser } from "../../core/auth-user.js";
import { type RawClaims } from "../../core/claims.js";
import { type ClaimMappingConfig, type NormalizedMicrosoftConfig } from "../../config/types.js";
import { AuthenticationError } from "../../errors/index.js";

/** Default source claims for each field, in priority order, for Microsoft tokens. */
const MICROSOFT_DEFAULTS: Required<{ [K in keyof ClaimMappingConfig]: string[] }> = {
  // `oid` is the immutable object id; `sub` is stable but pairwise per app.
  id: ["oid", "sub"],
  // v2 access tokens lack `email`; UPN/preferred_username cover most cases.
  email: ["email", "preferred_username", "upn", "unique_name"],
  name: ["name"],
  // App roles land in `roles`; some directories surface group ids in `groups`.
  roles: ["roles"],
  // v2 delegated scopes in `scp`; v1 sometimes uses `scope`.
  scopes: ["scp", "scope"],
  tenantId: ["tid"],
};

function toSourceList(value: string | string[] | undefined): string[] | undefined {
  if (value === undefined) return undefined;
  return Array.isArray(value) ? value : [value];
}

/** First claim in `sources` whose value is a non-empty string. */
function firstString(claims: RawClaims, sources: readonly string[]): string | undefined {
  for (const source of sources) {
    const value = claims[source];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

/**
 * Collect a string array from the first matching source. Accepts either a real
 * array of strings or a space-delimited string (how Entra encodes `scp`).
 */
function stringArray(claims: RawClaims, sources: readonly string[]): string[] {
  for (const source of sources) {
    const value = claims[source];
    if (Array.isArray(value)) {
      return value.filter((v): v is string => typeof v === "string" && v.length > 0);
    }
    if (typeof value === "string" && value.length > 0) {
      return value.split(" ").filter((v) => v.length > 0);
    }
  }
  return [];
}

/** Resolve the effective source list for a field: custom override else default. */
function sourcesFor(field: keyof ClaimMappingConfig, config: ClaimMappingConfig): string[] {
  return toSourceList(config[field]) ?? MICROSOFT_DEFAULTS[field];
}

/**
 * Map validated Microsoft claims into the normalized {@link AuthUser}, honoring
 * any config-driven {@link ClaimMappingConfig} overrides.
 *
 * The mapper is the only place that knows Microsoft claim names — the rest of the
 * framework consumes the provider-neutral `AuthUser`. Swapping defaults here (or
 * via config) is how a different directory's claim shape is accommodated without
 * touching middleware or core.
 */
export function mapClaimsToUser(
  claims: RawClaims,
  config: NormalizedMicrosoftConfig,
  providerName: string,
): AuthUser {
  const mapping = config.claims;

  const id = firstString(claims, sourcesFor("id", mapping));
  if (id === undefined) {
    // Without a stable subject we cannot safely identify the principal.
    throw new AuthenticationError("Token is missing a usable subject identifier", {
      tried: sourcesFor("id", mapping),
    });
  }

  const email = firstString(claims, sourcesFor("email", mapping));
  const name = firstString(claims, sourcesFor("name", mapping));
  const tenantId = firstString(claims, sourcesFor("tenantId", mapping));
  const roles = stringArray(claims, sourcesFor("roles", mapping));
  const scopes = stringArray(claims, sourcesFor("scopes", mapping));

  return {
    id,
    ...(email !== undefined ? { email } : {}),
    ...(name !== undefined ? { name } : {}),
    roles,
    scopes,
    ...(tenantId !== undefined ? { tenantId } : {}),
    provider: providerName,
    claims: Object.freeze({ ...claims }),
  };
}
