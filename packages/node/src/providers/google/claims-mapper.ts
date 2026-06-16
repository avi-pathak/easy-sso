import { type AuthUser } from "../../core/auth-user.js";
import { type RawClaims } from "../../core/claims.js";
import { type ClaimMappingConfig } from "../../config/types.js";
import { type NormalizedGoogleConfig } from "./config.js";
import { AuthenticationError } from "../../errors/index.js";

/**
 * Default source claims for each field, in priority order, for Google ID tokens.
 * Google ID tokens carry no application roles, so `roles` defaults to empty — map
 * roles from your own store. The `hd` (hosted domain) claim is surfaced as
 * `tenantId`, the closest analogue to a Microsoft tenant.
 */
const GOOGLE_DEFAULTS: Required<{ [K in keyof ClaimMappingConfig]: string[] }> = {
  id: ["sub"],
  email: ["email"],
  name: ["name"],
  roles: [],
  scopes: ["scope"],
  tenantId: ["hd"],
};

function toSourceList(value: string | string[] | undefined): string[] | undefined {
  if (value === undefined) return undefined;
  return Array.isArray(value) ? value : [value];
}

function firstString(claims: RawClaims, sources: readonly string[]): string | undefined {
  for (const source of sources) {
    const value = claims[source];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

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

function sourcesFor(field: keyof ClaimMappingConfig, config: ClaimMappingConfig): string[] {
  return toSourceList(config[field]) ?? GOOGLE_DEFAULTS[field];
}

/**
 * Map validated Google claims into the normalized {@link AuthUser}, honoring any
 * config-driven {@link ClaimMappingConfig} overrides. The only place that knows
 * Google claim names; the rest of the framework consumes the provider-neutral
 * `AuthUser`.
 */
export function mapGoogleClaimsToUser(
  claims: RawClaims,
  config: NormalizedGoogleConfig,
  providerName: string,
): AuthUser {
  const mapping = config.claims;

  const id = firstString(claims, sourcesFor("id", mapping));
  if (id === undefined) {
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
