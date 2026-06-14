import { systemClock } from "../cache/clock.js";
import { ConfigurationError } from "../errors/index.js";
import { isValidTenantId, isTenantGuid } from "../providers/microsoft/issuer.js";
import {
  type ClaimMappingConfig,
  type FetchLike,
  type MicrosoftAuthConfig,
  type NormalizedMicrosoftConfig,
  type TokenVersion,
} from "./types.js";

const DEFAULT_TENANT = "common";
const DEFAULT_AUTHORITY_HOST = "login.microsoftonline.com";
const DEFAULT_V1_ISSUER_HOST = "sts.windows.net";
const DEFAULT_CLOCK_TOLERANCE_SEC = 60;
const DEFAULT_JWKS_TTL_MS = 60 * 60 * 1000; // 1 hour
const VALID_VERSIONS: readonly TokenVersion[] = ["1.0", "2.0"];

function fail(message: string, details?: Record<string, unknown>): never {
  throw new ConfigurationError(message, details);
}

/** Strip protocol and any trailing slash from a host so URL building is uniform. */
function normalizeHost(host: string): string {
  return host.replace(/^https?:\/\//i, "").replace(/\/+$/, "");
}

function normalizeAudiences(audience: MicrosoftAuthConfig["audience"], clientId: string): string[] {
  if (audience === undefined) {
    return [clientId, `api://${clientId}`];
  }
  const list = Array.isArray(audience) ? audience : [audience];
  if (list.length === 0) {
    fail("`audience` was provided but empty; omit it to use defaults or supply at least one value");
  }
  for (const value of list) {
    if (typeof value !== "string" || value.trim().length === 0) {
      fail("`audience` entries must be non-empty strings", { audience });
    }
  }
  return list;
}

function validateClaimMapping(claims: ClaimMappingConfig | undefined): ClaimMappingConfig {
  if (claims === undefined) return {};
  for (const [field, value] of Object.entries(claims)) {
    if (value === undefined) continue;
    const list = Array.isArray(value) ? value : [value];
    if (list.length === 0) {
      fail(`\`claims.${field}\` was provided but empty`, { field });
    }
    for (const claimName of list) {
      if (typeof claimName !== "string" || claimName.trim().length === 0) {
        fail(`\`claims.${field}\` must map to non-empty claim name(s)`, { field, value });
      }
    }
  }
  return claims;
}

function resolveFetch(injected: FetchLike | undefined): FetchLike {
  if (injected !== undefined) return injected;
  if (typeof globalThis.fetch === "function") {
    return (input, init) => globalThis.fetch(input, init);
  }
  fail(
    "No global `fetch` is available (Node < 18). Upgrade Node or pass a `fetch` implementation in config.",
  );
}

/**
 * Validate and normalize user-supplied {@link MicrosoftAuthConfig}, applying all
 * defaults. Throws {@link ConfigurationError} with a descriptive message on the
 * first problem — this runs at startup so misconfiguration fails fast and loud.
 */
export function validateMicrosoftConfig(config: MicrosoftAuthConfig): NormalizedMicrosoftConfig {
  if (config === null || typeof config !== "object") {
    fail("Microsoft auth config must be an object");
  }

  const clientId = config.clientId;
  if (typeof clientId !== "string" || clientId.trim().length === 0) {
    fail("`clientId` is required and must be a non-empty string", { received: clientId });
  }

  const tenantId = config.tenantId ?? DEFAULT_TENANT;
  if (typeof tenantId !== "string" || !isValidTenantId(tenantId)) {
    fail(
      `\`tenantId\` must be 'common', 'organizations', 'consumers', or a tenant GUID (received: ${String(
        tenantId,
      )})`,
      { tenantId },
    );
  }

  const allowedTenants = config.allowedTenants ?? [];
  if (!Array.isArray(allowedTenants)) {
    fail("`allowedTenants` must be an array of tenant GUIDs");
  }
  for (const tenant of allowedTenants) {
    if (typeof tenant !== "string" || !isTenantGuid(tenant)) {
      fail("`allowedTenants` entries must be tenant GUIDs", { tenant });
    }
  }

  const acceptedVersions = config.acceptedVersions ?? [...VALID_VERSIONS];
  if (!Array.isArray(acceptedVersions) || acceptedVersions.length === 0) {
    fail("`acceptedVersions` must be a non-empty array");
  }
  for (const version of acceptedVersions) {
    if (!VALID_VERSIONS.includes(version)) {
      fail("`acceptedVersions` entries must be '1.0' or '2.0'", { version });
    }
  }

  const clockToleranceSec = config.clockToleranceSec ?? DEFAULT_CLOCK_TOLERANCE_SEC;
  if (
    typeof clockToleranceSec !== "number" ||
    !Number.isFinite(clockToleranceSec) ||
    clockToleranceSec < 0
  ) {
    fail("`clockToleranceSec` must be a non-negative number", { clockToleranceSec });
  }

  const authorityHost = normalizeHost(config.authorityHost ?? DEFAULT_AUTHORITY_HOST);
  if (authorityHost.length === 0) {
    fail("`authorityHost` must be a non-empty host");
  }
  const v1IssuerHost = normalizeHost(config.v1IssuerHost ?? DEFAULT_V1_ISSUER_HOST);

  const jwksTtlMs = config.jwks?.ttlMs ?? DEFAULT_JWKS_TTL_MS;
  if (typeof jwksTtlMs !== "number" || jwksTtlMs <= 0) {
    fail("`jwks.ttlMs` must be a positive number", { ttlMs: jwksTtlMs });
  }
  const jwksRefreshIntervalMs = config.jwks?.refreshIntervalMs;
  if (
    jwksRefreshIntervalMs !== undefined &&
    (typeof jwksRefreshIntervalMs !== "number" || jwksRefreshIntervalMs <= 0)
  ) {
    fail("`jwks.refreshIntervalMs` must be a positive number when provided", {
      refreshIntervalMs: jwksRefreshIntervalMs,
    });
  }

  const jwksUri = config.jwks?.uri ?? `https://${authorityHost}/${tenantId}/discovery/v2.0/keys`;

  return {
    clientId,
    tenantId,
    audiences: normalizeAudiences(config.audience, clientId),
    allowedTenants,
    acceptedVersions,
    clockToleranceSec,
    claims: validateClaimMapping(config.claims),
    authorityHost,
    v1IssuerHost,
    jwksUri,
    jwksTtlMs,
    jwksRefreshIntervalMs,
    fetch: resolveFetch(config.fetch),
    clock: config.clock ?? systemClock,
  };
}
