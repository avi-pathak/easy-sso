import { systemClock, type Clock } from "../../cache/clock.js";
import { ConfigurationError } from "../../errors/index.js";
import { type ClaimMappingConfig, type FetchLike, type JwksConfig } from "../../config/types.js";
import { DEFAULT_GOOGLE_JWKS_URI } from "./issuer.js";

const DEFAULT_CLOCK_TOLERANCE_SEC = 60;
const DEFAULT_JWKS_TTL_MS = 60 * 60 * 1000; // 1 hour

/**
 * Public configuration accepted by `googleAuth(...)` and `new GoogleProvider(...)`.
 * Validated and normalized at construction time.
 */
export interface GoogleAuthConfig {
  /** Your Google OAuth 2.0 client ID — the expected token audience. Required. */
  clientId: string;

  /**
   * Accepted token audience(s). Defaults to `[clientId]`. Supply several when
   * multiple client IDs (web/iOS/Android) share one backend.
   */
  audience?: string | string[];

  /**
   * Restrict logins to these Google Workspace domains: the token's `hd` claim
   * must match one. Omit to allow any Google account.
   */
  hostedDomains?: string[];

  /** Clock skew tolerance for `exp`/`nbf`, in seconds. Default: 60. */
  clockToleranceSec?: number;

  /** Config-driven claim mapping (overrides Google defaults). */
  claims?: ClaimMappingConfig;

  /** JWKS cache tuning. */
  jwks?: JwksConfig;

  /** Injected `fetch` (testing / custom transport). Defaults to global `fetch`. */
  fetch?: FetchLike;

  /** Injected clock (testing). Defaults to the system clock. */
  clock?: Clock;
}

/** Fully-resolved configuration with all defaults applied. Internal to the provider. */
export interface NormalizedGoogleConfig {
  readonly audiences: readonly string[];
  readonly hostedDomains: readonly string[];
  readonly clockToleranceSec: number;
  readonly claims: ClaimMappingConfig;
  readonly jwksUri: string;
  readonly jwksTtlMs: number;
  readonly jwksRefreshIntervalMs: number | undefined;
  readonly fetch: FetchLike;
  readonly clock: Clock;
}

function fail(message: string, details?: Record<string, unknown>): never {
  throw new ConfigurationError(message, details);
}

function normalizeAudiences(audience: GoogleAuthConfig["audience"], clientId: string): string[] {
  if (audience === undefined) {
    return [clientId];
  }
  const list = Array.isArray(audience) ? audience : [audience];
  if (list.length === 0) {
    fail("`audience` was provided but empty; omit it to default to the client ID");
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
 * Validate and normalize user-supplied {@link GoogleAuthConfig}, applying all
 * defaults. Throws {@link ConfigurationError} on the first problem — this runs at
 * startup so misconfiguration fails fast and loud.
 */
export function validateGoogleConfig(config: GoogleAuthConfig): NormalizedGoogleConfig {
  if (config === null || typeof config !== "object") {
    fail("Google auth config must be an object");
  }

  const clientId = config.clientId;
  if (typeof clientId !== "string" || clientId.trim().length === 0) {
    fail("`clientId` is required and must be a non-empty string", { received: clientId });
  }

  const hostedDomains = config.hostedDomains ?? [];
  if (!Array.isArray(hostedDomains)) {
    fail("`hostedDomains` must be an array of domain strings");
  }
  for (const domain of hostedDomains) {
    if (typeof domain !== "string" || domain.trim().length === 0) {
      fail("`hostedDomains` entries must be non-empty strings", { domain });
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

  return {
    audiences: normalizeAudiences(config.audience, clientId),
    hostedDomains,
    clockToleranceSec,
    claims: validateClaimMapping(config.claims),
    jwksUri: config.jwks?.uri ?? DEFAULT_GOOGLE_JWKS_URI,
    jwksTtlMs,
    jwksRefreshIntervalMs,
    fetch: resolveFetch(config.fetch),
    clock: config.clock ?? systemClock,
  };
}
