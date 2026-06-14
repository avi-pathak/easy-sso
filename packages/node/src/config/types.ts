import { type Clock } from "../cache/clock.js";

/** Microsoft Entra ID token versions this framework understands. */
export type TokenVersion = "1.0" | "2.0";

/**
 * Minimal structural type for the global `fetch`. Declared so the JWKS client can
 * accept an injected implementation in tests without depending on DOM lib types.
 */
export type FetchLike = (
  input: string | URL,
  init?: { signal?: AbortSignal },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/**
 * Config-driven mapping from {@link import("../core/auth-user.js").AuthUser}
 * fields to source JWT claim name(s). For each field you may supply a single
 * claim name or an ordered list — the first present, non-empty claim wins. When a
 * field is omitted, the provider's sensible Microsoft defaults apply.
 */
export interface ClaimMappingConfig {
  /** Source claim(s) for {@link import("../core/auth-user.js").AuthUser.id}. */
  id?: string | string[];
  /** Source claim(s) for `email`. */
  email?: string | string[];
  /** Source claim(s) for `name`. */
  name?: string | string[];
  /** Source claim(s) for `roles` (string array or space-delimited string). */
  roles?: string | string[];
  /** Source claim(s) for `scopes` (string array or space-delimited string). */
  scopes?: string | string[];
  /** Source claim(s) for `tenantId`. */
  tenantId?: string | string[];
}

/** Tuning for the JWKS cache used during signature verification. */
export interface JwksConfig {
  /** Freshness window for a fetched key set, in ms. Default: 1 hour. */
  ttlMs?: number;
  /**
   * Background proactive-refresh interval, in ms. Omit to disable (lazy refresh
   * on expiry only).
   */
  refreshIntervalMs?: number;
  /** Override the JWKS endpoint (sovereign clouds, B2C, or testing). */
  uri?: string;
}

/**
 * Public configuration accepted by `microsoftAuth(...)` and `new MicrosoftProvider(...)`.
 * This is the user-facing surface — validated and normalized at construction time.
 */
export interface MicrosoftAuthConfig {
  /** Application (client) ID of your Entra app registration. Required. */
  clientId: string;

  /**
   * Tenant mode: `"common"`, `"organizations"`, `"consumers"`, or a tenant GUID.
   * Controls which accounts are accepted and how the issuer is resolved.
   * Default: `"common"`.
   */
  tenantId?: string;

  /**
   * Accepted token audience(s). Defaults to the client ID and its `api://`
   * App ID URI form (`[clientId, "api://" + clientId]`).
   */
  audience?: string | string[];

  /**
   * Optional explicit allow-list of tenant GUIDs (`tid`). Useful for multi-tenant
   * apps that only serve specific customer tenants. Applied in addition to the
   * `tenantId` mode check.
   */
  allowedTenants?: string[];

  /** Accepted token versions. Default: both `"1.0"` and `"2.0"`. */
  acceptedVersions?: TokenVersion[];

  /** Clock skew tolerance for `exp`/`nbf`, in seconds. Default: 60. */
  clockToleranceSec?: number;

  /** Config-driven claim mapping. See {@link ClaimMappingConfig}. */
  claims?: ClaimMappingConfig;

  /** JWKS cache tuning. See {@link JwksConfig}. */
  jwks?: JwksConfig;

  /**
   * Authority host. Default: `"login.microsoftonline.com"`. Override for sovereign
   * clouds (e.g. `"login.microsoftonline.us"`).
   */
  authorityHost?: string;

  /**
   * Issuer host for **v1.0** tokens. Default: `"sts.windows.net"`. Override for
   * sovereign clouds.
   */
  v1IssuerHost?: string;

  /** Injected `fetch` (testing / custom transport). Defaults to global `fetch`. */
  fetch?: FetchLike;

  /** Injected clock (testing). Defaults to the system clock. */
  clock?: Clock;
}

/**
 * Fully-resolved configuration with all defaults applied and values normalized.
 * Internal to the provider; produced by `validateMicrosoftConfig`.
 */
export interface NormalizedMicrosoftConfig {
  readonly clientId: string;
  readonly tenantId: string;
  readonly audiences: readonly string[];
  readonly allowedTenants: readonly string[];
  readonly acceptedVersions: readonly TokenVersion[];
  readonly clockToleranceSec: number;
  readonly claims: ClaimMappingConfig;
  readonly authorityHost: string;
  readonly v1IssuerHost: string;
  readonly jwksUri: string;
  readonly jwksTtlMs: number;
  readonly jwksRefreshIntervalMs: number | undefined;
  readonly fetch: FetchLike;
  readonly clock: Clock;
}
