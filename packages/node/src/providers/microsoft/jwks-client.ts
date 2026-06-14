import { createLocalJWKSet, type JSONWebKeySet, type JWTVerifyGetKey } from "jose";
import { MemoryKeyCache } from "../../cache/memory-key-cache.js";
import { type Clock } from "../../cache/clock.js";
import { type FetchLike } from "../../config/types.js";
import { AuthenticationError } from "../../errors/index.js";

/** Options for {@link MicrosoftJwksClient}. */
export interface MicrosoftJwksClientOptions {
  /** Absolute URL of the JWKS (keys) endpoint. */
  jwksUri: string;
  /** Cache freshness window for the key set, in ms. */
  ttlMs: number;
  /** Optional background-refresh interval, in ms. */
  refreshIntervalMs?: number | undefined;
  /** `fetch` implementation (injected in tests). */
  fetch: FetchLike;
  /** Clock (injected in tests). */
  clock: Clock;
}

/** Narrow an arbitrary JSON value to a {@link JSONWebKeySet}. */
function assertJwks(value: unknown, uri: string): JSONWebKeySet {
  if (
    typeof value !== "object" ||
    value === null ||
    !("keys" in value) ||
    !Array.isArray(value.keys)
  ) {
    throw new AuthenticationError("JWKS endpoint returned a malformed key set", { uri });
  }
  return value as JSONWebKeySet;
}

/**
 * Fetches and caches the Microsoft JWKS, exposing a jose-compatible key resolver
 * for signature verification.
 *
 * Caching, single-flight dedup, TTL, and background refresh are all delegated to
 * {@link MemoryKeyCache} — this class only knows how to *fetch* a JWKS and adapt
 * it into a jose verifier. The local key set is rebuilt per resolver fetch (cheap)
 * so a rotated/refreshed JWKS is picked up immediately.
 */
export class MicrosoftJwksClient {
  private readonly cache: MemoryKeyCache<JSONWebKeySet>;
  private readonly jwksUri: string;

  public constructor(options: MicrosoftJwksClientOptions) {
    this.jwksUri = options.jwksUri;
    const doFetch = options.fetch;
    this.cache = new MemoryKeyCache<JSONWebKeySet>({
      ttlMs: options.ttlMs,
      clock: options.clock,
      ...(options.refreshIntervalMs !== undefined
        ? { refreshIntervalMs: options.refreshIntervalMs }
        : {}),
      loader: async (uri) => {
        let response: { ok: boolean; status: number; json(): Promise<unknown> };
        try {
          response = await doFetch(uri);
        } catch (cause) {
          throw new AuthenticationError("Failed to reach the JWKS endpoint", {
            uri,
            cause: cause instanceof Error ? cause.message : String(cause),
          });
        }
        if (!response.ok) {
          throw new AuthenticationError(`JWKS endpoint responded with HTTP ${response.status}`, {
            uri,
            status: response.status,
          });
        }
        return assertJwks(await response.json(), uri);
      },
    });
  }

  /** Resolve a jose key resolver backed by the cached JWKS (loads on miss). */
  public async getKeyResolver(): Promise<JWTVerifyGetKey> {
    const jwks = await this.cache.get(this.jwksUri);
    return createLocalJWKSet(jwks);
  }

  /** Force a JWKS refresh and return a resolver over the fresh set (key rotation). */
  public async refresh(): Promise<JWTVerifyGetKey> {
    const jwks = await this.cache.refresh(this.jwksUri);
    return createLocalJWKSet(jwks);
  }

  /** Eagerly warm the cache. Safe to call at startup; idempotent under load. */
  public async prime(): Promise<void> {
    await this.cache.get(this.jwksUri);
  }

  /** Release the underlying cache (timers, entries). */
  public dispose(): void {
    this.cache.dispose();
  }
}
