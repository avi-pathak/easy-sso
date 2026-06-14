import { type Clock, systemClock } from "./clock.js";

/** A loader resolves the fresh value for a cache key (e.g. fetch a JWKS). */
export type CacheLoader<V> = (key: string) => Promise<V>;

/** Options for {@link MemoryKeyCache}. */
export interface MemoryKeyCacheOptions<V> {
  /** How long a loaded value stays fresh, in milliseconds. */
  ttlMs: number;
  /** Resolves a fresh value for a key. Invoked at most once per key concurrently. */
  loader: CacheLoader<V>;
  /**
   * If a refresh of an already-cached key fails, keep serving the previous value
   * for up to this many ms past its TTL instead of throwing. Protects against
   * transient JWKS-endpoint blips. Set to `0` to disable. Defaults to `ttlMs`.
   */
  staleIfErrorMs?: number;
  /**
   * When set, a background timer proactively refreshes every live key on this
   * interval so request-path lookups rarely block on the network. The timer is
   * `unref`'d and never keeps the process alive. Call {@link MemoryKeyCache.dispose}
   * to stop it.
   */
  refreshIntervalMs?: number;
  /** Injectable clock for deterministic tests. Defaults to the system clock. */
  clock?: Clock;
  /** Optional hook for observability (e.g. logging a failed background refresh). */
  onError?: (key: string, error: unknown) => void;
}

interface CacheEntry<V> {
  value: V;
  /** Epoch ms after which the value is considered stale and must be refreshed. */
  expiresAt: number;
}

/**
 * An in-memory, per-key TTL cache with **single-flight** load deduplication.
 *
 * Guarantees:
 *  - **Single-flight:** N concurrent `get(key)` calls during a miss trigger the
 *    loader exactly once; all callers await the same in-flight promise.
 *  - **TTL + lazy eviction:** stale entries are reloaded on access; a periodic
 *    sweep and optional background refresh keep memory bounded and values warm.
 *  - **Stale-if-error:** a failed refresh of a previously-good key serves the old
 *    value within a grace window rather than failing open or hard-erroring.
 *
 * It is value-generic so it can cache JWKS key sets, OIDC metadata, etc. The core
 * has no knowledge of what `V` is — keeping this layer provider-agnostic.
 */
export class MemoryKeyCache<V> {
  private readonly entries = new Map<string, CacheEntry<V>>();
  private readonly inFlight = new Map<string, Promise<V>>();
  private readonly ttlMs: number;
  private readonly staleIfErrorMs: number;
  private readonly loader: CacheLoader<V>;
  private readonly clock: Clock;
  private readonly onError: ((key: string, error: unknown) => void) | undefined;
  private refreshTimer: ReturnType<typeof setInterval> | undefined;
  private disposed = false;

  public constructor(options: MemoryKeyCacheOptions<V>) {
    if (options.ttlMs <= 0) {
      throw new RangeError("MemoryKeyCache: ttlMs must be greater than 0");
    }
    this.ttlMs = options.ttlMs;
    this.staleIfErrorMs = options.staleIfErrorMs ?? options.ttlMs;
    this.loader = options.loader;
    this.clock = options.clock ?? systemClock;
    this.onError = options.onError;

    if (options.refreshIntervalMs !== undefined && options.refreshIntervalMs > 0) {
      this.refreshTimer = setInterval(() => {
        void this.refreshAll();
      }, options.refreshIntervalMs);
      // Do not keep the event loop alive solely for cache refreshes.
      this.refreshTimer.unref?.();
    }
  }

  /**
   * Resolve the value for `key`, loading it if absent or stale. Concurrent calls
   * for the same key share a single load (single-flight).
   */
  public async get(key: string): Promise<V> {
    this.assertNotDisposed();
    const entry = this.entries.get(key);
    if (entry !== undefined && !this.isExpired(entry)) {
      return entry.value;
    }
    return this.load(key);
  }

  /**
   * Force a reload of `key`, bypassing the freshness check but still
   * deduplicating with any in-flight load. Returns the fresh value.
   */
  public async refresh(key: string): Promise<V> {
    this.assertNotDisposed();
    return this.load(key, { force: true });
  }

  /** Return the cached value without loading. `undefined` if absent or expired. */
  public peek(key: string): V | undefined {
    const entry = this.entries.get(key);
    if (entry === undefined || this.isExpired(entry)) {
      return undefined;
    }
    return entry.value;
  }

  /** Whether a fresh (non-expired) entry exists for `key`. */
  public has(key: string): boolean {
    return this.peek(key) !== undefined;
  }

  /** Remove a single key's cached value. */
  public delete(key: string): void {
    this.entries.delete(key);
  }

  /** Remove every cached value. In-flight loads are left to settle. */
  public clear(): void {
    this.entries.clear();
  }

  /** Number of entries currently held (including expired-but-not-swept). */
  public size(): number {
    return this.entries.size;
  }

  /** Sweep and drop every expired entry. Returns the count removed. */
  public evictExpired(): number {
    let removed = 0;
    for (const [key, entry] of this.entries) {
      if (this.isExpired(entry)) {
        this.entries.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  /** Stop the background refresh timer and drop all state. Idempotent. */
  public dispose(): void {
    this.disposed = true;
    if (this.refreshTimer !== undefined) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = undefined;
    }
    this.entries.clear();
    this.inFlight.clear();
  }

  // --- internals -----------------------------------------------------------

  private isExpired(entry: CacheEntry<V>): boolean {
    return this.clock.now() >= entry.expiresAt;
  }

  /**
   * The single-flight core. If a load for `key` is already running, return that
   * promise; otherwise start one, register it, and clean up on settle.
   */
  private load(key: string, opts: { force?: boolean } = {}): Promise<V> {
    const existing = this.inFlight.get(key);
    if (existing !== undefined) {
      return existing;
    }

    // Re-check freshness for non-forced loads: a value may have been populated
    // between the caller's `get` check and acquiring the single-flight slot.
    if (opts.force !== true) {
      const entry = this.entries.get(key);
      if (entry !== undefined && !this.isExpired(entry)) {
        return Promise.resolve(entry.value);
      }
    }

    const promise = this.loader(key)
      .then((value) => {
        this.entries.set(key, { value, expiresAt: this.clock.now() + this.ttlMs });
        return value;
      })
      .catch((error: unknown) => {
        // Stale-if-error: if we still hold a value within the grace window, serve
        // it rather than propagating a transient loader failure.
        const stale = this.entries.get(key);
        if (stale !== undefined && this.clock.now() < stale.expiresAt + this.staleIfErrorMs) {
          this.onError?.(key, error);
          return stale.value;
        }
        throw error;
      })
      .finally(() => {
        this.inFlight.delete(key);
      });

    this.inFlight.set(key, promise);
    return promise;
  }

  /** Background-refresh every currently-tracked key, swallowing per-key errors. */
  private async refreshAll(): Promise<void> {
    const keys = [...this.entries.keys()];
    await Promise.all(
      keys.map((key) =>
        this.refresh(key).catch((error: unknown) => {
          this.onError?.(key, error);
        }),
      ),
    );
  }

  private assertNotDisposed(): void {
    if (this.disposed) {
      throw new Error("MemoryKeyCache: cache has been disposed");
    }
  }
}
