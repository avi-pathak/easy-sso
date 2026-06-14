import { describe, expect, it, vi } from "vitest";
import { MemoryKeyCache } from "../../src/cache/memory-key-cache.js";
import { fixedClock } from "../helpers/crypto.js";

describe("MemoryKeyCache", () => {
  it("rejects a non-positive ttl", () => {
    expect(() => new MemoryKeyCache({ ttlMs: 0, loader: () => Promise.resolve(1) })).toThrow(
      RangeError,
    );
  });

  it("loads on miss and serves from cache on hit (single load)", async () => {
    const loader = vi.fn((key: string) => Promise.resolve(`value:${key}`));
    const cache = new MemoryKeyCache<string>({ ttlMs: 1000, loader, clock: fixedClock() });

    expect(await cache.get("a")).toBe("value:a");
    expect(await cache.get("a")).toBe("value:a");
    expect(loader).toHaveBeenCalledTimes(1);
  });

  it("deduplicates concurrent misses into a single load (single-flight)", async () => {
    let resolveLoad!: (v: string) => void;
    const loader = vi.fn(
      () =>
        new Promise<string>((resolve) => {
          resolveLoad = resolve;
        }),
    );
    const cache = new MemoryKeyCache<string>({ ttlMs: 1000, loader, clock: fixedClock() });

    const p1 = cache.get("k");
    const p2 = cache.get("k");
    const p3 = cache.get("k");
    resolveLoad("loaded");

    expect(await Promise.all([p1, p2, p3])).toEqual(["loaded", "loaded", "loaded"]);
    expect(loader).toHaveBeenCalledTimes(1);
  });

  it("reloads after the ttl expires", async () => {
    const clock = fixedClock(0);
    const loader = vi.fn((key: string) => Promise.resolve(`${key}@${clock.now()}`));
    const cache = new MemoryKeyCache<string>({ ttlMs: 100, loader, clock });

    expect(await cache.get("k")).toBe("k@0");
    clock.set(50);
    expect(await cache.get("k")).toBe("k@0"); // still fresh
    clock.set(150);
    expect(await cache.get("k")).toBe("k@150"); // expired -> reload
    expect(loader).toHaveBeenCalledTimes(2);
  });

  it("refresh() forces a reload even when fresh", async () => {
    const clock = fixedClock(0);
    let counter = 0;
    const loader = vi.fn(() => Promise.resolve(++counter));
    const cache = new MemoryKeyCache<number>({ ttlMs: 10_000, loader, clock });

    expect(await cache.get("k")).toBe(1);
    expect(await cache.refresh("k")).toBe(2);
    expect(await cache.get("k")).toBe(2);
  });

  it("peek/has/size/delete/clear/evictExpired behave correctly", async () => {
    const clock = fixedClock(0);
    const cache = new MemoryKeyCache<string>({
      ttlMs: 100,
      loader: (k) => Promise.resolve(k),
      clock,
    });

    expect(cache.peek("k")).toBeUndefined();
    expect(cache.has("k")).toBe(false);
    await cache.get("k");
    expect(cache.peek("k")).toBe("k");
    expect(cache.has("k")).toBe(true);
    expect(cache.size()).toBe(1);

    clock.set(200);
    expect(cache.peek("k")).toBeUndefined();
    expect(cache.evictExpired()).toBe(1);
    expect(cache.size()).toBe(0);

    await cache.get("x");
    cache.delete("x");
    expect(cache.size()).toBe(0);
    await cache.get("y");
    cache.clear();
    expect(cache.size()).toBe(0);
  });

  it("serves a stale value when a refresh fails within the grace window", async () => {
    const clock = fixedClock(0);
    let attempt = 0;
    const loader = vi.fn(() => {
      attempt += 1;
      if (attempt === 1) return Promise.resolve("good");
      return Promise.reject(new Error("boom"));
    });
    const cache = new MemoryKeyCache<string>({
      ttlMs: 100,
      staleIfErrorMs: 1000,
      loader,
      clock,
    });

    expect(await cache.get("k")).toBe("good");
    clock.set(150); // expired, but within stale window
    expect(await cache.get("k")).toBe("good"); // refresh fails -> stale served
  });

  it("propagates the error when no stale value exists", async () => {
    const cache = new MemoryKeyCache<string>({
      ttlMs: 100,
      loader: () => Promise.reject(new Error("cold-miss")),
      clock: fixedClock(),
    });
    await expect(cache.get("k")).rejects.toThrow("cold-miss");
  });

  it("propagates the error once the stale grace window has passed", async () => {
    const clock = fixedClock(0);
    let attempt = 0;
    const loader = vi.fn(() => {
      attempt += 1;
      if (attempt === 1) return Promise.resolve("good");
      return Promise.reject(new Error("boom"));
    });
    const cache = new MemoryKeyCache<string>({ ttlMs: 100, staleIfErrorMs: 50, loader, clock });

    expect(await cache.get("k")).toBe("good");
    clock.set(1000); // well past ttl + staleIfErrorMs
    await expect(cache.get("k")).rejects.toThrow("boom");
  });

  it("invokes onError when serving stale on refresh failure", async () => {
    const clock = fixedClock(0);
    let attempt = 0;
    const onError = vi.fn();
    const cache = new MemoryKeyCache<string>({
      ttlMs: 100,
      staleIfErrorMs: 1000,
      onError,
      clock,
      loader: () => {
        attempt += 1;
        return attempt === 1 ? Promise.resolve("good") : Promise.reject(new Error("x"));
      },
    });
    await cache.get("k");
    clock.set(150);
    await cache.get("k");
    expect(onError).toHaveBeenCalledOnce();
  });

  it("throws after dispose()", async () => {
    const cache = new MemoryKeyCache<number>({
      ttlMs: 100,
      loader: () => Promise.resolve(1),
      clock: fixedClock(),
    });
    await cache.get("k");
    cache.dispose();
    expect(cache.size()).toBe(0);
    await expect(cache.get("k")).rejects.toThrow(/disposed/);
    cache.dispose(); // idempotent
  });

  it("runs the background refresh timer when configured", async () => {
    vi.useFakeTimers();
    try {
      let counter = 0;
      const loader = vi.fn(() => Promise.resolve(++counter));
      // Real Date-based clock so the refreshed value is considered fresh.
      const cache = new MemoryKeyCache<number>({
        ttlMs: 10_000,
        refreshIntervalMs: 1000,
        loader,
      });
      await cache.get("k");
      expect(loader).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1000);
      expect(loader).toHaveBeenCalledTimes(2);
      cache.dispose();
    } finally {
      vi.useRealTimers();
    }
  });
});
