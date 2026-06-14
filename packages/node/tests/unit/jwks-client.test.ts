import { describe, expect, it } from "vitest";
import { MicrosoftJwksClient } from "../../src/providers/microsoft/jwks-client.js";
import { AuthenticationError } from "../../src/errors/index.js";
import {
  FakeJwksServer,
  JWKS_URI,
  fixedClock,
  generateSigningKey,
  jwksFor,
} from "../helpers/crypto.js";

describe("MicrosoftJwksClient", () => {
  it("deduplicates concurrent resolver requests into one fetch", async () => {
    const key = await generateSigningKey("kid-1");
    const server = new FakeJwksServer(jwksFor(key));
    const client = new MicrosoftJwksClient({
      jwksUri: JWKS_URI,
      ttlMs: 10_000,
      fetch: server.fetch,
      clock: fixedClock(),
    });
    await Promise.all([client.getKeyResolver(), client.getKeyResolver(), client.getKeyResolver()]);
    expect(server.callCount).toBe(1);
  });

  it("prime() warms the cache once", async () => {
    const key = await generateSigningKey("kid-1");
    const server = new FakeJwksServer(jwksFor(key));
    const client = new MicrosoftJwksClient({
      jwksUri: JWKS_URI,
      ttlMs: 10_000,
      fetch: server.fetch,
      clock: fixedClock(),
    });
    await client.prime();
    await client.getKeyResolver();
    expect(server.callCount).toBe(1);
    client.dispose();
  });

  it("throws on a non-200 response", async () => {
    const server = new FakeJwksServer({ keys: [] });
    server.failNext = 1;
    const client = new MicrosoftJwksClient({
      jwksUri: JWKS_URI,
      ttlMs: 10_000,
      fetch: server.fetch,
      clock: fixedClock(),
    });
    await expect(client.getKeyResolver()).rejects.toBeInstanceOf(AuthenticationError);
  });

  it("throws on a malformed JWKS body", async () => {
    const client = new MicrosoftJwksClient({
      jwksUri: JWKS_URI,
      ttlMs: 10_000,
      fetch: () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) }),
      clock: fixedClock(),
    });
    await expect(client.getKeyResolver()).rejects.toThrow(/malformed/);
  });

  it("wraps a transport-level fetch rejection", async () => {
    const client = new MicrosoftJwksClient({
      jwksUri: JWKS_URI,
      ttlMs: 10_000,
      fetch: () => Promise.reject(new Error("ECONNREFUSED")),
      clock: fixedClock(),
    });
    await expect(client.getKeyResolver()).rejects.toThrow(/reach the JWKS endpoint/);
  });
});
