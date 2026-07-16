import { describe, expect, it } from "vitest";
import { validateGoogleConfig } from "../../src/providers/google/config.js";
import { ConfigurationError } from "../../src/errors/index.js";

const CLIENT_ID = "1234567890-abc.apps.googleusercontent.com";

describe("validateGoogleConfig", () => {
  it("applies defaults when only clientId is given", () => {
    const cfg = validateGoogleConfig({ clientId: CLIENT_ID });
    expect(cfg.audiences).toEqual([CLIENT_ID]);
    expect(cfg.hostedDomains).toEqual([]);
    expect(cfg.clockToleranceSec).toBe(60);
    expect(cfg.jwksTtlMs).toBe(60 * 60 * 1000);
    expect(cfg.jwksRefreshIntervalMs).toBeUndefined();
    expect(cfg.jwksUri).toContain("googleapis.com");
    expect(typeof cfg.fetch).toBe("function");
    expect(cfg.clock).toBeDefined();
  });

  it("rejects a non-object config", () => {
    expect(() => validateGoogleConfig(null as never)).toThrow(ConfigurationError);
    expect(() => validateGoogleConfig(undefined as never)).toThrow(ConfigurationError);
  });

  it("rejects a missing or blank clientId", () => {
    expect(() => validateGoogleConfig({ clientId: "" })).toThrow(ConfigurationError);
    expect(() => validateGoogleConfig({ clientId: "   " })).toThrow(ConfigurationError);
    expect(() => validateGoogleConfig({} as never)).toThrow(ConfigurationError);
  });

  it("normalizes a single audience string to an array", () => {
    const cfg = validateGoogleConfig({ clientId: CLIENT_ID, audience: "web-client" });
    expect(cfg.audiences).toEqual(["web-client"]);
  });

  it("accepts multiple audiences", () => {
    const cfg = validateGoogleConfig({ clientId: CLIENT_ID, audience: ["a", "b"] });
    expect(cfg.audiences).toEqual(["a", "b"]);
  });

  it("rejects an empty audience array", () => {
    expect(() => validateGoogleConfig({ clientId: CLIENT_ID, audience: [] })).toThrow(
      ConfigurationError,
    );
  });

  it("rejects a blank audience entry", () => {
    expect(() => validateGoogleConfig({ clientId: CLIENT_ID, audience: ["ok", "  "] })).toThrow(
      ConfigurationError,
    );
    expect(() =>
      validateGoogleConfig({ clientId: CLIENT_ID, audience: [123 as never] }),
    ).toThrow(ConfigurationError);
  });

  it("rejects a non-array hostedDomains", () => {
    expect(() =>
      validateGoogleConfig({ clientId: CLIENT_ID, hostedDomains: "example.com" as never }),
    ).toThrow(ConfigurationError);
  });

  it("rejects a blank hostedDomains entry", () => {
    expect(() =>
      validateGoogleConfig({ clientId: CLIENT_ID, hostedDomains: ["example.com", ""] }),
    ).toThrow(ConfigurationError);
  });

  it("rejects an invalid clockToleranceSec", () => {
    expect(() =>
      validateGoogleConfig({ clientId: CLIENT_ID, clockToleranceSec: -1 }),
    ).toThrow(ConfigurationError);
    expect(() =>
      validateGoogleConfig({ clientId: CLIENT_ID, clockToleranceSec: Number.NaN }),
    ).toThrow(ConfigurationError);
    expect(() =>
      validateGoogleConfig({ clientId: CLIENT_ID, clockToleranceSec: "60" as never }),
    ).toThrow(ConfigurationError);
  });

  it("rejects a non-positive jwks.ttlMs", () => {
    expect(() =>
      validateGoogleConfig({ clientId: CLIENT_ID, jwks: { ttlMs: 0 } }),
    ).toThrow(ConfigurationError);
    expect(() =>
      validateGoogleConfig({ clientId: CLIENT_ID, jwks: { ttlMs: -5 } }),
    ).toThrow(ConfigurationError);
  });

  it("rejects a non-positive jwks.refreshIntervalMs when provided", () => {
    expect(() =>
      validateGoogleConfig({ clientId: CLIENT_ID, jwks: { refreshIntervalMs: 0 } }),
    ).toThrow(ConfigurationError);
    expect(() =>
      validateGoogleConfig({
        clientId: CLIENT_ID,
        jwks: { refreshIntervalMs: "x" as never },
      }),
    ).toThrow(ConfigurationError);
  });

  it("accepts a valid jwks refresh interval and custom uri", () => {
    const cfg = validateGoogleConfig({
      clientId: CLIENT_ID,
      jwks: { ttlMs: 1000, refreshIntervalMs: 500, uri: "https://jwks.test/keys" },
    });
    expect(cfg.jwksTtlMs).toBe(1000);
    expect(cfg.jwksRefreshIntervalMs).toBe(500);
    expect(cfg.jwksUri).toBe("https://jwks.test/keys");
  });

  it("validates a provided claim mapping", () => {
    const cfg = validateGoogleConfig({
      clientId: CLIENT_ID,
      claims: { email: ["email", "preferred_username"], name: "name" },
    });
    expect(cfg.claims.email).toEqual(["email", "preferred_username"]);
  });

  it("skips undefined claim fields but rejects empty/blank mappings", () => {
    expect(
      validateGoogleConfig({ clientId: CLIENT_ID, claims: { email: undefined } }).claims,
    ).toBeDefined();
    expect(() =>
      validateGoogleConfig({ clientId: CLIENT_ID, claims: { email: [] } }),
    ).toThrow(ConfigurationError);
    expect(() =>
      validateGoogleConfig({ clientId: CLIENT_ID, claims: { name: "  " } }),
    ).toThrow(ConfigurationError);
  });
});
