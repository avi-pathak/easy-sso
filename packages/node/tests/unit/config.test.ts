import { describe, expect, it } from "vitest";
import { validateMicrosoftConfig } from "../../src/config/validate.js";
import { ConfigurationError } from "../../src/errors/index.js";
import { CLIENT_ID, TENANT_ID } from "../helpers/crypto.js";

const noopFetch = () => Promise.reject(new Error("unused"));
const ok = (overrides = {}) =>
  validateMicrosoftConfig({ clientId: CLIENT_ID, fetch: noopFetch, ...overrides });

describe("validateMicrosoftConfig", () => {
  it("applies sensible defaults", () => {
    const c = ok();
    expect(c.tenantId).toBe("common");
    expect(c.audiences).toEqual([CLIENT_ID, `api://${CLIENT_ID}`]);
    expect(c.acceptedVersions).toEqual(["1.0", "2.0"]);
    expect(c.clockToleranceSec).toBe(60);
    expect(c.authorityHost).toBe("login.microsoftonline.com");
    expect(c.v1IssuerHost).toBe("sts.windows.net");
    expect(c.jwksUri).toBe(`https://login.microsoftonline.com/common/discovery/v2.0/keys`);
    expect(c.jwksTtlMs).toBe(3_600_000);
    expect(c.jwksRefreshIntervalMs).toBeUndefined();
  });

  it.each([undefined, "", "   ", 42])("rejects an invalid clientId: %s", (clientId) => {
    expect(() =>
      validateMicrosoftConfig({ clientId: clientId as string, fetch: noopFetch }),
    ).toThrow(ConfigurationError);
  });

  it("rejects an invalid tenantId with a descriptive message", () => {
    expect(() => ok({ tenantId: "not-a-tenant" })).toThrow(/tenantId/);
  });

  it("accepts all valid tenant modes and GUIDs", () => {
    for (const tenantId of ["common", "organizations", "consumers", TENANT_ID]) {
      expect(ok({ tenantId }).tenantId).toBe(tenantId);
    }
  });

  it("normalizes a single audience to an array", () => {
    expect(ok({ audience: "custom-aud" }).audiences).toEqual(["custom-aud"]);
    expect(ok({ audience: ["a", "b"] }).audiences).toEqual(["a", "b"]);
  });

  it("rejects an empty or malformed audience", () => {
    expect(() => ok({ audience: [] })).toThrow(ConfigurationError);
    expect(() => ok({ audience: [""] })).toThrow(ConfigurationError);
  });

  it("validates allowedTenants are GUIDs", () => {
    expect(ok({ allowedTenants: [TENANT_ID] }).allowedTenants).toEqual([TENANT_ID]);
    expect(() => ok({ allowedTenants: ["nope"] })).toThrow(ConfigurationError);
    expect(() => ok({ allowedTenants: "x" as unknown as string[] })).toThrow(ConfigurationError);
  });

  it("validates acceptedVersions", () => {
    expect(ok({ acceptedVersions: ["2.0"] }).acceptedVersions).toEqual(["2.0"]);
    expect(() => ok({ acceptedVersions: [] })).toThrow(ConfigurationError);
    expect(() => ok({ acceptedVersions: ["3.0"] as unknown as ("1.0" | "2.0")[] })).toThrow(
      ConfigurationError,
    );
  });

  it("validates clockToleranceSec", () => {
    expect(ok({ clockToleranceSec: 0 }).clockToleranceSec).toBe(0);
    expect(() => ok({ clockToleranceSec: -1 })).toThrow(ConfigurationError);
    expect(() => ok({ clockToleranceSec: Number.NaN })).toThrow(ConfigurationError);
  });

  it("validates claim mappings", () => {
    expect(ok({ claims: { email: ["mail", "upn"] } }).claims.email).toEqual(["mail", "upn"]);
    expect(() => ok({ claims: { email: [] } })).toThrow(ConfigurationError);
    expect(() => ok({ claims: { email: "" } })).toThrow(ConfigurationError);
  });

  it("validates and normalizes jwks options", () => {
    const c = ok({ jwks: { ttlMs: 1000, refreshIntervalMs: 500, uri: "https://x/keys" } });
    expect(c.jwksTtlMs).toBe(1000);
    expect(c.jwksRefreshIntervalMs).toBe(500);
    expect(c.jwksUri).toBe("https://x/keys");
    expect(() => ok({ jwks: { ttlMs: 0 } })).toThrow(ConfigurationError);
    expect(() => ok({ jwks: { refreshIntervalMs: -5 } })).toThrow(ConfigurationError);
  });

  it("normalizes authority hosts by stripping protocol and trailing slash", () => {
    const c = ok({ authorityHost: "https://login.microsoftonline.us/" });
    expect(c.authorityHost).toBe("login.microsoftonline.us");
    expect(c.jwksUri).toContain("login.microsoftonline.us");
  });

  it("computes the jwks uri from a GUID tenant", () => {
    expect(ok({ tenantId: TENANT_ID }).jwksUri).toBe(
      `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`,
    );
  });

  it("rejects a non-object config", () => {
    expect(() => validateMicrosoftConfig(null as unknown as { clientId: string })).toThrow(
      ConfigurationError,
    );
  });

  it("defaults to the global fetch when none is injected", () => {
    const c = validateMicrosoftConfig({ clientId: CLIENT_ID });
    expect(typeof c.fetch).toBe("function");
  });

  it("fails when no fetch is available (Node < 18 simulation)", () => {
    const original = globalThis.fetch;
    // @ts-expect-error — intentionally remove fetch to simulate old runtimes.
    delete globalThis.fetch;
    try {
      expect(() => validateMicrosoftConfig({ clientId: CLIENT_ID })).toThrow(/fetch/);
    } finally {
      globalThis.fetch = original;
    }
  });
});
