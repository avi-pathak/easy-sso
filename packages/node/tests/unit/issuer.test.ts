import { describe, expect, it } from "vitest";
import {
  assertTenantAllowed,
  isTenantGuid,
  isValidTenantId,
  PERSONAL_MSA_TENANT_ID,
  resolveExpectedIssuer,
} from "../../src/providers/microsoft/issuer.js";
import { validateMicrosoftConfig } from "../../src/config/validate.js";
import { InvalidIssuerError } from "../../src/errors/index.js";
import { CLIENT_ID, TENANT_ID, OTHER_TENANT_ID } from "../helpers/crypto.js";

const baseConfig = (tenantId: string, allowedTenants?: string[]) =>
  validateMicrosoftConfig({
    clientId: CLIENT_ID,
    tenantId,
    ...(allowedTenants ? { allowedTenants } : {}),
    fetch: () => Promise.reject(new Error("unused")),
  });

describe("tenant id helpers", () => {
  it("recognizes GUIDs", () => {
    expect(isTenantGuid(TENANT_ID)).toBe(true);
    expect(isTenantGuid("common")).toBe(false);
  });

  it("validates named modes and GUIDs", () => {
    for (const mode of ["common", "organizations", "consumers", TENANT_ID]) {
      expect(isValidTenantId(mode)).toBe(true);
    }
    expect(isValidTenantId("nonsense")).toBe(false);
  });
});

describe("resolveExpectedIssuer", () => {
  it("builds the v2 issuer from the real tenant id", () => {
    expect(resolveExpectedIssuer(TENANT_ID, "2.0", baseConfig("common"))).toBe(
      `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
    );
  });

  it("builds the v1 issuer with trailing slash", () => {
    expect(resolveExpectedIssuer(TENANT_ID, "1.0", baseConfig("common"))).toBe(
      `https://sts.windows.net/${TENANT_ID}/`,
    );
  });
});

describe("assertTenantAllowed", () => {
  it("allows any tenant under 'common'", () => {
    expect(() => assertTenantAllowed(OTHER_TENANT_ID, baseConfig("common"))).not.toThrow();
  });

  it("requires an exact match under a GUID tenant", () => {
    expect(() => assertTenantAllowed(TENANT_ID, baseConfig(TENANT_ID))).not.toThrow();
    expect(() => assertTenantAllowed(OTHER_TENANT_ID, baseConfig(TENANT_ID))).toThrow(
      InvalidIssuerError,
    );
  });

  it("rejects personal accounts under 'organizations'", () => {
    expect(() => assertTenantAllowed(TENANT_ID, baseConfig("organizations"))).not.toThrow();
    expect(() => assertTenantAllowed(PERSONAL_MSA_TENANT_ID, baseConfig("organizations"))).toThrow(
      InvalidIssuerError,
    );
  });

  it("requires the MSA tenant under 'consumers'", () => {
    expect(() =>
      assertTenantAllowed(PERSONAL_MSA_TENANT_ID, baseConfig("consumers")),
    ).not.toThrow();
    expect(() => assertTenantAllowed(TENANT_ID, baseConfig("consumers"))).toThrow(
      InvalidIssuerError,
    );
  });

  it("enforces an explicit allow-list on top of the mode", () => {
    const config = baseConfig("common", [TENANT_ID]);
    expect(() => assertTenantAllowed(TENANT_ID, config)).not.toThrow();
    expect(() => assertTenantAllowed(OTHER_TENANT_ID, config)).toThrow(InvalidIssuerError);
  });
});
