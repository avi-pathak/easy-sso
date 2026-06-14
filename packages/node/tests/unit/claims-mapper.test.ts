import { describe, expect, it } from "vitest";
import { mapClaimsToUser } from "../../src/providers/microsoft/claims-mapper.js";
import { validateMicrosoftConfig } from "../../src/config/validate.js";
import { AuthenticationError } from "../../src/errors/index.js";
import { type RawClaims } from "../../src/core/claims.js";
import { CLIENT_ID, TENANT_ID } from "../helpers/crypto.js";

const config = (overrides = {}) =>
  validateMicrosoftConfig({
    clientId: CLIENT_ID,
    tenantId: "common",
    fetch: () => Promise.reject(new Error("unused")),
    ...overrides,
  });

describe("mapClaimsToUser", () => {
  it("maps default Microsoft claims to a normalized user", () => {
    const claims: RawClaims = {
      oid: "user-oid",
      sub: "subject",
      name: "Ada Lovelace",
      preferred_username: "ada@contoso.com",
      tid: TENANT_ID,
      roles: ["admin", "editor"],
      scp: "User.Read Mail.Send",
    };
    const user = mapClaimsToUser(claims, config(), "microsoft");
    expect(user).toMatchObject({
      id: "user-oid",
      name: "Ada Lovelace",
      email: "ada@contoso.com",
      tenantId: TENANT_ID,
      roles: ["admin", "editor"],
      scopes: ["User.Read", "Mail.Send"],
      provider: "microsoft",
    });
    expect(Object.isFrozen(user.claims)).toBe(true);
  });

  it("falls back through the default email source list", () => {
    const user = mapClaimsToUser({ oid: "x", upn: "u@contoso.com" }, config(), "microsoft");
    expect(user.email).toBe("u@contoso.com");
  });

  it("prefers oid then sub for id", () => {
    expect(mapClaimsToUser({ sub: "s" }, config(), "microsoft").id).toBe("s");
    expect(mapClaimsToUser({ oid: "o", sub: "s" }, config(), "microsoft").id).toBe("o");
  });

  it("defaults roles and scopes to empty arrays", () => {
    const user = mapClaimsToUser({ oid: "x" }, config(), "microsoft");
    expect(user.roles).toEqual([]);
    expect(user.scopes).toEqual([]);
    expect(user.email).toBeUndefined();
  });

  it("honors custom claim mapping overrides", () => {
    const user = mapClaimsToUser(
      { custom_id: "cid", mail: "c@x.com", display: "C", groups: ["g1", "g2"] },
      config({
        claims: { id: "custom_id", email: "mail", name: "display", roles: "groups" },
      }),
      "microsoft",
    );
    expect(user).toMatchObject({
      id: "cid",
      email: "c@x.com",
      name: "C",
      roles: ["g1", "g2"],
    });
  });

  it("accepts a space-delimited string for roles via custom mapping", () => {
    const user = mapClaimsToUser(
      { oid: "x", wids: "role-a role-b" },
      config({ claims: { roles: "wids" } }),
      "microsoft",
    );
    expect(user.roles).toEqual(["role-a", "role-b"]);
  });

  it("throws when no usable subject is present", () => {
    expect(() => mapClaimsToUser({ name: "x" }, config(), "microsoft")).toThrow(
      AuthenticationError,
    );
  });
});
