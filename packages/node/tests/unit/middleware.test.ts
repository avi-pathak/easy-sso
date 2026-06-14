import { beforeEach, describe, expect, it } from "vitest";
import { createAuthMiddleware, microsoftAuth } from "../../src/middleware/auth.js";
import { requireAuth } from "../../src/middleware/require-auth.js";
import { requireRole, requireRoles } from "../../src/middleware/require-role.js";
import { ConfigurationError } from "../../src/errors/index.js";
import { type AuthProvider } from "../../src/core/auth-provider.js";
import { type AuthUser } from "../../src/core/auth-user.js";
import { makeRequest, runMiddleware } from "../helpers/http.js";
import {
  CLIENT_ID,
  FakeJwksServer,
  TENANT_ID,
  fixedClock,
  generateSigningKey,
  jwksFor,
  mintToken,
  v2Issuer,
} from "../helpers/crypto.js";
import { testConfig } from "../helpers/config.js";

const user: AuthUser = {
  id: "u1",
  roles: ["admin", "editor"],
  scopes: [],
  provider: "fake",
  claims: {},
};

/** A trivial provider that accepts the token "good" and rejects everything else. */
const fakeProvider: AuthProvider = {
  name: "fake",
  authenticate: (token) => {
    if (token === "good") return Promise.resolve(user);
    return Promise.reject(new Error("bad token"));
  },
};

describe("createAuthMiddleware", () => {
  it("attaches req.user for a valid token and calls next()", async () => {
    const mw = createAuthMiddleware(fakeProvider);
    const req = makeRequest("good");
    const { nextCalled, res } = await runMiddleware(mw, req);
    expect(nextCalled).toBe(true);
    expect(req.user).toEqual(user);
    expect(res.statusCode).toBeUndefined();
  });

  it("continues as anonymous when no token is present (default)", async () => {
    const mw = createAuthMiddleware(fakeProvider);
    const req = makeRequest();
    const { nextCalled } = await runMiddleware(mw, req);
    expect(nextCalled).toBe(true);
    expect(req.user).toBeUndefined();
  });

  it("rejects a missing token when credentialsRequired is set", async () => {
    const mw = createAuthMiddleware(fakeProvider, { credentialsRequired: true });
    const { res, nextCalled } = await runMiddleware(mw, makeRequest());
    expect(nextCalled).toBe(false);
    expect(res.statusCode).toBe(401);
    expect(res.body).toMatchObject({ error: "missing_token" });
    expect(res.headers["www-authenticate"]).toContain("Bearer");
  });

  it("rejects a present-but-invalid token with 401", async () => {
    const mw = createAuthMiddleware(fakeProvider);
    const { res, nextCalled } = await runMiddleware(mw, makeRequest("bad"));
    expect(nextCalled).toBe(false);
    expect(res.statusCode).toBe(401);
    expect(res.body).toMatchObject({ error: "authentication_error" });
  });

  it("supports a custom tokenExtractor", async () => {
    const mw = createAuthMiddleware(fakeProvider, {
      tokenExtractor: (req) => (req.headers["x-token"] as string | undefined) ?? undefined,
    });
    const req = makeRequest(undefined, { headers: { "x-token": "good" } });
    const { nextCalled } = await runMiddleware(mw, req);
    expect(nextCalled).toBe(true);
    expect(req.user).toEqual(user);
  });

  it("supports a custom onError handler", async () => {
    let forwarded: unknown;
    const mw = createAuthMiddleware(fakeProvider, {
      onError: (err, _req, _res, next) => {
        forwarded = err;
        next(err);
      },
    });
    const { nextCalled, nextError } = await runMiddleware(mw, makeRequest("bad"));
    expect(nextCalled).toBe(true);
    expect(nextError).toBe(forwarded);
  });
});

describe("microsoftAuth (integration with real validation)", () => {
  it("validates a real token end to end", async () => {
    const key = await generateSigningKey("kid-1");
    const server = new FakeJwksServer(jwksFor(key));
    const clock = fixedClock();
    const mw = microsoftAuth(testConfig(server.fetch, clock));
    const token = await mintToken({
      privateKey: key.privateKey,
      kid: key.kid,
      issuer: v2Issuer(),
      audience: CLIENT_ID,
      claims: { tid: TENANT_ID, ver: "2.0", oid: "real-user", roles: ["reader"] },
    });
    const req = makeRequest(token);
    const { nextCalled } = await runMiddleware(mw, req);
    expect(nextCalled).toBe(true);
    expect(req.user).toMatchObject({ id: "real-user", roles: ["reader"], provider: "microsoft" });
  });

  it("throws a ConfigurationError at construction for a bad config", () => {
    expect(() => microsoftAuth({ clientId: "" })).toThrow(ConfigurationError);
  });
});

describe("requireAuth", () => {
  let authed = makeRequest();
  beforeEach(() => {
    authed = makeRequest();
    authed.user = user;
  });

  it("passes when a user is present", async () => {
    const { nextCalled, res } = await runMiddleware(requireAuth(), authed);
    expect(nextCalled).toBe(true);
    expect(res.statusCode).toBeUndefined();
  });

  it("responds 401 when no user is present", async () => {
    const { nextCalled, res } = await runMiddleware(requireAuth(), makeRequest());
    expect(nextCalled).toBe(false);
    expect(res.statusCode).toBe(401);
    expect(res.body).toMatchObject({ error: "authentication_error" });
  });
});

describe("requireRole / requireRoles", () => {
  const authed = (): ReturnType<typeof makeRequest> => {
    const req = makeRequest();
    req.user = user; // roles: admin, editor
    return req;
  };

  it("allows a user holding the required role", async () => {
    const { nextCalled } = await runMiddleware(requireRole("admin"), authed());
    expect(nextCalled).toBe(true);
  });

  it("responds 403 when the role is missing", async () => {
    const { nextCalled, res } = await runMiddleware(requireRole("superuser"), authed());
    expect(nextCalled).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ error: "authorization_error" });
  });

  it("responds 401 when unauthenticated", async () => {
    const { res } = await runMiddleware(requireRole("admin"), makeRequest());
    expect(res.statusCode).toBe(401);
  });

  it("requireRoles defaults to ANY match", async () => {
    const { nextCalled } = await runMiddleware(requireRoles(["admin", "nope"]), authed());
    expect(nextCalled).toBe(true);
  });

  it("requireRoles with mode 'all' requires every role", async () => {
    const pass = await runMiddleware(requireRoles(["admin", "editor"], { mode: "all" }), authed());
    expect(pass.nextCalled).toBe(true);
    const fail = await runMiddleware(
      requireRoles(["admin", "superuser"], { mode: "all" }),
      authed(),
    );
    expect(fail.nextCalled).toBe(false);
    expect(fail.res.statusCode).toBe(403);
  });

  it("throws if constructed with no roles", () => {
    expect(() => requireRoles([])).toThrow(ConfigurationError);
  });
});
