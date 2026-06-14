import { describe, expect, it } from "vitest";
import { microsoftAuth } from "../../src/middleware/auth.js";
import { requireAuth } from "../../src/middleware/require-auth.js";
import { requireRole } from "../../src/middleware/require-role.js";
import { createAuthContext } from "../../src/core/auth-context.js";
import { type AuthAwareRequest, type RequestHandler } from "../../src/middleware/types.js";
import { makeRequest, makeResponse, type CapturedResponse } from "../helpers/http.js";
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

/** Run an Express-like chain until one handler responds or the chain ends. */
async function runChain(
  handlers: RequestHandler[],
  req: AuthAwareRequest,
): Promise<{ res: CapturedResponse; reached: boolean }> {
  const res = makeResponse();
  let reached = false;
  let index = 0;

  await new Promise<void>((resolve) => {
    let settled = false;
    const finish = (): void => {
      if (!settled) {
        settled = true;
        resolve();
      }
    };
    const originalJson = res.json.bind(res);
    res.json = (payload: unknown): unknown => {
      const r = originalJson(payload);
      finish();
      return r;
    };
    const next = (err?: unknown): void => {
      if (err !== undefined || index >= handlers.length) {
        reached = err === undefined;
        finish();
        return;
      }
      const handler = handlers[index];
      index += 1;
      handler!(req, res, next);
    };
    next();
  });

  return { res, reached };
}

describe("integration: full auth pipeline", () => {
  async function setup(): Promise<{
    auth: RequestHandler;
    issue: (claims: Record<string, unknown>) => Promise<string>;
  }> {
    const key = await generateSigningKey("kid-int");
    const server = new FakeJwksServer(jwksFor(key));
    const clock = fixedClock();
    const auth = microsoftAuth(testConfig(server.fetch, clock));
    const issue = (claims: Record<string, unknown>): Promise<string> =>
      mintToken({
        privateKey: key.privateKey,
        kid: key.kid,
        issuer: v2Issuer(),
        audience: CLIENT_ID,
        claims: { tid: TENANT_ID, ver: "2.0", ...claims },
      });
    return { auth, issue };
  }

  it("authenticates, authorizes, and reaches a protected route", async () => {
    const { auth, issue } = await setup();
    const token = await issue({ oid: "admin-user", roles: ["admin"] });
    const { res, reached } = await runChain(
      [auth, requireAuth(), requireRole("admin")],
      makeRequest(token),
    );
    expect(reached).toBe(true);
    expect(res.statusCode).toBeUndefined();
  });

  it("blocks an authenticated user lacking the role (403)", async () => {
    const { auth, issue } = await setup();
    const token = await issue({ oid: "plain-user", roles: ["reader"] });
    const { res, reached } = await runChain(
      [auth, requireAuth(), requireRole("admin")],
      makeRequest(token),
    );
    expect(reached).toBe(false);
    expect(res.statusCode).toBe(403);
  });

  it("blocks an anonymous request at requireAuth (401)", async () => {
    const { auth } = await setup();
    const { res, reached } = await runChain([auth, requireAuth()], makeRequest());
    expect(reached).toBe(false);
    expect(res.statusCode).toBe(401);
  });

  it("rejects a tampered token before any route runs", async () => {
    const { auth } = await setup();
    const { res } = await runChain([auth, requireAuth()], makeRequest("tampered.token.value"));
    expect(res.statusCode).toBe(401);
  });
});

describe("createAuthContext", () => {
  it("lowercases header keys and carries optional fields", () => {
    const ctx = createAuthContext(
      { Authorization: "Bearer x", "X-Custom": "y" },
      { token: "x", method: "POST", path: "/p" },
    );
    expect(ctx.headers.authorization).toBe("Bearer x");
    expect(ctx.headers["x-custom"]).toBe("y");
    expect(ctx.token).toBe("x");
    expect(ctx.method).toBe("POST");
    expect(ctx.path).toBe("/p");
  });

  it("omits optional fields when not provided", () => {
    const ctx = createAuthContext({});
    expect(ctx.token).toBeUndefined();
    expect(ctx.method).toBeUndefined();
  });
});
