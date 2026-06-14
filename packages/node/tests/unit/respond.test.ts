import { describe, expect, it, vi } from "vitest";
import { defaultErrorHandler, toAuthError } from "../../src/middleware/respond.js";
import { AuthenticationError, AuthorizationError } from "../../src/errors/index.js";
import { makeRequest, makeResponse } from "../helpers/http.js";

describe("defaultErrorHandler", () => {
  it("writes the JSON body and status", () => {
    const res = makeResponse();
    defaultErrorHandler(new AuthorizationError("nope"), makeRequest(), res, () => undefined);
    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ error: "authorization_error" });
    expect(res.headers["www-authenticate"]).toBeUndefined(); // only on 401
  });

  it("adds a WWW-Authenticate challenge on 401", () => {
    const res = makeResponse();
    defaultErrorHandler(new AuthenticationError("x"), makeRequest(), res, () => undefined);
    expect(res.headers["www-authenticate"]).toContain('Bearer error="authentication_error"');
  });

  it("does nothing if a response was already sent", () => {
    const res = makeResponse();
    res.headersSent = true;
    const status = vi.spyOn(res, "status");
    defaultErrorHandler(new AuthenticationError(), makeRequest(), res, () => undefined);
    expect(status).not.toHaveBeenCalled();
  });
});

describe("toAuthError", () => {
  it("passes framework errors through unchanged", () => {
    const err = new AuthorizationError("keep");
    expect(toAuthError(err)).toBe(err);
  });

  it("wraps a plain Error", () => {
    const wrapped = toAuthError(new Error("boom"));
    expect(wrapped).toBeInstanceOf(AuthenticationError);
    expect(wrapped.details).toMatchObject({ cause: "boom" });
  });

  it("wraps a non-Error throwable", () => {
    const wrapped = toAuthError("string failure");
    expect(wrapped).toBeInstanceOf(AuthenticationError);
    expect(wrapped.details).toMatchObject({ cause: "string failure" });
  });
});
