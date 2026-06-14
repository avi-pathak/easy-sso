import { type AuthAwareRequest, type AuthAwareResponse } from "../../src/middleware/types.js";

export interface CapturedResponse extends AuthAwareResponse {
  statusCode: number | undefined;
  body: unknown;
  headers: Record<string, string>;
}

/** A minimal Express-like response that records what the middleware wrote. */
export function makeResponse(): CapturedResponse {
  const res: CapturedResponse = {
    statusCode: undefined,
    body: undefined,
    headers: {},
    headersSent: false,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(payload: unknown) {
      res.body = payload;
      res.headersSent = true;
      return res;
    },
    setHeader(name: string, value: string) {
      res.headers[name.toLowerCase()] = value;
      return res;
    },
  };
  return res;
}

/** Build a request with a bearer Authorization header (or none). */
export function makeRequest(
  token?: string,
  extra: Partial<AuthAwareRequest> = {},
): AuthAwareRequest {
  return {
    headers: token !== undefined ? { authorization: `Bearer ${token}` } : {},
    method: "GET",
    path: "/",
    ...extra,
  };
}

/**
 * Run a middleware once and resolve when it either calls `next()` or writes a
 * response. Resolution is driven by both signals so async (validation) and sync
 * (guard) middlewares are handled uniformly.
 */
export async function runMiddleware(
  handler: (req: AuthAwareRequest, res: AuthAwareResponse, next: (err?: unknown) => void) => void,
  req: AuthAwareRequest,
): Promise<{ res: CapturedResponse; nextCalled: boolean; nextError: unknown }> {
  const res = makeResponse();
  let nextCalled = false;
  let nextError: unknown = undefined;

  await new Promise<void>((resolve) => {
    let settled = false;
    const done = (): void => {
      if (!settled) {
        settled = true;
        resolve();
      }
    };
    const next = (err?: unknown): void => {
      nextCalled = true;
      nextError = err;
      done();
    };
    const originalJson = res.json.bind(res);
    res.json = (payload: unknown): unknown => {
      const result = originalJson(payload);
      done();
      return result;
    };
    handler(req, res, next);
  });

  return { res, nextCalled, nextError };
}
