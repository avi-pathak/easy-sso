import { type AuthUser } from "../core/auth-user.js";
import { type AuthError } from "../errors/index.js";

/** Inbound header map as Node/Express present it (lower-cased keys). */
export type IncomingHeaders = Record<string, string | string[] | undefined>;

/**
 * Structural subset of an HTTP request the middleware needs. Express's `Request`
 * (and Fastify's, via a thin adapter) is assignable to this, so the framework
 * never hard-depends on a specific HTTP server. The optional `user` is populated
 * by the auth middleware after successful validation.
 */
export interface AuthAwareRequest {
  headers: IncomingHeaders;
  method?: string | undefined;
  url?: string | undefined;
  originalUrl?: string | undefined;
  path?: string | undefined;
  user?: AuthUser | undefined;
}

/** Structural subset of an HTTP response the middleware needs. */
export interface AuthAwareResponse {
  status(code: number): AuthAwareResponse;
  json(body: unknown): unknown;
  setHeader(name: string, value: string): unknown;
  headersSent?: boolean;
}

/** Express-compatible `next` callback. */
export type NextFunction = (err?: unknown) => void;

/** A middleware/route handler. */
export type RequestHandler = (
  req: AuthAwareRequest,
  res: AuthAwareResponse,
  next: NextFunction,
) => void;

/**
 * Handles an {@link AuthError} produced by the middleware. The default writes a
 * JSON body and the appropriate status; supply your own to forward to an Express
 * error handler (`next(error)`), log, or shape the response differently.
 */
export type AuthErrorHandler = (
  error: AuthError,
  req: AuthAwareRequest,
  res: AuthAwareResponse,
  next: NextFunction,
) => void;
