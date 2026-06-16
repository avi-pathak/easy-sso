import { type AuthProvider } from "../core/auth-provider.js";
import { createAuthContext } from "../core/auth-context.js";
import { MissingTokenError } from "../errors/index.js";
import { extractBearerToken } from "../utils/bearer.js";
import { type MicrosoftAuthConfig } from "../config/types.js";
import { MicrosoftProvider } from "../providers/microsoft/microsoft-provider.js";
import { GoogleProvider } from "../providers/google/google-provider.js";
import { type GoogleAuthConfig } from "../providers/google/config.js";
import { defaultErrorHandler, toAuthError } from "./respond.js";
import { type AuthAwareRequest, type AuthErrorHandler, type RequestHandler } from "./types.js";

/** Options shared by the authentication middleware factories. */
export interface AuthMiddlewareOptions {
  /**
   * When `true`, a request with no bearer token is rejected (401) by this
   * middleware. When `false` (default) the request continues as anonymous and you
   * gate individual routes with {@link requireAuth}. Either way, a *present but
   * invalid* token is always rejected — there is no way to pass an invalid token.
   */
  credentialsRequired?: boolean;
  /** Override how the token is located on the request. Default: `Authorization: Bearer`. */
  tokenExtractor?: (req: AuthAwareRequest) => string | undefined;
  /** Override the error response. Default writes JSON + status + WWW-Authenticate. */
  onError?: AuthErrorHandler;
}

function defaultTokenExtractor(req: AuthAwareRequest): string | undefined {
  return extractBearerToken(req.headers.authorization);
}

/**
 * Build authentication middleware around **any** {@link AuthProvider}.
 *
 * This is the provider-agnostic entry point: pass a Microsoft provider today, a
 * Google/Okta provider tomorrow — the middleware code is identical. It validates
 * a present token, attaches `req.user`, and calls `next()`; on an invalid token
 * it responds via `onError` and does not continue.
 */
export function createAuthMiddleware(
  provider: AuthProvider,
  options: AuthMiddlewareOptions = {},
): RequestHandler {
  const extract = options.tokenExtractor ?? defaultTokenExtractor;
  const onError = options.onError ?? defaultErrorHandler;
  const credentialsRequired = options.credentialsRequired ?? false;

  return (req, res, next): void => {
    const run = async (): Promise<void> => {
      const token = extract(req);
      if (token === undefined) {
        if (credentialsRequired) {
          throw new MissingTokenError();
        }
        next();
        return;
      }
      const context = createAuthContext(req.headers, {
        token,
        ...(req.method !== undefined ? { method: req.method } : {}),
        ...(req.path !== undefined ? { path: req.path } : {}),
      });
      req.user = await provider.authenticate(token, context);
      next();
    };

    run().catch((error: unknown) => {
      onError(toAuthError(error), req, res, next);
    });
  };
}

/**
 * Convenience factory for the Microsoft Entra ID provider.
 *
 * ```ts
 * app.use(microsoftAuth({ clientId: process.env.CLIENT_ID, tenantId: "common" }));
 * ```
 *
 * Equivalent to `createAuthMiddleware(new MicrosoftProvider(config), options)`.
 * Construction validates the config and throws a descriptive `ConfigurationError`
 * immediately on misconfiguration (fail-fast at startup).
 */
export function microsoftAuth(
  config: MicrosoftAuthConfig,
  options?: AuthMiddlewareOptions,
): RequestHandler {
  const provider = new MicrosoftProvider(config);
  return createAuthMiddleware(provider, options);
}

/**
 * Convenience factory for the Google provider.
 *
 * ```ts
 * app.use(googleAuth({ clientId: process.env.GOOGLE_CLIENT_ID }));
 * ```
 *
 * Equivalent to `createAuthMiddleware(new GoogleProvider(config), options)`.
 * Construction validates the config and throws a descriptive `ConfigurationError`
 * immediately on misconfiguration (fail-fast at startup).
 */
export function googleAuth(
  config: GoogleAuthConfig,
  options?: AuthMiddlewareOptions,
): RequestHandler {
  const provider = new GoogleProvider(config);
  return createAuthMiddleware(provider, options);
}
