/**
 * A framework-agnostic view of an inbound request, sufficient for a provider to
 * locate and validate credentials.
 *
 * Adapters (Express, Fastify, …) build an `AuthContext` from their native
 * request object. The core and providers depend only on this — never on
 * `express.Request` — which is what keeps the framework HTTP-server-agnostic.
 */
export interface AuthContext {
  /**
   * Lower-cased request headers. Multi-valued headers are preserved as arrays.
   * Providers read e.g. `headers["authorization"]` from here.
   */
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;

  /**
   * The bearer token already extracted from the request, if the adapter chose to
   * do so. When present, providers should prefer it over re-parsing headers.
   */
  readonly token?: string;

  /** Request method, when known. Purely informational for providers. */
  readonly method?: string;

  /** Request path, when known. Purely informational for providers. */
  readonly path?: string;
}

/**
 * Builds a minimal {@link AuthContext} from a header map. Useful for adapters and
 * for tests that need to exercise providers without a real HTTP server.
 */
export function createAuthContext(
  headers: Record<string, string | string[] | undefined>,
  extra: { token?: string; method?: string; path?: string } = {},
): AuthContext {
  const lowerCased: Record<string, string | string[] | undefined> = {};
  for (const [key, value] of Object.entries(headers)) {
    lowerCased[key.toLowerCase()] = value;
  }
  return {
    headers: lowerCased,
    ...(extra.token !== undefined ? { token: extra.token } : {}),
    ...(extra.method !== undefined ? { method: extra.method } : {}),
    ...(extra.path !== undefined ? { path: extra.path } : {}),
  };
}
