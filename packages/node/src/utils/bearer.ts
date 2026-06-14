/**
 * Extract a bearer token from an `Authorization` header value.
 *
 * Accepts the raw header (string, or array as Node may present duplicates) and
 * returns the token sans the `Bearer ` scheme, or `undefined` when absent/empty/
 * not a bearer credential. Scheme matching is case-insensitive per RFC 6750.
 */
export function extractBearerToken(header: string | string[] | undefined): string | undefined {
  const value = Array.isArray(header) ? header[0] : header;
  if (typeof value !== "string") {
    return undefined;
  }
  const match = /^Bearer\s+(.+)$/i.exec(value.trim());
  if (match === null) {
    return undefined;
  }
  const token = match[1]?.trim();
  return token !== undefined && token.length > 0 ? token : undefined;
}
