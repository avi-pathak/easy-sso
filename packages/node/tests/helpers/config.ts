import { type MicrosoftAuthConfig } from "../../src/config/types.js";
import { type Clock } from "../../src/cache/clock.js";
import { type FetchLike } from "../../src/config/types.js";
import { CLIENT_ID, JWKS_URI, TENANT_ID } from "./crypto.js";

/** Build a test config wired to an injected fetch + clock and the fake JWKS URI. */
export function testConfig(
  fetch: FetchLike,
  clock: Clock,
  overrides: Partial<MicrosoftAuthConfig> = {},
): MicrosoftAuthConfig {
  return {
    clientId: CLIENT_ID,
    tenantId: TENANT_ID,
    fetch,
    clock,
    jwks: { uri: JWKS_URI },
    ...overrides,
  };
}
