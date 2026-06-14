import { InvalidIssuerError } from "../../errors/index.js";
import { type NormalizedMicrosoftConfig, type TokenVersion } from "../../config/types.js";

/**
 * The well-known tenant ID for personal Microsoft accounts (MSA / consumers).
 * Used to distinguish work/school (`organizations`) from personal accounts.
 */
export const PERSONAL_MSA_TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad";

/** Special tenant modes that are not GUIDs. */
const TENANT_MODES = new Set(["common", "organizations", "consumers"]);

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Whether `value` looks like a tenant GUID (vs a named mode like `common`). */
export function isTenantGuid(value: string): boolean {
  return GUID_RE.test(value);
}

/** Whether `value` is a valid tenant value (`common`/`organizations`/`consumers`/GUID). */
export function isValidTenantId(value: string): boolean {
  return TENANT_MODES.has(value) || isTenantGuid(value);
}

/**
 * Resolve the **expected** issuer for a token, given the tenant GUID (`tid`) the
 * token actually claims and its version.
 *
 * This is the crux of correct Entra validation: with `common`/`organizations` the
 * issuer is *not* a fixed string — it embeds the real tenant GUID. So we read the
 * (still-unverified) `tid`, compute the issuer it implies, and later assert the
 * cryptographically-verified token carries exactly that issuer.
 *
 *  - v2.0: `https://{authorityHost}/{tid}/v2.0`
 *  - v1.0: `https://{v1IssuerHost}/{tid}/`  (note the trailing slash)
 */
export function resolveExpectedIssuer(
  tid: string,
  version: TokenVersion,
  config: NormalizedMicrosoftConfig,
): string {
  if (version === "2.0") {
    return `https://${config.authorityHost}/${tid}/v2.0`;
  }
  return `https://${config.v1IssuerHost}/${tid}/`;
}

/**
 * Enforce that the token's tenant (`tid`) is acceptable for the configured tenant
 * mode and any explicit allow-list. Throws {@link InvalidIssuerError} otherwise.
 *
 *  - GUID mode  → `tid` must equal the configured tenant.
 *  - consumers  → `tid` must be the personal-MSA tenant.
 *  - organizations → `tid` must NOT be the personal-MSA tenant.
 *  - common     → any tenant is allowed.
 *  - `allowedTenants` (if non-empty) → `tid` must be a member.
 */
export function assertTenantAllowed(tid: string, config: NormalizedMicrosoftConfig): void {
  const configured = config.tenantId;

  if (isTenantGuid(configured)) {
    if (tid.toLowerCase() !== configured.toLowerCase()) {
      throw new InvalidIssuerError(
        `Token tenant '${tid}' does not match the configured tenant '${configured}'`,
        { expected: configured, actual: tid },
      );
    }
  } else if (configured === "consumers") {
    if (tid.toLowerCase() !== PERSONAL_MSA_TENANT_ID) {
      throw new InvalidIssuerError(
        "Configured for personal accounts only, but token is from a work/school tenant",
        { actual: tid },
      );
    }
  } else if (configured === "organizations") {
    if (tid.toLowerCase() === PERSONAL_MSA_TENANT_ID) {
      throw new InvalidIssuerError(
        "Configured for work/school accounts only, but token is from a personal account",
        { actual: tid },
      );
    }
  }
  // `common` imposes no tenant restriction here.

  if (config.allowedTenants.length > 0) {
    const allowed = config.allowedTenants.some((t) => t.toLowerCase() === tid.toLowerCase());
    if (!allowed) {
      throw new InvalidIssuerError(`Token tenant '${tid}' is not in the allowed-tenants list`, {
        actual: tid,
        allowedTenants: config.allowedTenants,
      });
    }
  }
}
