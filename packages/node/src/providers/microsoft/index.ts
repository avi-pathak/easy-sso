export { MicrosoftProvider } from "./microsoft-provider.js";
export { MicrosoftTokenValidator } from "./token-validator.js";
export { MicrosoftJwksClient } from "./jwks-client.js";
export type { MicrosoftJwksClientOptions } from "./jwks-client.js";
export { mapClaimsToUser } from "./claims-mapper.js";
export {
  resolveExpectedIssuer,
  assertTenantAllowed,
  isTenantGuid,
  isValidTenantId,
  PERSONAL_MSA_TENANT_ID,
} from "./issuer.js";
