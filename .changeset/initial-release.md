---
"@easy-sso/node": minor
---

Initial release of `@easy-sso/node`: a provider-agnostic SSO framework for Node.js
with Microsoft Entra ID as the first provider. Includes JWKS caching with
single-flight protection, full token validation (signature, issuer, audience,
exp, nbf, token version), Express middleware (`requireAuth`, `requireRole`,
`requireRoles`), config-driven claim mapping, and fail-fast config validation.
