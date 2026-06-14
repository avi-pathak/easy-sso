# @easy-sso/node

All notable changes to this package are documented here. This file is maintained
by [Changesets](https://github.com/changesets/changesets); entries below the
"Unreleased" heading are generated at release time.

## Unreleased

### Minor Changes

- Initial release of `@easy-sso/node`: a provider-agnostic SSO framework for
  Node.js with Microsoft Entra ID as the first provider.
  - Core abstractions: `AuthProvider`, `AuthUser`, `AuthContext` (no provider
    logic in core).
  - Microsoft Entra ID provider with dynamic issuer resolution
    (`common` / `organizations` / `consumers` / tenant GUID), v1.0 & v2.0 token
    support, and RS256-pinned signature verification.
  - JWKS layer: `MemoryKeyCache` with TTL, background refresh, expired-key
    eviction, key-rotation retry, and single-flight concurrent-request dedup.
  - Express middleware: `microsoftAuth`, `createAuthMiddleware`, `requireAuth`,
    `requireRole`, `requireRoles`, plus a typed `req.user` augmentation.
  - Fail-fast config validation and config-driven custom claim mapping.
  - Typed error hierarchy with `code` / `message` / `statusCode` / `toJSON()`.
  - Dual ESM + CJS builds with emitted `.d.ts`.
