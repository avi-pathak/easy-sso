# Contributing to easy-sso

Thanks for your interest! This guide covers local setup, the quality bar, and how
releases work.

## Prerequisites

- Node.js **18+**
- npm 10+ (the repo uses npm workspaces)

## Setup

```bash
git clone https://github.com/easy-sso/easy-sso.git
cd easy-sso
npm install
npm run build
```

## Day-to-day

```bash
npm test                  # run the Vitest suite
npm run test:coverage     # enforce coverage thresholds (95% stmts/lines/funcs, 90% branches)
npm run lint              # ESLint (flat config, type-aware)
npm run typecheck         # tsc --noEmit, strict
npm run format            # Prettier
```

Run an example locally:

```bash
CLIENT_ID=<app-id> npm run start --workspace=@easy-sso/example-express
```

## The bar for changes

- **TypeScript strict, zero `any`.** The public surface must stay fully typed.
- **Security defaults are not negotiable.** Never add a switch to disable
  signature/issuer/audience validation; never accept `alg: none`.
- **The core stays provider-agnostic.** Nothing in `src/core` may import from
  `src/providers/*`. Provider-specific logic lives only under that provider's
  folder.
- **Tests required.** New behavior needs tests; mock JWKS with a locally
  generated keypair (see `tests/helpers/crypto.ts`) — never hit live endpoints.
- Keep coverage at or above the configured thresholds.

## Adding a provider

Implement the `AuthProvider` interface; do not change the core or public API. See
[docs/adding-a-provider.md](docs/adding-a-provider.md).

## Commits & releases

We use [Changesets](https://github.com/changesets/changesets) for versioning.

1. Make your change with tests.
2. Add a changeset describing it:

   ```bash
   npm run changeset
   ```

   Pick the affected package and bump type (patch / minor / major) and write a
   user-facing summary.
3. Open a PR. CI runs install → lint → typecheck → test → build.
4. On merge to `main`, the release workflow opens/updates a "Version Packages"
   PR. Merging that publishes to npm with semantic versioning.

## Code of conduct

Be respectful and constructive. Assume good intent.
