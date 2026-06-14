# easy-sso

A provider-agnostic Single Sign-On framework for Node.js. The core knows only an
`AuthProvider` interface; **Microsoft Entra ID** ships as the first provider, and
Google / Okta / Auth0 / Keycloak plug in later with zero public-API changes.

```ts
import { microsoftAuth, requireAuth, requireRole } from "@easy-sso/node";

app.use(microsoftAuth({ clientId: process.env.CLIENT_ID, tenantId: "common" }));
app.get("/profile", requireAuth(), (req, res) => res.json(req.user));
```

## Monorepo layout

| Path | What |
| --- | --- |
| [`packages/node`](packages/node) | The `@easy-sso/node` package — [full README & API docs](packages/node/README.md). |
| [`examples/express`](examples/express) | Minimal Express API. |
| [`examples/fastify`](examples/fastify) | The provider-agnostic core used **without** Express. |
| [`examples/multi-tenant`](examples/multi-tenant) | `organizations` mode + tenant allow-list + custom claims. |
| [`docs/adding-a-provider.md`](docs/adding-a-provider.md) | Worked Google provider against the same interface. |

## Develop

```bash
npm install
npm run build      # build @easy-sso/node
npm test           # vitest
npm run lint
npm run typecheck
```

Requires Node 18+. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [packages/node/LICENSE](packages/node/LICENSE).
