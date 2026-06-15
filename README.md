# easy-sso

A provider-agnostic Single Sign-On framework, available for **Node.js** and
**Go**. The core knows only an `AuthProvider` interface; **Microsoft Entra ID**
ships as the first provider, and Google / Okta / Auth0 / Keycloak plug in later
with zero public-API changes.

```ts
// Node.js
import { microsoftAuth, requireAuth, requireRole } from "@easy-sso/node";

app.use(microsoftAuth({ clientId: process.env.CLIENT_ID, tenantId: "common" }));
app.get("/profile", requireAuth(), (req, res) => res.json(req.user));
```

```go
// Go
auth, _ := easysso.MicrosoftAuth(easysso.MicrosoftAuthConfig{
	ClientID: os.Getenv("CLIENT_ID"), TenantID: "common",
}, easysso.MiddlewareOptions{})

mux.Handle("/profile", easysso.RequireAuth(nil)(profileHandler))
http.ListenAndServe(":8080", auth(mux))
```

## Monorepo layout

| Path | What |
| --- | --- |
| [`packages/node`](packages/node) | The `@easy-sso/node` package — [full README & API docs](packages/node/README.md). |
| [`packages/go`](packages/go) | The Go module (`easysso`) — dependency-free, [full README & API docs](packages/go/README.md). |
| [`examples/express`](examples/express) | Minimal Express API. |
| [`examples/fastify`](examples/fastify) | The provider-agnostic core used **without** Express. |
| [`examples/multi-tenant`](examples/multi-tenant) | `organizations` mode + tenant allow-list + custom claims. |
| [`docs/adding-a-provider.md`](docs/adding-a-provider.md) | Worked Google provider against the same interface. |

## Develop

```bash
# Node.js
npm install
npm run build      # build @easy-sso/node
npm test           # vitest
npm run lint
npm run typecheck

# Go
cd packages/go
go test ./...
go vet ./...
```

Requires Node 18+ and Go 1.21+. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [packages/node/LICENSE](packages/node/LICENSE).
