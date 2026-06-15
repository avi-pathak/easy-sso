# easy-sso for Go

A provider-agnostic Single Sign-On framework for Go. The core knows only an
`AuthProvider` interface; **Microsoft Entra ID** ships as the first provider, and
Google / Okta / Auth0 / Keycloak plug in later with zero public-API changes.

It is **dependency-free** — token decoding, RS256 signature verification, JWKS
fetching/caching, and claim validation are implemented against the Go standard
library only.

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	easysso "github.com/avi-pathak/easy-sso/packages/go"
)

func main() {
	auth, err := easysso.MicrosoftAuth(easysso.MicrosoftAuthConfig{
		ClientID: os.Getenv("CLIENT_ID"),
		TenantID: "common",
	}, easysso.MiddlewareOptions{})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/profile", easysso.RequireAuth(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := easysso.UserFromContext(r.Context())
		_ = json.NewEncoder(w).Encode(user)
	})))

	log.Fatal(http.ListenAndServe(":8080", auth(mux)))
}
```

## Install

```bash
go get github.com/avi-pathak/easy-sso/packages/go
```

Requires Go 1.21+.

## What it validates

Every token is checked end-to-end before a user is resolved:

- **Signature** against the issuer's JWKS, **RS256 only** (`alg: none` and
  algorithm-confusion attacks are rejected by construction).
- **Issuer** — resolved per token from the verified tenant (`tid`) and version,
  so `common` / `organizations` are handled correctly.
- **Audience** (`aud`), **expiry** (`exp`), **not-before** (`nbf`) with
  configurable clock tolerance.
- **Tenant policy** — GUID / `organizations` / `consumers` / `common` modes plus
  an optional allow-list.
- **Token version** — `1.0` / `2.0`, configurable.

JWKS keys are cached with a single-flight loader, TTL, stale-if-error fallback,
and optional background refresh, so the request path rarely blocks on the network
and key rotation is picked up automatically.

## Packages

| Import | What |
| --- | --- |
| `…/packages/go` | `easysso` — aggregator re-exporting the common API. |
| `…/packages/go/core` | `AuthProvider`, `AuthUser`, `AuthContext`, `Claims`. |
| `…/packages/go/ssoerr` | `AuthError` + stable error codes / HTTP status mapping. |
| `…/packages/go/cache` | Generic single-flight TTL cache + `Clock`. |
| `…/packages/go/config` | `MicrosoftAuthConfig` + validation. |
| `…/packages/go/provider/microsoft` | The Microsoft Entra ID provider. |
| `…/packages/go/middleware` | `net/http` middleware: auth, `RequireAuth`, `RequireRole(s)`. |

## API highlights

```go
// Build a provider directly (e.g. to reuse across servers, or to call Initialize).
p, err := microsoft.NewProvider(config.MicrosoftAuthConfig{ClientID: id})
_ = p.Initialize(ctx) // optional: warm the JWKS cache at startup
mw := middleware.New(p, middleware.Options{})

// Gating
easysso.RequireAuth(nil)
easysso.RequireRole("admin", nil)
easysso.RequireRoles([]string{"a", "b"}, easysso.MatchAll, nil)

// Read the user in a handler
user, ok := easysso.UserFromContext(r.Context())
```

`MiddlewareOptions` lets you set `CredentialsRequired`, a custom `TokenExtractor`,
or a custom `OnError` responder. By default the middleware lets unauthenticated
requests continue as anonymous (gate them with `RequireAuth`); a *present but
invalid* token is always rejected.

## Errors

Every failure is an `*ssoerr.AuthError` carrying a stable `Code`, an HTTP
`StatusCode`, and a JSON body:

```json
{ "error": "invalid_audience", "message": "Token audience is invalid", "statusCode": 401 }
```

Use `ssoerr.As(err)` to inspect a returned error.

## Adding a provider

Implement `core.AuthProvider` and pass it to `middleware.New` — nothing else in
the framework changes:

```go
type GoogleProvider struct{ /* ... */ }

func (p *GoogleProvider) Name() string { return "google" }
func (p *GoogleProvider) Authenticate(ctx context.Context, token string, _ *core.AuthContext) (*core.AuthUser, error) {
	// validate, then return a *core.AuthUser
}
```

## Develop

```bash
cd packages/go
go test ./...
go vet ./...
gofmt -l .
```

## License

MIT — see [LICENSE](LICENSE).
