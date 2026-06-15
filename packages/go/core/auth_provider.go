package core

import "context"

// AuthProvider is the single contract every authentication backend implements.
//
// This is the seam that makes the framework provider-agnostic. The middleware,
// the error layer, and consuming applications all program against AuthProvider
// and never against a concrete provider. Adding Google/Okta/Auth0/Keycloak later
// means implementing this interface — with zero changes to the public API.
//
// Contract:
//   - Authenticate MUST validate the token fully (signature, issuer, audience,
//     expiry, …) and either resolve a normalized *AuthUser or return an
//     *ssoerr.AuthError.
//   - It MUST NOT return a partially-trusted user. There is no "soft" success.
//   - Implementations should be safe to share across requests and concurrent-safe.
type AuthProvider interface {
	// Name is a stable, lowercase identifier for the provider (e.g. "microsoft").
	Name() string

	// Authenticate validates a raw bearer token (no "Bearer " prefix) and resolves
	// the authenticated principal. authCtx is optional framework-agnostic context.
	Authenticate(ctx context.Context, token string, authCtx *AuthContext) (*AuthUser, error)
}

// Initializer is optionally implemented by providers that support eager startup
// warming (e.g. priming a JWKS cache). Implementations must be idempotent.
type Initializer interface {
	Initialize(ctx context.Context) error
}

// Disposer is optionally implemented by providers that hold resources (timers,
// caches) which need cleanup. Safe to call multiple times.
type Disposer interface {
	Dispose() error
}
