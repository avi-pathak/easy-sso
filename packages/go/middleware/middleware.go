package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/core"
	"github.com/avi-pathak/easy-sso/packages/go/provider/microsoft"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

type contextKey struct{}

var userKey = contextKey{}

// UserFromContext returns the authenticated user attached by the auth middleware.
func UserFromContext(ctx context.Context) (*core.AuthUser, bool) {
	u, ok := ctx.Value(userKey).(*core.AuthUser)
	return u, ok
}

// Options configures the authentication middleware.
type Options struct {
	// CredentialsRequired, when true, rejects a request with no bearer token (401).
	// When false (default) the request continues as anonymous and routes are gated
	// with RequireAuth. Either way, a present-but-invalid token is always rejected.
	CredentialsRequired bool

	// TokenExtractor overrides how the token is located. Default: Authorization: Bearer.
	TokenExtractor func(r *http.Request) string

	// OnError overrides the error response. Default writes JSON + WWW-Authenticate.
	OnError ErrorHandler
}

// ExtractBearerToken parses a bearer token from an Authorization header value,
// returning the token sans scheme, or "" when absent/not a bearer credential.
func ExtractBearerToken(header string) string {
	header = strings.TrimSpace(header)
	const prefix = "bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

func defaultExtractor(r *http.Request) string {
	return ExtractBearerToken(r.Header.Get("Authorization"))
}

// New builds authentication middleware around any core.AuthProvider. This is the
// provider-agnostic entry point: pass a Microsoft provider today, another
// provider tomorrow — the middleware is identical.
func New(provider core.AuthProvider, opts Options) func(http.Handler) http.Handler {
	extract := opts.TokenExtractor
	if extract == nil {
		extract = defaultExtractor
	}
	onError := opts.OnError
	if onError == nil {
		onError = DefaultErrorHandler
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extract(r)
			if token == "" {
				if opts.CredentialsRequired {
					onError(w, r, ssoerr.NewMissingTokenError("", nil))
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			authCtx := core.NewAuthContext(map[string][]string(r.Header), token, r.Method, r.URL.Path)
			user, err := provider.Authenticate(r.Context(), token, &authCtx)
			if err != nil {
				onError(w, r, ssoerr.Coerce(err))
				return
			}
			ctx := context.WithValue(r.Context(), userKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Microsoft is a convenience constructor for the Microsoft Entra ID provider
// middleware. Construction validates the config and returns a ConfigurationError
// immediately on misconfiguration (fail-fast at startup).
func Microsoft(cfg config.MicrosoftAuthConfig, opts Options) (func(http.Handler) http.Handler, error) {
	p, err := microsoft.NewProvider(cfg)
	if err != nil {
		return nil, err
	}
	return New(p, opts), nil
}
