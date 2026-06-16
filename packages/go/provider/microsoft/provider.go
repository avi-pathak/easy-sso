package microsoft

import (
	"context"

	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/core"
	"github.com/avi-pathak/easy-sso/packages/go/internal/oidc"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

// Provider is the Microsoft Entra ID implementation of core.AuthProvider. It is
// the only place that ties together Entra-specific issuer resolution, JWKS
// endpoints, and claim shapes; the middleware and core depend on the interface,
// never on this type — which is what lets other providers drop in later.
type Provider struct {
	cfg       config.NormalizedMicrosoftConfig
	jwks      *oidc.JWKSClient
	validator *TokenValidator
}

var (
	_ core.AuthProvider = (*Provider)(nil)
	_ core.Initializer  = (*Provider)(nil)
	_ core.Disposer     = (*Provider)(nil)
)

// NewProvider validates the config (fail-fast) and constructs a provider. A bad
// config returns a descriptive ConfigurationError here, at startup — never deep
// inside request handling.
func NewProvider(cfg config.MicrosoftAuthConfig) (*Provider, error) {
	normalized, err := config.ValidateMicrosoftConfig(cfg)
	if err != nil {
		return nil, err
	}
	jwks := oidc.NewJWKSClient(oidc.JWKSClientOptions{
		URI:             normalized.JWKSURI,
		TTL:             normalized.JWKSTTL,
		RefreshInterval: normalized.JWKSRefresh,
		HTTPClient:      normalized.HTTPClient,
		Clock:           normalized.Clock,
	})
	return &Provider{
		cfg:       normalized,
		jwks:      jwks,
		validator: NewTokenValidator(normalized, jwks),
	}, nil
}

// Name returns the provider identifier.
func (p *Provider) Name() string { return "microsoft" }

// Authenticate validates a raw bearer token and resolves the authenticated user.
func (p *Provider) Authenticate(_ context.Context, token string, _ *core.AuthContext) (*core.AuthUser, error) {
	if token == "" {
		return nil, ssoerr.NewMissingTokenError("", nil)
	}
	claims, err := p.validator.Validate(token)
	if err != nil {
		return nil, err
	}
	return MapClaimsToUser(claims, p.cfg, p.Name())
}

// Initialize eagerly warms the JWKS cache so the first request doesn't pay the fetch.
func (p *Provider) Initialize(_ context.Context) error { return p.jwks.Prime() }

// Dispose releases timers/caches held by the provider.
func (p *Provider) Dispose() error { p.jwks.Dispose(); return nil }
