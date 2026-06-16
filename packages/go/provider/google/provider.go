package google

import (
	"context"

	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/core"
	"github.com/avi-pathak/easy-sso/packages/go/internal/oidc"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

// googleDefaults are the default source claims for each AuthUser field for Google
// ID tokens. Google ID tokens carry no application roles, so Roles defaults to
// empty — map roles from your own store. The `hd` (hosted domain) claim is
// surfaced as TenantID.
var googleDefaults = config.ClaimMappingConfig{
	ID:       []string{"sub"},
	Email:    []string{"email"},
	Name:     []string{"name"},
	Roles:    nil,
	Scopes:   []string{"scope"},
	TenantID: []string{"hd"},
}

// Provider is the Google implementation of core.AuthProvider. The middleware and
// core depend on the interface, never on this type.
type Provider struct {
	cfg  normalizedConfig
	jwks *oidc.JWKSClient
}

var (
	_ core.AuthProvider = (*Provider)(nil)
	_ core.Initializer  = (*Provider)(nil)
	_ core.Disposer     = (*Provider)(nil)
)

// NewProvider validates the config (fail-fast) and constructs a provider.
func NewProvider(cfg AuthConfig) (*Provider, error) {
	normalized, err := validateConfig(cfg)
	if err != nil {
		return nil, err
	}
	jwks := oidc.NewJWKSClient(oidc.JWKSClientOptions{
		URI:             normalized.jwksURI,
		TTL:             normalized.jwksTTL,
		RefreshInterval: normalized.jwksRefresh,
		HTTPClient:      normalized.httpClient,
		Clock:           normalized.clock,
	})
	return &Provider{cfg: normalized, jwks: jwks}, nil
}

// Name returns the provider identifier.
func (p *Provider) Name() string { return "google" }

// Authenticate validates a raw Google ID token and resolves the authenticated user.
func (p *Provider) Authenticate(_ context.Context, token string, _ *core.AuthContext) (*core.AuthUser, error) {
	if token == "" {
		return nil, ssoerr.NewMissingTokenError("", nil)
	}

	header, claims, parts, err := oidc.Decode(token)
	if err != nil {
		return nil, err
	}
	if err := oidc.VerifySignature(p.jwks, parts, header); err != nil {
		return nil, err
	}
	if err := oidc.VerifyStandardClaims(claims, oidc.ClaimsOptions{
		Issuers:   GoogleIssuers,
		Audiences: p.cfg.audiences,
		Now:       p.cfg.clock.Now(),
		Tolerance: p.cfg.clockTolerance,
	}); err != nil {
		return nil, err
	}

	hd, _ := claims.String("hd")
	if err := assertHostedDomainAllowed(hd, p.cfg.hostedDomains); err != nil {
		return nil, err
	}

	return p.mapClaimsToUser(claims)
}

func (p *Provider) mapClaimsToUser(claims core.Claims) (*core.AuthUser, error) {
	m := p.cfg.claims

	idSources := oidc.SourcesFor(m.ID, googleDefaults.ID)
	id, ok := oidc.FirstString(claims, idSources)
	if !ok {
		return nil, ssoerr.NewAuthenticationError(
			"Token is missing a usable subject identifier",
			map[string]any{"tried": idSources},
		)
	}

	email, _ := oidc.FirstString(claims, oidc.SourcesFor(m.Email, googleDefaults.Email))
	name, _ := oidc.FirstString(claims, oidc.SourcesFor(m.Name, googleDefaults.Name))
	tenantID, _ := oidc.FirstString(claims, oidc.SourcesFor(m.TenantID, googleDefaults.TenantID))
	roles := oidc.StringArray(claims, oidc.SourcesFor(m.Roles, googleDefaults.Roles))
	scopes := oidc.StringArray(claims, oidc.SourcesFor(m.Scopes, googleDefaults.Scopes))

	return &core.AuthUser{
		ID:       id,
		Email:    email,
		Name:     name,
		Roles:    roles,
		Scopes:   scopes,
		TenantID: tenantID,
		Provider: p.Name(),
		Claims:   claims,
	}, nil
}

// Initialize eagerly warms the JWKS cache so the first request doesn't pay the fetch.
func (p *Provider) Initialize(_ context.Context) error { return p.jwks.Prime() }

// Dispose releases timers/caches held by the provider.
func (p *Provider) Dispose() error { p.jwks.Dispose(); return nil }
