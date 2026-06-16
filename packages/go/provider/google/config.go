// Package google is the Google (Sign in with Google / Google Identity)
// implementation of core.AuthProvider. It validates Google-issued OIDC ID tokens
// against Google's published JWKS, reusing the shared oidc plumbing.
package google

import (
	"net/http"
	"strings"
	"time"

	"github.com/avi-pathak/easy-sso/packages/go/cache"
	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

// GoogleIssuers are the accepted `iss` values for Google ID tokens. Google emits
// both the bare host and the https form.
var GoogleIssuers = []string{"https://accounts.google.com", "accounts.google.com"}

// DefaultJWKSURI is Google's OAuth2 certs (JWKS) endpoint.
const DefaultJWKSURI = "https://www.googleapis.com/oauth2/v3/certs"

const (
	defaultClockTolerance = 60 * time.Second
	defaultJWKSTTL        = time.Hour
)

// AuthConfig is the user-facing configuration for the Google provider. It is
// validated and normalized at construction time.
type AuthConfig struct {
	// ClientID is your Google OAuth 2.0 client ID — the expected token audience.
	// Required.
	ClientID string

	// Audiences overrides the accepted audience(s). Defaults to [ClientID]. Use
	// this when several client IDs (web/iOS/Android) share a backend.
	Audiences []string

	// HostedDomains, when non-empty, restricts logins to these Google Workspace
	// domains (the token's `hd` claim must match one). Leave empty to allow any
	// Google account.
	HostedDomains []string

	// ClockTolerance is the skew tolerance for exp/nbf. Default: 60s.
	ClockTolerance time.Duration

	// Claims is the config-driven claim mapping (overrides Google defaults).
	Claims config.ClaimMappingConfig

	// JWKS tunes the JWKS cache.
	JWKS config.JWKSConfig

	// HTTPClient is the injected HTTP client (testing / custom transport).
	HTTPClient config.HTTPClient

	// Clock is the injected clock (testing). Defaults to the system clock.
	Clock cache.Clock
}

// normalizedConfig is the fully-resolved configuration with defaults applied.
type normalizedConfig struct {
	audiences      []string
	hostedDomains  []string
	clockTolerance time.Duration
	claims         config.ClaimMappingConfig
	jwksURI        string
	jwksTTL        time.Duration
	jwksRefresh    time.Duration
	httpClient     config.HTTPClient
	clock          cache.Clock
}

func validateConfig(cfg AuthConfig) (normalizedConfig, error) {
	var n normalizedConfig

	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		return n, ssoerr.NewConfigurationError("`ClientID` is required and must be a non-empty string", map[string]any{"received": cfg.ClientID})
	}

	audiences := cfg.Audiences
	if len(audiences) == 0 {
		audiences = []string{clientID}
	} else {
		for _, a := range audiences {
			if strings.TrimSpace(a) == "" {
				return n, ssoerr.NewConfigurationError("`Audiences` entries must be non-empty strings", nil)
			}
		}
	}

	for _, d := range cfg.HostedDomains {
		if strings.TrimSpace(d) == "" {
			return n, ssoerr.NewConfigurationError("`HostedDomains` entries must be non-empty strings", nil)
		}
	}

	tol := cfg.ClockTolerance
	if tol == 0 {
		tol = defaultClockTolerance
	}
	if tol < 0 {
		return n, ssoerr.NewConfigurationError("`ClockTolerance` must be a non-negative duration", nil)
	}

	jwksTTL := cfg.JWKS.TTL
	if jwksTTL == 0 {
		jwksTTL = defaultJWKSTTL
	}
	if jwksTTL <= 0 {
		return n, ssoerr.NewConfigurationError("`JWKS.TTL` must be a positive duration", nil)
	}
	if cfg.JWKS.RefreshInterval < 0 {
		return n, ssoerr.NewConfigurationError("`JWKS.RefreshInterval` must be positive when provided", nil)
	}

	jwksURI := cfg.JWKS.URI
	if jwksURI == "" {
		jwksURI = DefaultJWKSURI
	}

	for field, list := range map[string][]string{
		"ID": cfg.Claims.ID, "Email": cfg.Claims.Email, "Name": cfg.Claims.Name,
		"Roles": cfg.Claims.Roles, "Scopes": cfg.Claims.Scopes, "TenantID": cfg.Claims.TenantID,
	} {
		for _, c := range list {
			if strings.TrimSpace(c) == "" {
				return n, ssoerr.NewConfigurationError("`Claims."+field+"` must map to non-empty claim name(s)", map[string]any{"field": field})
			}
		}
	}

	var httpClient config.HTTPClient = cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	clk := cfg.Clock
	if clk == nil {
		clk = cache.SystemClock
	}

	return normalizedConfig{
		audiences:      audiences,
		hostedDomains:  cfg.HostedDomains,
		clockTolerance: tol,
		claims:         cfg.Claims,
		jwksURI:        jwksURI,
		jwksTTL:        jwksTTL,
		jwksRefresh:    cfg.JWKS.RefreshInterval,
		httpClient:     httpClient,
		clock:          clk,
	}, nil
}

// assertHostedDomainAllowed enforces the optional Google Workspace domain
// allow-list against the token's `hd` claim.
func assertHostedDomainAllowed(hd string, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}
	for _, d := range allowed {
		if d == hd {
			return nil
		}
	}
	return ssoerr.NewInvalidIssuerError(
		"Token hosted domain is not in the allowed list",
		map[string]any{"actual": hd, "allowedHostedDomains": allowed},
	)
}
