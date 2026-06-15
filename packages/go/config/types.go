// Package config holds the user-facing Microsoft Entra ID configuration plus its
// validation/normalization. It is provider-specific but sits below the provider
// package so the provider can depend on it without a cycle.
package config

import (
	"net/http"
	"time"

	"github.com/avi-pathak/easy-sso/packages/go/cache"
)

// TokenVersion is a Microsoft Entra ID token version this framework understands.
type TokenVersion string

const (
	TokenV1 TokenVersion = "1.0"
	TokenV2 TokenVersion = "2.0"
)

// HTTPClient is the minimal interface the JWKS fetcher needs; *http.Client
// satisfies it. Injectable for tests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// ClaimMappingConfig maps AuthUser fields to source JWT claim name(s). For each
// field the first present, non-empty claim wins. An empty field falls back to
// the provider's Microsoft defaults.
type ClaimMappingConfig struct {
	ID       []string
	Email    []string
	Name     []string
	Roles    []string
	Scopes   []string
	TenantID []string
}

// JWKSConfig tunes the JWKS cache used during signature verification.
type JWKSConfig struct {
	// TTL is the freshness window for a fetched key set. Default: 1 hour.
	TTL time.Duration
	// RefreshInterval enables background proactive refresh when > 0.
	RefreshInterval time.Duration
	// URI overrides the JWKS endpoint (sovereign clouds, B2C, or testing).
	URI string
}

// MicrosoftAuthConfig is the user-facing configuration accepted by the Microsoft
// provider. It is validated and normalized at construction time.
type MicrosoftAuthConfig struct {
	// ClientID is the application (client) ID of your Entra app registration. Required.
	ClientID string

	// TenantID is the tenant mode: "common", "organizations", "consumers", or a
	// tenant GUID. Default: "common".
	TenantID string

	// Audience is the accepted token audience(s). Defaults to
	// [ClientID, "api://"+ClientID].
	Audience []string

	// AllowedTenants is an optional allow-list of tenant GUIDs (tid).
	AllowedTenants []string

	// AcceptedVersions are the accepted token versions. Default: both 1.0 and 2.0.
	AcceptedVersions []TokenVersion

	// ClockTolerance is the skew tolerance for exp/nbf. Default: 60s.
	ClockTolerance time.Duration

	// Claims is the config-driven claim mapping.
	Claims ClaimMappingConfig

	// JWKS tunes the JWKS cache.
	JWKS JWKSConfig

	// AuthorityHost is the authority host. Default: "login.microsoftonline.com".
	AuthorityHost string

	// V1IssuerHost is the issuer host for v1.0 tokens. Default: "sts.windows.net".
	V1IssuerHost string

	// HTTPClient is the injected HTTP client (testing / custom transport).
	HTTPClient HTTPClient

	// Clock is the injected clock (testing). Defaults to the system clock.
	Clock cache.Clock
}

// NormalizedMicrosoftConfig is the fully-resolved configuration with all defaults
// applied and values normalized. Produced by ValidateMicrosoftConfig.
type NormalizedMicrosoftConfig struct {
	ClientID         string
	TenantID         string
	Audiences        []string
	AllowedTenants   []string
	AcceptedVersions []TokenVersion
	ClockTolerance   time.Duration
	Claims           ClaimMappingConfig
	AuthorityHost    string
	V1IssuerHost     string
	JWKSURI          string
	JWKSTTL          time.Duration
	JWKSRefresh      time.Duration
	HTTPClient       HTTPClient
	Clock            cache.Clock
}
