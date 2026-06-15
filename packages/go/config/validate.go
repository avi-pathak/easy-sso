package config

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/avi-pathak/easy-sso/packages/go/cache"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

const (
	defaultTenant         = "common"
	defaultAuthorityHost  = "login.microsoftonline.com"
	defaultV1IssuerHost   = "sts.windows.net"
	defaultClockTolerance = 60 * time.Second
	defaultJWKSTTL        = time.Hour
)

var validVersions = []TokenVersion{TokenV1, TokenV2}

func fail(msg string, details map[string]any) error {
	return ssoerr.NewConfigurationError(msg, details)
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// normalizeHost strips protocol and any trailing slash so URL building is uniform.
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	lower := strings.ToLower(host)
	switch {
	case strings.HasPrefix(lower, "https://"):
		host = host[len("https://"):]
	case strings.HasPrefix(lower, "http://"):
		host = host[len("http://"):]
	}
	return strings.TrimRight(host, "/")
}

// ValidateMicrosoftConfig validates and normalizes a user-supplied config,
// applying all defaults. It returns a ConfigurationError on the first problem —
// this runs at startup so misconfiguration fails fast and loud.
func ValidateMicrosoftConfig(cfg MicrosoftAuthConfig) (NormalizedMicrosoftConfig, error) {
	var n NormalizedMicrosoftConfig

	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		return n, fail("`ClientID` is required and must be a non-empty string", map[string]any{"received": cfg.ClientID})
	}

	tenantID := orStr(cfg.TenantID, defaultTenant)
	if !IsValidTenantID(tenantID) {
		return n, fail(
			fmt.Sprintf("`TenantID` must be 'common', 'organizations', 'consumers', or a tenant GUID (received: %s)", tenantID),
			map[string]any{"tenantId": tenantID},
		)
	}

	for _, t := range cfg.AllowedTenants {
		if !IsTenantGUID(t) {
			return n, fail("`AllowedTenants` entries must be tenant GUIDs", map[string]any{"tenant": t})
		}
	}

	versions := cfg.AcceptedVersions
	if len(versions) == 0 {
		versions = append([]TokenVersion(nil), validVersions...)
	}
	for _, v := range versions {
		if v != TokenV1 && v != TokenV2 {
			return n, fail("`AcceptedVersions` entries must be '1.0' or '2.0'", map[string]any{"version": v})
		}
	}

	tol := cfg.ClockTolerance
	if tol == 0 {
		tol = defaultClockTolerance
	}
	if tol < 0 {
		return n, fail("`ClockTolerance` must be a non-negative duration", map[string]any{"clockTolerance": tol.String()})
	}

	authorityHost := normalizeHost(orStr(cfg.AuthorityHost, defaultAuthorityHost))
	if authorityHost == "" {
		return n, fail("`AuthorityHost` must be a non-empty host", nil)
	}
	v1IssuerHost := normalizeHost(orStr(cfg.V1IssuerHost, defaultV1IssuerHost))

	jwksTTL := cfg.JWKS.TTL
	if jwksTTL == 0 {
		jwksTTL = defaultJWKSTTL
	}
	if jwksTTL <= 0 {
		return n, fail("`JWKS.TTL` must be a positive duration", map[string]any{"ttl": jwksTTL.String()})
	}
	if cfg.JWKS.RefreshInterval < 0 {
		return n, fail("`JWKS.RefreshInterval` must be positive when provided", nil)
	}

	jwksURI := cfg.JWKS.URI
	if jwksURI == "" {
		jwksURI = fmt.Sprintf("https://%s/%s/discovery/v2.0/keys", authorityHost, tenantID)
	}

	audiences := cfg.Audience
	if len(audiences) == 0 {
		audiences = []string{clientID, "api://" + clientID}
	} else {
		for _, a := range audiences {
			if strings.TrimSpace(a) == "" {
				return n, fail("`Audience` entries must be non-empty strings", nil)
			}
		}
	}

	if err := validateClaimMapping(cfg.Claims); err != nil {
		return n, err
	}

	var httpClient HTTPClient = cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	clk := cfg.Clock
	if clk == nil {
		clk = cache.SystemClock
	}

	return NormalizedMicrosoftConfig{
		ClientID:         clientID,
		TenantID:         tenantID,
		Audiences:        audiences,
		AllowedTenants:   cfg.AllowedTenants,
		AcceptedVersions: versions,
		ClockTolerance:   tol,
		Claims:           cfg.Claims,
		AuthorityHost:    authorityHost,
		V1IssuerHost:     v1IssuerHost,
		JWKSURI:          jwksURI,
		JWKSTTL:          jwksTTL,
		JWKSRefresh:      cfg.JWKS.RefreshInterval,
		HTTPClient:       httpClient,
		Clock:            clk,
	}, nil
}

func validateClaimMapping(m ClaimMappingConfig) error {
	fields := map[string][]string{
		"ID":       m.ID,
		"Email":    m.Email,
		"Name":     m.Name,
		"Roles":    m.Roles,
		"Scopes":   m.Scopes,
		"TenantID": m.TenantID,
	}
	for field, list := range fields {
		for _, claimName := range list {
			if strings.TrimSpace(claimName) == "" {
				return fail(fmt.Sprintf("`Claims.%s` must map to non-empty claim name(s)", field), map[string]any{"field": field})
			}
		}
	}
	return nil
}
