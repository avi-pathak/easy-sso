package config

import (
	"testing"
	"time"

	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

func TestDefaultsApplied(t *testing.T) {
	n, err := ValidateMicrosoftConfig(MicrosoftAuthConfig{ClientID: "client-123"})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if n.TenantID != "common" {
		t.Fatalf("tenant default = %q", n.TenantID)
	}
	if len(n.Audiences) != 2 || n.Audiences[0] != "client-123" || n.Audiences[1] != "api://client-123" {
		t.Fatalf("audiences = %v", n.Audiences)
	}
	if n.ClockTolerance != 60*time.Second {
		t.Fatalf("clock tolerance = %v", n.ClockTolerance)
	}
	if n.JWKSTTL != time.Hour {
		t.Fatalf("jwks ttl = %v", n.JWKSTTL)
	}
	if n.JWKSURI != "https://login.microsoftonline.com/common/discovery/v2.0/keys" {
		t.Fatalf("jwks uri = %q", n.JWKSURI)
	}
	if len(n.AcceptedVersions) != 2 {
		t.Fatalf("versions = %v", n.AcceptedVersions)
	}
	if n.HTTPClient == nil || n.Clock == nil {
		t.Fatal("http client / clock must default to non-nil")
	}
}

func TestMissingClientID(t *testing.T) {
	_, err := ValidateMicrosoftConfig(MicrosoftAuthConfig{})
	wantConfigErr(t, err)
}

func TestInvalidTenant(t *testing.T) {
	_, err := ValidateMicrosoftConfig(MicrosoftAuthConfig{ClientID: "c", TenantID: "not-a-tenant"})
	wantConfigErr(t, err)
}

func TestInvalidAllowedTenant(t *testing.T) {
	_, err := ValidateMicrosoftConfig(MicrosoftAuthConfig{ClientID: "c", AllowedTenants: []string{"nope"}})
	wantConfigErr(t, err)
}

func TestNegativeClockTolerance(t *testing.T) {
	_, err := ValidateMicrosoftConfig(MicrosoftAuthConfig{ClientID: "c", ClockTolerance: -time.Second})
	wantConfigErr(t, err)
}

func TestEmptyAudienceEntry(t *testing.T) {
	_, err := ValidateMicrosoftConfig(MicrosoftAuthConfig{ClientID: "c", Audience: []string{"ok", "  "}})
	wantConfigErr(t, err)
}

func TestAuthorityHostNormalized(t *testing.T) {
	n, err := ValidateMicrosoftConfig(MicrosoftAuthConfig{ClientID: "c", AuthorityHost: "https://login.microsoftonline.us/"})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if n.AuthorityHost != "login.microsoftonline.us" {
		t.Fatalf("authority host = %q (should strip scheme + trailing slash)", n.AuthorityHost)
	}
}

func wantConfigErr(t *testing.T, err error) {
	t.Helper()
	ae, ok := ssoerr.As(err)
	if !ok || ae.Code != ssoerr.CodeConfiguration {
		t.Fatalf("want configuration_error, got %v", err)
	}
}
