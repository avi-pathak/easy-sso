package microsoft

import (
	"testing"

	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/core"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

func TestMapClaimsDefaults(t *testing.T) {
	cfg := norm(t, config.MicrosoftAuthConfig{ClientID: "c", TenantID: "common"})
	claims := core.Claims{
		"oid":   "object-id",
		"sub":   "subject",
		"email": "user@example.com",
		"name":  "Ada Lovelace",
		"tid":   "tenant-1",
		"roles": []any{"admin", "reader", ""},
		"scp":   "read write",
	}
	u, err := MapClaimsToUser(claims, cfg, "microsoft")
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if u.ID != "object-id" { // oid wins over sub
		t.Fatalf("id = %q", u.ID)
	}
	if u.Email != "user@example.com" || u.Name != "Ada Lovelace" || u.TenantID != "tenant-1" {
		t.Fatalf("unexpected user: %+v", u)
	}
	if len(u.Roles) != 2 || u.Roles[0] != "admin" || u.Roles[1] != "reader" {
		t.Fatalf("roles = %v (empty strings should be filtered)", u.Roles)
	}
	if len(u.Scopes) != 2 || u.Scopes[0] != "read" || u.Scopes[1] != "write" {
		t.Fatalf("scopes = %v (space-delimited scp)", u.Scopes)
	}
	if u.Provider != "microsoft" {
		t.Fatalf("provider = %q", u.Provider)
	}
}

func TestMapClaimsFallbackToSub(t *testing.T) {
	cfg := norm(t, config.MicrosoftAuthConfig{ClientID: "c", TenantID: "common"})
	u, err := MapClaimsToUser(core.Claims{"sub": "only-sub"}, cfg, "microsoft")
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if u.ID != "only-sub" {
		t.Fatalf("id = %q, want sub fallback", u.ID)
	}
	if u.Roles == nil || u.Scopes == nil {
		t.Fatal("roles/scopes must be non-nil")
	}
}

func TestMapClaimsMissingSubject(t *testing.T) {
	cfg := norm(t, config.MicrosoftAuthConfig{ClientID: "c", TenantID: "common"})
	_, err := MapClaimsToUser(core.Claims{"email": "x@y.z"}, cfg, "microsoft")
	if ae, ok := ssoerr.As(err); !ok || ae.Code != ssoerr.CodeAuthentication {
		t.Fatalf("want authentication_error, got %v", err)
	}
}

func TestMapClaimsCustomMapping(t *testing.T) {
	cfg := norm(t, config.MicrosoftAuthConfig{
		ClientID: "c", TenantID: "common",
		Claims: config.ClaimMappingConfig{
			ID:    []string{"custom_id"},
			Roles: []string{"groups"},
		},
	})
	claims := core.Claims{
		"custom_id": "cid",
		"oid":       "ignored",
		"groups":    []any{"g1", "g2"},
	}
	u, err := MapClaimsToUser(claims, cfg, "microsoft")
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if u.ID != "cid" {
		t.Fatalf("id = %q, want custom mapping", u.ID)
	}
	if len(u.Roles) != 2 {
		t.Fatalf("roles = %v, want from groups", u.Roles)
	}
}
