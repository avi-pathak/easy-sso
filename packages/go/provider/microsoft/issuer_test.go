package microsoft

import (
	"testing"

	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

func norm(t *testing.T, cfg config.MicrosoftAuthConfig) config.NormalizedMicrosoftConfig {
	t.Helper()
	n, err := config.ValidateMicrosoftConfig(cfg)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	return n
}

func TestResolveExpectedIssuer(t *testing.T) {
	cfg := norm(t, config.MicrosoftAuthConfig{ClientID: "c", TenantID: "common"})
	tid := "abc"
	if got := ResolveExpectedIssuer(tid, config.TokenV2, cfg); got != "https://login.microsoftonline.com/abc/v2.0" {
		t.Fatalf("v2 issuer = %q", got)
	}
	if got := ResolveExpectedIssuer(tid, config.TokenV1, cfg); got != "https://sts.windows.net/abc/" {
		t.Fatalf("v1 issuer = %q", got)
	}
}

func TestAssertTenantAllowed(t *testing.T) {
	guid := "11111111-2222-3333-4444-555555555555"
	other := "99999999-2222-3333-4444-555555555555"

	cases := []struct {
		name    string
		cfg     config.MicrosoftAuthConfig
		tid     string
		wantErr bool
	}{
		{"guid match", config.MicrosoftAuthConfig{ClientID: "c", TenantID: guid}, guid, false},
		{"guid mismatch", config.MicrosoftAuthConfig{ClientID: "c", TenantID: guid}, other, true},
		{"common allows any", config.MicrosoftAuthConfig{ClientID: "c", TenantID: "common"}, other, false},
		{"organizations rejects personal", config.MicrosoftAuthConfig{ClientID: "c", TenantID: "organizations"}, config.PersonalMSATenantID, true},
		{"organizations allows work", config.MicrosoftAuthConfig{ClientID: "c", TenantID: "organizations"}, guid, false},
		{"consumers requires personal", config.MicrosoftAuthConfig{ClientID: "c", TenantID: "consumers"}, guid, true},
		{"allow-list miss", config.MicrosoftAuthConfig{ClientID: "c", TenantID: "common", AllowedTenants: []string{guid}}, other, true},
		{"allow-list hit", config.MicrosoftAuthConfig{ClientID: "c", TenantID: "common", AllowedTenants: []string{guid}}, guid, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := AssertTenantAllowed(tc.tid, norm(t, tc.cfg))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if ae, ok := ssoerr.As(err); !ok || ae.Code != ssoerr.CodeInvalidIssuer {
					t.Fatalf("want invalid_issuer, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
