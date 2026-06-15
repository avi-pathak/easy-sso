// Package microsoft is the Microsoft Entra ID implementation of
// core.AuthProvider. It is the only place that ties together Entra-specific
// issuer resolution, JWKS endpoints, and claim shapes.
package microsoft

import (
	"fmt"
	"strings"

	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

// ResolveExpectedIssuer computes the expected issuer for a token given the tenant
// GUID (tid) it claims and its version.
//
// This is the crux of correct Entra validation: with common/organizations the
// issuer is not a fixed string — it embeds the real tenant GUID.
//
//   - v2.0: https://{authorityHost}/{tid}/v2.0
//   - v1.0: https://{v1IssuerHost}/{tid}/  (note the trailing slash)
func ResolveExpectedIssuer(tid string, version config.TokenVersion, cfg config.NormalizedMicrosoftConfig) string {
	if version == config.TokenV2 {
		return fmt.Sprintf("https://%s/%s/v2.0", cfg.AuthorityHost, tid)
	}
	return fmt.Sprintf("https://%s/%s/", cfg.V1IssuerHost, tid)
}

// AssertTenantAllowed enforces that the token's tenant (tid) is acceptable for
// the configured tenant mode and any explicit allow-list.
//
//   - GUID mode      → tid must equal the configured tenant.
//   - consumers      → tid must be the personal-MSA tenant.
//   - organizations  → tid must NOT be the personal-MSA tenant.
//   - common         → any tenant is allowed.
//   - AllowedTenants → if non-empty, tid must be a member.
func AssertTenantAllowed(tid string, cfg config.NormalizedMicrosoftConfig) error {
	configured := cfg.TenantID

	switch {
	case config.IsTenantGUID(configured):
		if !strings.EqualFold(tid, configured) {
			return ssoerr.NewInvalidIssuerError(
				fmt.Sprintf("Token tenant '%s' does not match the configured tenant '%s'", tid, configured),
				map[string]any{"expected": configured, "actual": tid},
			)
		}
	case configured == "consumers":
		if !strings.EqualFold(tid, config.PersonalMSATenantID) {
			return ssoerr.NewInvalidIssuerError(
				"Configured for personal accounts only, but token is from a work/school tenant",
				map[string]any{"actual": tid},
			)
		}
	case configured == "organizations":
		if strings.EqualFold(tid, config.PersonalMSATenantID) {
			return ssoerr.NewInvalidIssuerError(
				"Configured for work/school accounts only, but token is from a personal account",
				map[string]any{"actual": tid},
			)
		}
	}

	if len(cfg.AllowedTenants) > 0 {
		for _, t := range cfg.AllowedTenants {
			if strings.EqualFold(t, tid) {
				return nil
			}
		}
		return ssoerr.NewInvalidIssuerError(
			fmt.Sprintf("Token tenant '%s' is not in the allowed-tenants list", tid),
			map[string]any{"actual": tid, "allowedTenants": cfg.AllowedTenants},
		)
	}
	return nil
}
