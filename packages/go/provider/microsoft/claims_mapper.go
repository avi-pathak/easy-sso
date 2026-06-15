package microsoft

import (
	"strings"

	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/core"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

// microsoftDefaults are the default source claims for each field, in priority
// order, for Microsoft tokens.
var microsoftDefaults = config.ClaimMappingConfig{
	// oid is the immutable object id; sub is stable but pairwise per app.
	ID: []string{"oid", "sub"},
	// v2 access tokens lack email; UPN/preferred_username cover most cases.
	Email: []string{"email", "preferred_username", "upn", "unique_name"},
	Name:  []string{"name"},
	// App roles land in roles.
	Roles: []string{"roles"},
	// v2 delegated scopes in scp; v1 sometimes uses scope.
	Scopes:   []string{"scp", "scope"},
	TenantID: []string{"tid"},
}

func sourcesFor(custom, def []string) []string {
	if len(custom) > 0 {
		return custom
	}
	return def
}

// firstString returns the first source claim whose value is a non-empty string.
func firstString(claims core.Claims, sources []string) (string, bool) {
	for _, s := range sources {
		if v, ok := claims.String(s); ok {
			return v, true
		}
	}
	return "", false
}

// stringArray collects a string slice from the first matching source. Accepts
// either a real array of strings or a space-delimited string (how Entra encodes
// scp). Returns a non-nil (possibly empty) slice.
func stringArray(claims core.Claims, sources []string) []string {
	for _, s := range sources {
		switch v := claims[s].(type) {
		case []any:
			out := make([]string, 0, len(v))
			for _, item := range v {
				if str, ok := item.(string); ok && str != "" {
					out = append(out, str)
				}
			}
			return out
		case []string:
			out := make([]string, 0, len(v))
			for _, str := range v {
				if str != "" {
					out = append(out, str)
				}
			}
			return out
		case string:
			if v != "" {
				return strings.Fields(v)
			}
		}
	}
	return []string{}
}

// MapClaimsToUser maps validated Microsoft claims into the normalized AuthUser,
// honoring any config-driven claim-mapping overrides. It is the only place that
// knows Microsoft claim names; the rest of the framework consumes AuthUser.
func MapClaimsToUser(claims core.Claims, cfg config.NormalizedMicrosoftConfig, providerName string) (*core.AuthUser, error) {
	m := cfg.Claims

	idSources := sourcesFor(m.ID, microsoftDefaults.ID)
	id, ok := firstString(claims, idSources)
	if !ok {
		return nil, ssoerr.NewAuthenticationError(
			"Token is missing a usable subject identifier",
			map[string]any{"tried": idSources},
		)
	}

	email, _ := firstString(claims, sourcesFor(m.Email, microsoftDefaults.Email))
	name, _ := firstString(claims, sourcesFor(m.Name, microsoftDefaults.Name))
	tenantID, _ := firstString(claims, sourcesFor(m.TenantID, microsoftDefaults.TenantID))
	roles := stringArray(claims, sourcesFor(m.Roles, microsoftDefaults.Roles))
	scopes := stringArray(claims, sourcesFor(m.Scopes, microsoftDefaults.Scopes))

	return &core.AuthUser{
		ID:       id,
		Email:    email,
		Name:     name,
		Roles:    roles,
		Scopes:   scopes,
		TenantID: tenantID,
		Provider: providerName,
		Claims:   claims,
	}, nil
}
