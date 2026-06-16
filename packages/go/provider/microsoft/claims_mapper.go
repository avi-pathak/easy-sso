package microsoft

import (
	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/core"
	"github.com/avi-pathak/easy-sso/packages/go/internal/oidc"
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

// MapClaimsToUser maps validated Microsoft claims into the normalized AuthUser,
// honoring any config-driven claim-mapping overrides. It is the only place that
// knows Microsoft claim names; the rest of the framework consumes AuthUser.
func MapClaimsToUser(claims core.Claims, cfg config.NormalizedMicrosoftConfig, providerName string) (*core.AuthUser, error) {
	m := cfg.Claims

	idSources := oidc.SourcesFor(m.ID, microsoftDefaults.ID)
	id, ok := oidc.FirstString(claims, idSources)
	if !ok {
		return nil, ssoerr.NewAuthenticationError(
			"Token is missing a usable subject identifier",
			map[string]any{"tried": idSources},
		)
	}

	email, _ := oidc.FirstString(claims, oidc.SourcesFor(m.Email, microsoftDefaults.Email))
	name, _ := oidc.FirstString(claims, oidc.SourcesFor(m.Name, microsoftDefaults.Name))
	tenantID, _ := oidc.FirstString(claims, oidc.SourcesFor(m.TenantID, microsoftDefaults.TenantID))
	roles := oidc.StringArray(claims, oidc.SourcesFor(m.Roles, microsoftDefaults.Roles))
	scopes := oidc.StringArray(claims, oidc.SourcesFor(m.Scopes, microsoftDefaults.Scopes))

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
