package core

// AuthUser is the normalized, provider-agnostic representation of an
// authenticated principal. Every provider — Microsoft today, Google/Okta/Auth0
// tomorrow — maps its token into this shape. Consumers only ever see AuthUser;
// they never branch on which provider produced it.
type AuthUser struct {
	// ID is a stable, unique identifier for the principal within the issuing
	// directory (Microsoft: oid, falling back to sub).
	ID string `json:"id"`

	// Email is the primary email / UPN, if the token carries one.
	Email string `json:"email,omitempty"`

	// Name is a human-readable display name, if available.
	Name string `json:"name,omitempty"`

	// Roles are the application roles granted to the principal. Never nil so
	// authorization checks never have to nil-guard.
	Roles []string `json:"roles"`

	// Scopes are the OAuth2 scopes / delegated permissions on the token. Never nil.
	Scopes []string `json:"scopes"`

	// TenantID is the tenant / organization identifier (Microsoft: tid), when the
	// provider is multi-tenant aware.
	TenantID string `json:"tenantId,omitempty"`

	// Provider is the name of the provider that authenticated this user.
	Provider string `json:"provider"`

	// Claims is the full set of validated claims from the token.
	Claims Claims `json:"claims"`
}

// HasRole reports whether the user was granted role.
func (u *AuthUser) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasScope reports whether the user's token carries scope.
func (u *AuthUser) HasScope(scope string) bool {
	for _, s := range u.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}
