package config

import "regexp"

// PersonalMSATenantID is the well-known tenant ID for personal Microsoft accounts
// (MSA / consumers). Used to distinguish work/school from personal accounts.
const PersonalMSATenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"

var tenantModes = map[string]bool{"common": true, "organizations": true, "consumers": true}

var guidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsTenantGUID reports whether value looks like a tenant GUID (vs a named mode).
func IsTenantGUID(value string) bool { return guidRE.MatchString(value) }

// IsValidTenantID reports whether value is a valid tenant value
// (common/organizations/consumers/GUID).
func IsValidTenantID(value string) bool { return tenantModes[value] || IsTenantGUID(value) }
