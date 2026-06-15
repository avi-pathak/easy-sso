// Package core holds the provider-agnostic abstractions for easy-sso. Nothing
// here knows about any concrete provider; providers depend on core, never the
// reverse.
package core

// Claims is a decoded set of JWT claims: the registered claims (RFC 7519) plus
// any provider-specific claims. Values are untyped (JSON-decoded), so use the
// helper accessors to read them safely.
type Claims map[string]any

// String returns the claim named name as a string when present and non-empty.
func (c Claims) String(name string) (string, bool) {
	v, ok := c[name].(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// Float returns a numeric claim (e.g. exp/nbf/iat) as a float64. JSON numbers
// decode to float64; integer fakes are tolerated for tests.
func (c Claims) Float(name string) (float64, bool) {
	switch v := c[name].(type) {
	case float64:
		return v, true
	case int64:
		return float64(v), true
	case int:
		return float64(v), true
	}
	return 0, false
}
