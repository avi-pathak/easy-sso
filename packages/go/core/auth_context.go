package core

import "strings"

// AuthContext is a framework-agnostic view of an inbound request, sufficient for
// a provider to locate and validate credentials. HTTP adapters build one from
// their native request; the core and providers depend only on this — never on a
// concrete server type — which keeps the framework HTTP-server-agnostic.
type AuthContext struct {
	// Headers are the request headers with lower-cased keys.
	Headers map[string][]string

	// Token is the bearer token already extracted from the request, if any.
	Token string

	// Method is the request method, when known (informational for providers).
	Method string

	// Path is the request path, when known (informational for providers).
	Path string
}

// NewAuthContext builds an AuthContext from a header map, lower-casing keys.
func NewAuthContext(headers map[string][]string, token, method, path string) AuthContext {
	lc := make(map[string][]string, len(headers))
	for k, v := range headers {
		lc[strings.ToLower(k)] = v
	}
	return AuthContext{Headers: lc, Token: token, Method: method, Path: path}
}

// Header returns the first value of the named (case-insensitive) header.
func (c AuthContext) Header(name string) string {
	if v := c.Headers[strings.ToLower(name)]; len(v) > 0 {
		return v[0]
	}
	return ""
}
