package middleware

import (
	"net/http"
	"strings"

	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

// RequireAuth gates a handler on an authenticated principal. It assumes the auth
// middleware ran earlier and populated the request context. Responds 401 when no
// user is present. Pass nil onError to use DefaultErrorHandler.
func RequireAuth(onError ErrorHandler) func(http.Handler) http.Handler {
	if onError == nil {
		onError = DefaultErrorHandler
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := UserFromContext(r.Context()); !ok {
				onError(w, r, ssoerr.NewAuthenticationError("Authentication is required to access this resource", nil))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RoleMatchMode controls whether the user must have ANY of the listed roles or ALL.
type RoleMatchMode string

const (
	// MatchAny passes if the user has at least one listed role.
	MatchAny RoleMatchMode = "any"
	// MatchAll requires every listed role.
	MatchAll RoleMatchMode = "all"
)

// RequireRoles gates a handler on role membership. Must run after the auth
// middleware. Responds 401 if unauthenticated, 403 if authenticated but lacking
// the required role(s). It panics at wire-up if roles is empty (a programming
// error). An empty mode defaults to MatchAny; nil onError uses DefaultErrorHandler.
func RequireRoles(roles []string, mode RoleMatchMode, onError ErrorHandler) func(http.Handler) http.Handler {
	if len(roles) == 0 {
		panic("middleware: RequireRoles requires at least one role")
	}
	if mode == "" {
		mode = MatchAny
	}
	if onError == nil {
		onError = DefaultErrorHandler
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := UserFromContext(r.Context())
			if !ok {
				onError(w, r, ssoerr.NewAuthenticationError("Authentication is required to access this resource", nil))
				return
			}
			granted := make(map[string]bool, len(user.Roles))
			for _, role := range user.Roles {
				granted[role] = true
			}
			authorized := mode == MatchAll
			for _, role := range roles {
				has := granted[role]
				if mode == MatchAll && !has {
					authorized = false
					break
				}
				if mode == MatchAny && has {
					authorized = true
					break
				}
			}
			if !authorized {
				word := "one"
				if mode == MatchAll {
					word = "all"
				}
				onError(w, r, ssoerr.NewAuthorizationError(
					"Access denied: requires "+word+" of role(s) ["+strings.Join(roles, ", ")+"]",
					map[string]any{"requiredRoles": roles, "mode": string(mode)},
				))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole is a convenience for a single required role.
func RequireRole(role string, onError ErrorHandler) func(http.Handler) http.Handler {
	return RequireRoles([]string{role}, MatchAny, onError)
}
