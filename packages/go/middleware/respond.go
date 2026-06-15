// Package middleware provides net/http middleware that wraps any
// core.AuthProvider: it validates a present token, attaches the user to the
// request context, and gates routes on authentication and roles.
package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

// ErrorHandler writes an HTTP response for an AuthError. Override to forward to a
// logger, shape the body differently, etc.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err *ssoerr.AuthError)

// DefaultErrorHandler emits the error's structured JSON body with its status code
// and a WWW-Authenticate: Bearer challenge on 401 responses (per RFC 6750).
func DefaultErrorHandler(w http.ResponseWriter, _ *http.Request, err *ssoerr.AuthError) {
	if err.StatusCode == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer error=%q, error_description=%q", string(err.Code), err.Message))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)
	_ = json.NewEncoder(w).Encode(err)
}
