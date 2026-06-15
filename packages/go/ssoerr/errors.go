// Package ssoerr defines the single error type the framework returns, along with
// stable, machine-readable error codes and the HTTP status each maps to.
package ssoerr

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Code is a stable, machine-readable error code. These are part of the public
// API: clients and logs may switch on them, so treat changes as breaking.
type Code string

const (
	CodeAuthentication   Code = "authentication_error"
	CodeMissingToken     Code = "missing_token"
	CodeTokenExpired     Code = "token_expired"
	CodeTokenNotYetValid Code = "token_not_yet_valid"
	CodeInvalidAudience  Code = "invalid_audience"
	CodeInvalidIssuer    Code = "invalid_issuer"
	CodeInvalidSignature Code = "invalid_signature"
	CodeInvalidToken     Code = "invalid_token"
	CodeAuthorization    Code = "authorization_error"
	CodeConfiguration    Code = "configuration_error"
)

// AuthError is the single error type the framework returns. It carries a stable
// Code, a human-readable Message, the HTTP StatusCode an adapter should respond
// with, and optional non-sensitive structured Details.
type AuthError struct {
	Code       Code
	Message    string
	StatusCode int
	Details    map[string]any
}

// Error implements the error interface.
func (e *AuthError) Error() string { return e.Message }

type errorJSON struct {
	Error      Code           `json:"error"`
	Message    string         `json:"message"`
	StatusCode int            `json:"statusCode"`
	Details    map[string]any `json:"details,omitempty"`
}

// MarshalJSON renders a safe, structured payload suitable for an HTTP response body.
func (e *AuthError) MarshalJSON() ([]byte, error) {
	return json.Marshal(errorJSON{
		Error:      e.Code,
		Message:    e.Message,
		StatusCode: e.StatusCode,
		Details:    e.Details,
	})
}

// As extracts an *AuthError from err, if present anywhere in its chain.
func As(err error) (*AuthError, bool) {
	var ae *AuthError
	if errors.As(err, &ae) {
		return ae, true
	}
	return nil, false
}

// Coerce returns err as an *AuthError, wrapping any non-AuthError as a generic
// authentication failure.
func Coerce(err error) *AuthError {
	if ae, ok := As(err); ok {
		return ae
	}
	return NewAuthenticationError("Authentication failed", map[string]any{"cause": err.Error()})
}

func newErr(code Code, status int, msg string, details map[string]any) *AuthError {
	return &AuthError{Code: code, Message: msg, StatusCode: status, Details: details}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// NewAuthenticationError is a generic authentication failure (HTTP 401).
func NewAuthenticationError(msg string, details map[string]any) *AuthError {
	return newErr(CodeAuthentication, http.StatusUnauthorized, orDefault(msg, "Authentication failed"), details)
}

// NewMissingTokenError signals an absent Authorization header / bearer token (HTTP 401).
func NewMissingTokenError(msg string, details map[string]any) *AuthError {
	return newErr(CodeMissingToken, http.StatusUnauthorized, orDefault(msg, "No bearer token was provided"), details)
}

// NewTokenExpiredError signals an exp claim in the past (HTTP 401).
func NewTokenExpiredError(msg string, details map[string]any) *AuthError {
	return newErr(CodeTokenExpired, http.StatusUnauthorized, orDefault(msg, "Token has expired"), details)
}

// NewTokenNotYetValidError signals an nbf claim in the future (HTTP 401).
func NewTokenNotYetValidError(msg string, details map[string]any) *AuthError {
	return newErr(CodeTokenNotYetValid, http.StatusUnauthorized, orDefault(msg, "Token is not yet valid"), details)
}

// NewInvalidAudienceError signals an aud claim that did not match (HTTP 401).
func NewInvalidAudienceError(msg string, details map[string]any) *AuthError {
	return newErr(CodeInvalidAudience, http.StatusUnauthorized, orDefault(msg, "Token audience is invalid"), details)
}

// NewInvalidIssuerError signals an iss claim that did not match (HTTP 401).
func NewInvalidIssuerError(msg string, details map[string]any) *AuthError {
	return newErr(CodeInvalidIssuer, http.StatusUnauthorized, orDefault(msg, "Token issuer is invalid"), details)
}

// NewInvalidSignatureError signals a signature that failed verification (HTTP 401).
func NewInvalidSignatureError(msg string, details map[string]any) *AuthError {
	return newErr(CodeInvalidSignature, http.StatusUnauthorized, orDefault(msg, "Token signature verification failed"), details)
}

// NewInvalidTokenError signals a malformed / unparseable token (HTTP 401).
func NewInvalidTokenError(msg string, details map[string]any) *AuthError {
	return newErr(CodeInvalidToken, http.StatusUnauthorized, orDefault(msg, "Token is invalid"), details)
}

// NewAuthorizationError signals an authenticated principal lacking the required
// role/scope (HTTP 403).
func NewAuthorizationError(msg string, details map[string]any) *AuthError {
	return newErr(CodeAuthorization, http.StatusForbidden, orDefault(msg, "You do not have permission to access this resource"), details)
}

// NewConfigurationError signals invalid or missing framework configuration (HTTP 500).
func NewConfigurationError(msg string, details map[string]any) *AuthError {
	return newErr(CodeConfiguration, http.StatusInternalServerError, orDefault(msg, "Invalid configuration"), details)
}
