// Package easysso is a provider-agnostic Single Sign-On framework for Go. The
// core knows only an AuthProvider interface; Microsoft Entra ID ships as the
// first provider, and others plug in later with zero public-API changes.
//
// This package is a thin aggregator: it re-exports the most commonly used types
// and constructors from the sub-packages so consumers can rely on a single
// import for the common case.
//
//	mw, err := easysso.MicrosoftAuth(easysso.MicrosoftAuthConfig{
//		ClientID: os.Getenv("CLIENT_ID"),
//		TenantID: "common",
//	}, easysso.MiddlewareOptions{})
//	if err != nil { log.Fatal(err) }
//
//	mux := http.NewServeMux()
//	mux.Handle("/profile", easysso.RequireAuth(nil)(profileHandler))
//	http.ListenAndServe(":8080", mw(mux))
package easysso

import (
	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/core"
	"github.com/avi-pathak/easy-sso/packages/go/middleware"
	"github.com/avi-pathak/easy-sso/packages/go/provider/google"
	"github.com/avi-pathak/easy-sso/packages/go/provider/microsoft"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

// Core abstractions (provider-agnostic).
type (
	AuthUser     = core.AuthUser
	AuthProvider = core.AuthProvider
	AuthContext  = core.AuthContext
	Claims       = core.Claims
)

// Errors.
type (
	AuthError = ssoerr.AuthError
	ErrorCode = ssoerr.Code
)

// Config.
type (
	MicrosoftAuthConfig = config.MicrosoftAuthConfig
	ClaimMappingConfig  = config.ClaimMappingConfig
	JWKSConfig          = config.JWKSConfig
	TokenVersion        = config.TokenVersion
)

// Microsoft provider.
type MicrosoftProvider = microsoft.Provider

// Google provider.
type (
	GoogleProvider   = google.Provider
	GoogleAuthConfig = google.AuthConfig
)

// Middleware.
type (
	MiddlewareOptions = middleware.Options
	ErrorHandler      = middleware.ErrorHandler
	RoleMatchMode     = middleware.RoleMatchMode
)

// Constructors and helpers, re-exported for a single import.
var (
	// NewMicrosoftProvider builds a Microsoft Entra ID provider.
	NewMicrosoftProvider = microsoft.NewProvider
	// NewGoogleProvider builds a Google provider.
	NewGoogleProvider = google.NewProvider
	// NewAuthMiddleware wraps any AuthProvider in net/http middleware.
	NewAuthMiddleware = middleware.New
	// MicrosoftAuth is a convenience that builds the Microsoft provider middleware.
	MicrosoftAuth = middleware.Microsoft
	// GoogleAuth is a convenience that builds the Google provider middleware.
	GoogleAuth = middleware.Google

	RequireAuth         = middleware.RequireAuth
	RequireRole         = middleware.RequireRole
	RequireRoles        = middleware.RequireRoles
	UserFromContext     = middleware.UserFromContext
	ExtractBearerToken  = middleware.ExtractBearerToken
	DefaultErrorHandler = middleware.DefaultErrorHandler

	ValidateMicrosoftConfig = config.ValidateMicrosoftConfig
)

// Tenant match modes.
const (
	MatchAny = middleware.MatchAny
	MatchAll = middleware.MatchAll
)
