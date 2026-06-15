// Command example is a minimal net/http server protected by easy-sso's Microsoft
// Entra ID provider.
//
// Run it with your Entra app registration's client id:
//
//	CLIENT_ID=<app-client-id> TENANT_ID=common go run .
//
// Then call it with a bearer token issued for that app:
//
//	curl -H "Authorization: Bearer <token>" localhost:8080/profile
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	easysso "github.com/avi-pathak/easy-sso/packages/go"
)

func main() {
	clientID := os.Getenv("CLIENT_ID")
	if clientID == "" {
		log.Fatal("CLIENT_ID is required")
	}
	tenantID := os.Getenv("TENANT_ID")
	if tenantID == "" {
		tenantID = "common"
	}

	// Build the auth middleware. Construction validates the config and fails fast
	// on misconfiguration.
	auth, err := easysso.MicrosoftAuth(easysso.MicrosoftAuthConfig{
		ClientID: clientID,
		TenantID: tenantID,
	}, easysso.MiddlewareOptions{})
	if err != nil {
		log.Fatalf("auth setup: %v", err)
	}

	mux := http.NewServeMux()

	// Public route: works with or without a token.
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})

	// Protected route: requires a valid token.
	mux.Handle("/profile", easysso.RequireAuth(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := easysso.UserFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(user)
	})))

	// Admin route: requires the "admin" app role.
	mux.Handle("/admin", easysso.RequireRole("admin", nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("welcome, admin"))
	})))

	addr := ":8080"
	log.Printf("listening on %s", addr)
	// Wrap the whole mux so every request runs through authentication.
	log.Fatal(http.ListenAndServe(addr, auth(mux)))
}
