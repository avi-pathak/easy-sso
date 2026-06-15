// Command validate verifies a real Microsoft token with the easy-sso Go package
// against Microsoft's live Entra JWKS.
//
//	go run ./validate <token>
//
// Env:
//
//	CLIENT_ID         required (the app the token was issued for)
//	VALIDATE_TENANT   override tenant mode (e.g. your tenant GUID for v1 tokens)
//	TENANT            fallback tenant mode (default "organizations")
//	AUDIENCE          comma-separated accepted audiences (defaults to client-id forms)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/provider/microsoft"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

func main() {
	loadDotenv(os.Getenv("ENV_FILE"), "./.env", "../../../../examples/login-webapp/.env")

	if len(os.Args) < 2 || os.Args[1] == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./validate <token>")
		os.Exit(2)
	}
	token := os.Args[1]

	clientID := os.Getenv("CLIENT_ID")
	if clientID == "" {
		fmt.Fprintln(os.Stderr, "CLIENT_ID is not set (see .env)")
		os.Exit(2)
	}

	cfg := config.MicrosoftAuthConfig{
		ClientID: clientID,
		TenantID: firstNonEmpty(os.Getenv("VALIDATE_TENANT"), os.Getenv("TENANT"), "organizations"),
	}
	if aud := os.Getenv("AUDIENCE"); aud != "" {
		cfg.Audience = strings.Split(aud, ",")
	}

	provider, err := microsoft.NewProvider(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(2)
	}

	user, err := provider.Authenticate(context.Background(), token, nil)
	if err != nil {
		code := "error"
		if ae, ok := ssoerr.As(err); ok {
			code = string(ae.Code)
		}
		fmt.Fprintf(os.Stderr, "❌ REJECTED — %s: %s\n", code, err.Error())
		os.Exit(1)
	}

	fmt.Println("✅ VALID — verified by easy-sso (Go) against live Microsoft JWKS")
	fmt.Println()
	out, _ := json.MarshalIndent(user, "", "  ")
	fmt.Println(string(out))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// loadDotenv loads KEY=VALUE pairs from the first existing path into the
// environment (without overriding already-set vars).
func loadDotenv(paths ...string) {
	for _, p := range paths {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			eq := strings.IndexByte(line, '=')
			if eq < 0 {
				continue
			}
			key := strings.TrimSpace(line[:eq])
			val := strings.Trim(strings.TrimSpace(line[eq+1:]), `"'`)
			if _, set := os.LookupEnv(key); !set {
				_ = os.Setenv(key, val)
			}
		}
		return
	}
}
