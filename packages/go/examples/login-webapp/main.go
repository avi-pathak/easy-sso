// Command login-webapp is a minimal server-side web app that signs a user in
// with Microsoft Entra ID and validates the returned ID token with the easy-sso
// Go package. No frontend build — just net/http, the OIDC authorization-code
// flow, and microsoft.Provider doing the token validation.
//
//	Browser ──/auth/login──▶ Microsoft sign-in
//	        ◀──code──────── /auth/callback
//	                         │  exchange code → id_token
//	                         │  provider.Authenticate(id_token)   ← easy-sso
//	                         ▼  session cookie → profile page
//
// It reads the SAME env vars as the Node login-webapp demo, so you can reuse the
// same .env / app registration:
//
//	cd packages/go/examples/login-webapp
//	go run .
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/core"
	"github.com/avi-pathak/easy-sso/packages/go/provider/microsoft"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

var (
	clientID     string
	clientSecret string
	tenant       string
	port         int
	redirectURI  string
	authority    string
	provider     *microsoft.Provider
)

const scope = "openid profile email"

func main() {
	// Load the same .env the Node demo uses (local copy first, then the Node
	// example's file so a single configured .env serves both).
	loadDotenv(os.Getenv("ENV_FILE"), "./.env", "../../../../examples/login-webapp/.env")

	clientID = requireEnv("CLIENT_ID")
	clientSecret = requireEnv("CLIENT_SECRET")
	tenant = envOr("TENANT", "organizations")
	port = atoiOr(os.Getenv("PORT"), 7070)
	redirectURI = envOr("REDIRECT_URI", fmt.Sprintf("http://localhost:%d/auth/callback", port))
	authority = "https://login.microsoftonline.com/" + tenant

	// The whole point of the demo: easy-sso validates the ID token Microsoft
	// returns from the code exchange (signature, issuer, audience, expiry, tenant).
	p, err := microsoft.NewProvider(config.MicrosoftAuthConfig{
		ClientID: clientID,
		TenantID: tenant,
	})
	if err != nil {
		log.Fatalf("provider setup: %v", err)
	}
	provider = p

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHome)
	mux.HandleFunc("/auth/login", handleLogin)
	mux.HandleFunc("/auth/callback", handleCallback)
	mux.HandleFunc("/auth/logout", handleLogout)
	mux.HandleFunc("/api/me", handleAPIMe)

	log.Printf("▶ login demo on http://localhost:%d", port)
	log.Printf("  tenant=%s  redirect_uri=%s", tenant, redirectURI)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), mux))
}

// --- Sessions (trivial in-memory store) -------------------------------------

type session struct {
	state string
	nonce string
	user  *core.AuthUser
}

var (
	sessMu   sync.Mutex
	sessions = map[string]*session{}
)

func getSession(w http.ResponseWriter, r *http.Request) *session {
	sessMu.Lock()
	defer sessMu.Unlock()
	if c, err := r.Cookie("sid"); err == nil {
		if s, ok := sessions[c.Value]; ok {
			return s
		}
	}
	sid := randomHex(16)
	s := &session{}
	sessions[sid] = s
	http.SetCookie(w, &http.Cookie{
		Name: "sid", Value: sid, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 3600,
	})
	return s
}

// --- Routes -----------------------------------------------------------------

func handleHome(w http.ResponseWriter, r *http.Request) {
	s := getSession(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if s.user != nil {
		io.WriteString(w, profilePage(s.user))
	} else {
		io.WriteString(w, loginPage())
	}
}

// Step 1: redirect the browser to Microsoft to sign in.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	s := getSession(w, r)
	s.state = randomHex(16)
	s.nonce = randomHex(16)

	q := url.Values{
		"client_id":     {clientID},
		"response_type": {"code"},
		"redirect_uri":  {redirectURI},
		"response_mode": {"query"},
		"scope":         {scope},
		"state":         {s.state},
		"nonce":         {s.nonce},
	}
	http.Redirect(w, r, authority+"/oauth2/v2.0/authorize?"+q.Encode(), http.StatusFound)
}

// Step 2: Microsoft redirects back with a code; exchange it and validate.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	s := getSession(w, r)
	q := r.URL.Query()

	if e := q.Get("error"); e != "" {
		renderError(w, fmt.Sprintf("%s: %s", e, q.Get("error_description")), http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	if code == "" || q.Get("state") != s.state {
		renderError(w, "Invalid OAuth state or missing authorization code", http.StatusBadRequest)
		return
	}

	idToken, err := exchangeCode(r.Context(), code)
	if err != nil {
		renderError(w, err.Error(), http.StatusBadGateway)
		return
	}

	// *** easy-sso validates the ID token here. ***
	user, err := provider.Authenticate(r.Context(), idToken, nil)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		if ae, ok := ssoerr.As(err); ok {
			status, msg = ae.StatusCode, fmt.Sprintf("%s: %s", ae.Code, ae.Message)
		}
		log.Printf("[auth error] %s", msg)
		renderError(w, msg, status)
		return
	}

	// Bind the validated token to this login attempt (replay defense).
	if nonce, _ := user.Claims.String("nonce"); nonce != s.nonce {
		renderError(w, "Nonce mismatch — possible replay", http.StatusBadRequest)
		return
	}

	s.user = user
	s.state, s.nonce = "", ""
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("sid"); err == nil {
		sessMu.Lock()
		delete(sessions, c.Value)
		sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleAPIMe(w http.ResponseWriter, r *http.Request) {
	s := getSession(w, r)
	w.Header().Set("Content-Type", "application/json")
	if s.user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"not_authenticated"}`)
		return
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s.user)
}

// exchangeCode swaps the authorization code for tokens (confidential client) and
// returns the id_token.
func exchangeCode(ctx context.Context, code string) (string, error) {
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"scope":         {scope},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, authority+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var tokens struct {
		IDToken          string `json:"id_token"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &tokens)
	if resp.StatusCode != http.StatusOK || tokens.IDToken == "" {
		detail := tokens.ErrorDescription
		if detail == "" {
			detail = strconv.Itoa(resp.StatusCode)
		}
		return "", fmt.Errorf("token exchange failed: %s", detail)
	}
	return tokens.IDToken, nil
}

// --- env helpers ------------------------------------------------------------

func requireEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("Missing required env var %s — see .env.example", name)
	}
	return v
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// --- Views (no frontend build — just HTML) ----------------------------------

func pageShell(body string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>easy-sso · Login with Microsoft</title>
<style>
  body{font:16px/1.5 system-ui,sans-serif;max-width:640px;margin:64px auto;padding:0 20px;color:#1b1b1f}
  .card{border:1px solid #e3e3e8;border-radius:12px;padding:28px}
  .btn{display:inline-block;background:#2f2f31;color:#fff;text-decoration:none;padding:10px 18px;border-radius:8px;font-weight:600}
  .btn.ms{background:#2563eb}
  pre{background:#f5f5f7;border-radius:8px;padding:16px;overflow:auto;font-size:13px}
  .muted{color:#6b6b70}
  a.link{color:#2563eb}
</style></head><body>` + body + `</body></html>`
}

func loginPage() string {
	return pageShell(`<div class="card">
    <h1>Sign in</h1>
    <p class="muted">This page is protected. Authenticate with your Microsoft work or school account.</p>
    <p><a class="btn ms" href="/auth/login">Login with Microsoft</a></p>
  </div>`)
}

func profilePage(u *core.AuthUser) string {
	claimsJSON, _ := json.MarshalIndent(u.Claims, "", "  ")
	display := firstNonEmpty(u.Name, u.Email, u.ID)
	return pageShell(`<div class="card">
    <h1>Hello, ` + html.EscapeString(display) + ` 👋</h1>
    <p class="muted">Your ID token was validated by the easy-sso Go package.</p>
    <ul>
      <li><strong>id:</strong> ` + html.EscapeString(u.ID) + `</li>
      <li><strong>email:</strong> ` + html.EscapeString(orDash(u.Email)) + `</li>
      <li><strong>tenant:</strong> ` + html.EscapeString(orDash(u.TenantID)) + `</li>
      <li><strong>roles:</strong> ` + html.EscapeString(orDash(strings.Join(u.Roles, ", "))) + `</li>
    </ul>
    <p><a class="link" href="/api/me">/api/me (JSON)</a> · <a class="link" href="/auth/logout">Logout</a></p>
    <details><summary>Validated claims</summary><pre>` + html.EscapeString(string(claimsJSON)) + `</pre></details>
  </div>`)
}

func renderError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, pageShell(`<div class="card">
    <h1>Sign-in failed</h1>
    <pre>`+html.EscapeString(message)+`</pre>
    <p><a class="link" href="/">← Back</a></p>
  </div>`))
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
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
// environment (without overriding already-set vars). Minimal, dependency-free.
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
		log.Printf("loaded env from %s", p)
		return
	}
}
