// Command login-webapp is a minimal server-side web app that signs a user in
// with Microsoft Entra ID and/or Google and validates the returned ID token with
// the easy-sso Go package. No frontend build — just net/http, the OIDC
// authorization-code flow, and the providers doing the token validation.
//
//	Browser ──/auth/<p>/login──▶ provider sign-in
//	        ◀──code──────────── /auth/<p>/callback
//	                             │  exchange code → id_token
//	                             │  provider.Authenticate(id_token)   ← easy-sso
//	                             ▼  session cookie → profile page
//
// Each provider is optional: it is enabled when its client id + secret are set.
// Configure Microsoft, Google, or both. It reads the SAME env vars as the Node
// login-webapp demo, so you can reuse the same .env / app registrations:
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
	"github.com/avi-pathak/easy-sso/packages/go/provider/google"
	"github.com/avi-pathak/easy-sso/packages/go/provider/microsoft"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

// oauthFlow holds everything needed to drive one provider's authorization-code
// flow and validate the resulting ID token.
type oauthFlow struct {
	name            string
	label           string
	loginPath       string
	callbackPath    string
	authorizeURL    string
	tokenURL        string
	clientID        string
	clientSecret    string
	redirectURI     string
	scope           string
	extraAuthParams map[string]string
	validate        func(ctx context.Context, idToken string) (*core.AuthUser, error)
}

var (
	port       int
	flows      []*oauthFlow
	flowByName = map[string]*oauthFlow{}
)

func main() {
	loadDotenv(os.Getenv("ENV_FILE"), "./.env", "../../../../examples/login-webapp/.env")
	port = atoiOr(os.Getenv("PORT"), 7070)

	if err := buildFlows(); err != nil {
		log.Fatalf("provider setup: %v", err)
	}
	if len(flows) == 0 {
		log.Fatal("Configure at least one provider in .env: Microsoft (CLIENT_ID + CLIENT_SECRET) and/or Google (GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET). See .env.example.")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHome)
	mux.HandleFunc("/auth/logout", handleLogout)
	mux.HandleFunc("/api/me", handleAPIMe)
	// Login routes are per-provider (internal links — not registered with the IdP).
	for _, f := range flows {
		flow := f
		mux.HandleFunc(flow.loginPath, func(w http.ResponseWriter, r *http.Request) { startLogin(flow, w, r) })
	}
	// Callback routes dispatch by the session-recorded provider, so two providers
	// may share one redirect URI (e.g. both on /auth/callback).
	seen := map[string]bool{}
	for _, f := range flows {
		if seen[f.callbackPath] {
			continue
		}
		seen[f.callbackPath] = true
		mux.HandleFunc(f.callbackPath, handleCallback)
	}

	labels := make([]string, len(flows))
	for i, f := range flows {
		labels[i] = f.label
	}
	log.Printf("▶ login demo on http://localhost:%d", port)
	log.Printf("  providers: %s", strings.Join(labels, ", "))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), mux))
}

func buildFlows() error {
	// Microsoft Entra ID
	if clientID, secret := os.Getenv("CLIENT_ID"), os.Getenv("CLIENT_SECRET"); clientID != "" && secret != "" {
		tenant := envOr("TENANT", "organizations")
		authority := "https://login.microsoftonline.com/" + tenant
		p, err := microsoft.NewProvider(config.MicrosoftAuthConfig{ClientID: clientID, TenantID: tenant})
		if err != nil {
			return err
		}
		redirect := envOr("REDIRECT_URI", fmt.Sprintf("http://localhost:%d/auth/callback", port))
		flows = append(flows, &oauthFlow{
			name:            "microsoft",
			label:           "Microsoft",
			loginPath:       "/auth/login",
			callbackPath:    callbackPathOf(redirect),
			authorizeURL:    authority + "/oauth2/v2.0/authorize",
			tokenURL:        authority + "/oauth2/v2.0/token",
			clientID:        clientID,
			clientSecret:    secret,
			redirectURI:     redirect,
			scope:           "openid profile email",
			extraAuthParams: map[string]string{"response_mode": "query"},
			validate:        func(ctx context.Context, t string) (*core.AuthUser, error) { return p.Authenticate(ctx, t, nil) },
		})
	}

	// Google
	if clientID, secret := os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET"); clientID != "" && secret != "" {
		p, err := google.NewProvider(google.AuthConfig{ClientID: clientID})
		if err != nil {
			return err
		}
		redirect := envOr("GOOGLE_REDIRECT_URI", fmt.Sprintf("http://localhost:%d/auth/callback", port))
		flows = append(flows, &oauthFlow{
			name:            "google",
			label:           "Google",
			loginPath:       "/auth/google/login",
			callbackPath:    callbackPathOf(redirect),
			authorizeURL:    "https://accounts.google.com/o/oauth2/v2/auth",
			tokenURL:        "https://oauth2.googleapis.com/token",
			clientID:        clientID,
			clientSecret:    secret,
			redirectURI:     redirect,
			scope:           "openid email profile",
			extraAuthParams: map[string]string{"access_type": "online", "prompt": "select_account"},
			validate:        func(ctx context.Context, t string) (*core.AuthUser, error) { return p.Authenticate(ctx, t, nil) },
		})
	}
	for _, f := range flows {
		flowByName[f.name] = f
	}
	return nil
}

// callbackPathOf extracts the path from a redirect URI so the handler is
// registered at exactly the path the IdP will redirect to.
func callbackPathOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
		return u.Path
	}
	return "/auth/callback"
}

// --- Sessions (trivial in-memory store) -------------------------------------

type session struct {
	state string
	nonce string
	flow  string
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
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s := getSession(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if s.user != nil {
		io.WriteString(w, profilePage(s.user))
	} else {
		io.WriteString(w, loginPage())
	}
}

// Step 1: redirect the browser to the provider to sign in.
func startLogin(flow *oauthFlow, w http.ResponseWriter, r *http.Request) {
	s := getSession(w, r)
	s.state = randomHex(16)
	s.nonce = randomHex(16)
	s.flow = flow.name

	q := url.Values{
		"client_id":     {flow.clientID},
		"response_type": {"code"},
		"redirect_uri":  {flow.redirectURI},
		"scope":         {flow.scope},
		"state":         {s.state},
		"nonce":         {s.nonce},
	}
	for k, v := range flow.extraAuthParams {
		q.Set(k, v)
	}
	http.Redirect(w, r, flow.authorizeURL+"?"+q.Encode(), http.StatusFound)
}

// Step 2: the provider redirects back with a code; exchange it and validate. The
// provider is resolved from the session (recorded at login), not the URL — so
// providers can even share one redirect URI.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	s := getSession(w, r)
	q := r.URL.Query()

	if e := q.Get("error"); e != "" {
		renderError(w, fmt.Sprintf("%s: %s", e, q.Get("error_description")), http.StatusBadRequest)
		return
	}
	flow := flowByName[s.flow]
	code := q.Get("code")
	if flow == nil || code == "" || q.Get("state") != s.state {
		renderError(w, "Invalid OAuth state or missing authorization code", http.StatusBadRequest)
		return
	}

	idToken, err := exchangeCode(r.Context(), flow, code)
	if err != nil {
		renderError(w, err.Error(), http.StatusBadGateway)
		return
	}

	// *** easy-sso validates the ID token here (Microsoft or Google). ***
	user, err := flow.validate(r.Context(), idToken)
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
	s.state, s.nonce, s.flow = "", "", ""
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
func exchangeCode(ctx context.Context, flow *oauthFlow, code string) (string, error) {
	form := url.Values{
		"client_id":     {flow.clientID},
		"client_secret": {flow.clientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {flow.redirectURI},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, flow.tokenURL, strings.NewReader(form.Encode()))
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
<title>easy-sso · Login</title>
<style>
  body{font:16px/1.5 system-ui,sans-serif;max-width:640px;margin:64px auto;padding:0 20px;color:#1b1b1f}
  .card{border:1px solid #e3e3e8;border-radius:12px;padding:28px}
  .btn{display:inline-block;color:#fff;text-decoration:none;padding:10px 18px;border-radius:8px;font-weight:600;margin:6px 8px 6px 0}
  .btn.microsoft{background:#2563eb}
  .btn.google{background:#1a73e8}
  pre{background:#f5f5f7;border-radius:8px;padding:16px;overflow:auto;font-size:13px}
  .muted{color:#6b6b70}
  a.link{color:#2563eb}
  .tag{display:inline-block;background:#eef;border-radius:6px;padding:2px 8px;font-size:13px}
</style></head><body>` + body + `</body></html>`
}

func loginPage() string {
	var buttons strings.Builder
	for _, f := range flows {
		buttons.WriteString(`<a class="btn ` + f.name + `" href="` + f.loginPath + `">Login with ` + f.label + `</a>`)
	}
	return pageShell(`<div class="card">
    <h1>Sign in</h1>
    <p class="muted">This page is protected. Choose a provider — the returned ID token is validated by the easy-sso Go package.</p>
    <p>` + buttons.String() + `</p>
  </div>`)
}

func profilePage(u *core.AuthUser) string {
	claimsJSON, _ := json.MarshalIndent(u.Claims, "", "  ")
	display := firstNonEmpty(u.Name, u.Email, u.ID)
	return pageShell(`<div class="card">
    <h1>Hello, ` + html.EscapeString(display) + ` 👋</h1>
    <p class="muted">Signed in via <span class="tag">` + html.EscapeString(u.Provider) + `</span> — validated by the easy-sso Go package.</p>
    <ul>
      <li><strong>id:</strong> ` + html.EscapeString(u.ID) + `</li>
      <li><strong>email:</strong> ` + html.EscapeString(orDash(u.Email)) + `</li>
      <li><strong>tenant / hd:</strong> ` + html.EscapeString(orDash(u.TenantID)) + `</li>
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
