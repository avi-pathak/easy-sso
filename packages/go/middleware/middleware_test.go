package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/avi-pathak/easy-sso/packages/go/core"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

// stubProvider authenticates the token "good" as a user with the given roles, and
// rejects everything else.
type stubProvider struct {
	roles []string
}

func (s stubProvider) Name() string { return "stub" }

func (s stubProvider) Authenticate(_ context.Context, token string, _ *core.AuthContext) (*core.AuthUser, error) {
	if token != "good" {
		return nil, ssoerr.NewInvalidTokenError("nope", nil)
	}
	return &core.AuthUser{ID: "u1", Roles: s.roles, Provider: "stub"}, nil
}

func okHandler(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFromContext(r.Context())
	w.WriteHeader(http.StatusOK)
	if u != nil {
		_, _ = w.Write([]byte(u.ID))
	} else {
		_, _ = w.Write([]byte("anon"))
	}
}

func TestExtractBearerToken(t *testing.T) {
	cases := map[string]string{
		"Bearer abc":   "abc",
		"bearer abc":   "abc",
		"BEARER  abc ": "abc",
		"Basic abc":    "",
		"":             "",
		"Bearer":       "",
	}
	for in, want := range cases {
		if got := ExtractBearerToken(in); got != want {
			t.Errorf("ExtractBearerToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMiddlewareAttachesUser(t *testing.T) {
	mw := New(stubProvider{}, Options{})
	srv := mw(http.HandlerFunc(okHandler))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "u1" {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareAnonymousByDefault(t *testing.T) {
	mw := New(stubProvider{}, Options{})
	srv := mw(http.HandlerFunc(okHandler))

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "anon" {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareCredentialsRequired(t *testing.T) {
	mw := New(stubProvider{}, Options{CredentialsRequired: true})
	srv := mw(http.HandlerFunc(okHandler))

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatal("missing WWW-Authenticate challenge")
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != string(ssoerr.CodeMissingToken) {
		t.Fatalf("error body = %v", body)
	}
}

func TestMiddlewareInvalidTokenRejected(t *testing.T) {
	mw := New(stubProvider{}, Options{})
	srv := mw(http.HandlerFunc(okHandler))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
}

func TestRequireAuth(t *testing.T) {
	mw := New(stubProvider{}, Options{})
	protected := mw(RequireAuth(nil)(http.HandlerFunc(okHandler)))

	// no token -> 401
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon code = %d, want 401", rec.Code)
	}

	// good token -> 200
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer good")
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("auth code = %d, want 200", rec.Code)
	}
}

func TestRequireRoles(t *testing.T) {
	build := func(provRoles []string, need []string, mode RoleMatchMode) *httptest.ResponseRecorder {
		mw := New(stubProvider{roles: provRoles}, Options{})
		h := mw(RequireRoles(need, mode, nil)(http.HandlerFunc(okHandler)))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer good")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := build([]string{"admin"}, []string{"admin"}, MatchAny); rec.Code != http.StatusOK {
		t.Fatalf("any/has = %d, want 200", rec.Code)
	}
	if rec := build([]string{"reader"}, []string{"admin"}, MatchAny); rec.Code != http.StatusForbidden {
		t.Fatalf("any/missing = %d, want 403", rec.Code)
	}
	if rec := build([]string{"a", "b"}, []string{"a", "b"}, MatchAll); rec.Code != http.StatusOK {
		t.Fatalf("all/has = %d, want 200", rec.Code)
	}
	if rec := build([]string{"a"}, []string{"a", "b"}, MatchAll); rec.Code != http.StatusForbidden {
		t.Fatalf("all/partial = %d, want 403", rec.Code)
	}
}

func TestRequireRolesPanicsWithoutRoles(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for empty roles")
		}
	}()
	RequireRoles(nil, MatchAny, nil)
}
