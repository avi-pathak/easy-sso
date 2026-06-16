package google

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

const clientID = "1234567890-abc.apps.googleusercontent.com"

var fixedNow = time.Unix(1_700_000_000, 0)

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type fakeHTTP struct {
	mu  sync.Mutex
	doc []byte
}

func (f *fakeHTTP) Do(*http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(f.doc)), Header: make(http.Header)}, nil
}

func (f *fakeHTTP) setJWKS(kid string, pub *rsa.PublicKey) {
	eBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(eBuf, uint32(pub.E))
	i := 0
	for i < len(eBuf)-1 && eBuf[i] == 0 {
		i++
	}
	doc := map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(eBuf[i:]),
	}}}
	b, _ := json.Marshal(doc)
	f.mu.Lock()
	f.doc = b
	f.mu.Unlock()
}

func signToken(key *rsa.PrivateKey, kid, alg string, claims map[string]any) string {
	header := map[string]any{"typ": "JWT"}
	if alg != "" {
		header["alg"] = alg
	}
	if kid != "" {
		header["kid"] = kid
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	seg := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	if alg != "RS256" {
		return seg + "."
	}
	digest := sha256.Sum256([]byte(seg))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	return seg + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func baseClaims() map[string]any {
	return map[string]any{
		"iss":   "https://accounts.google.com",
		"aud":   clientID,
		"sub":   "108112098765432101234",
		"email": "ada@example.com",
		"name":  "Ada Lovelace",
		"exp":   float64(fixedNow.Add(time.Hour).Unix()),
		"nbf":   float64(fixedNow.Add(-time.Minute).Unix()),
		"iat":   float64(fixedNow.Add(-time.Minute).Unix()),
	}
}

func setup(t *testing.T) (*rsa.PrivateKey, *fakeHTTP) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	h := &fakeHTTP{}
	h.setJWKS("g-kid-1", &key.PublicKey)
	return key, h
}

func newProvider(t *testing.T, cfg AuthConfig, h *fakeHTTP) *Provider {
	t.Helper()
	cfg.HTTPClient = h
	cfg.Clock = fakeClock{t: fixedNow}
	cfg.JWKS.URI = "https://jwks.test/certs"
	if cfg.ClientID == "" {
		cfg.ClientID = clientID
	}
	p, err := NewProvider(cfg)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

func wantCode(t *testing.T, err error, code ssoerr.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %s, got nil", code)
	}
	ae, ok := ssoerr.As(err)
	if !ok {
		t.Fatalf("error is not *AuthError: %v", err)
	}
	if ae.Code != code {
		t.Fatalf("error code = %s, want %s (%s)", ae.Code, code, ae.Message)
	}
}

func TestValidToken(t *testing.T) {
	key, h := setup(t)
	p := newProvider(t, AuthConfig{}, h)

	user, err := p.Authenticate(context.Background(), signToken(key, "g-kid-1", "RS256", baseClaims()), nil)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if user.ID != "108112098765432101234" || user.Email != "ada@example.com" || user.Provider != "google" {
		t.Fatalf("unexpected user: %+v", user)
	}
	if user.Roles == nil || user.Scopes == nil {
		t.Fatal("roles/scopes must be non-nil")
	}
}

func TestBareIssuerAccepted(t *testing.T) {
	key, h := setup(t)
	p := newProvider(t, AuthConfig{}, h)
	claims := baseClaims()
	claims["iss"] = "accounts.google.com" // bare host form
	if _, err := p.Authenticate(context.Background(), signToken(key, "g-kid-1", "RS256", claims), nil); err != nil {
		t.Fatalf("bare issuer should be accepted: %v", err)
	}
}

func TestWrongAudience(t *testing.T) {
	key, h := setup(t)
	p := newProvider(t, AuthConfig{}, h)
	claims := baseClaims()
	claims["aud"] = "someone-elses-client-id"
	_, err := p.Authenticate(context.Background(), signToken(key, "g-kid-1", "RS256", claims), nil)
	wantCode(t, err, ssoerr.CodeInvalidAudience)
}

func TestWrongIssuer(t *testing.T) {
	key, h := setup(t)
	p := newProvider(t, AuthConfig{}, h)
	claims := baseClaims()
	claims["iss"] = "https://evil.example.com"
	_, err := p.Authenticate(context.Background(), signToken(key, "g-kid-1", "RS256", claims), nil)
	wantCode(t, err, ssoerr.CodeInvalidIssuer)
}

func TestExpired(t *testing.T) {
	key, h := setup(t)
	p := newProvider(t, AuthConfig{}, h)
	claims := baseClaims()
	claims["exp"] = float64(fixedNow.Add(-time.Hour).Unix())
	_, err := p.Authenticate(context.Background(), signToken(key, "g-kid-1", "RS256", claims), nil)
	wantCode(t, err, ssoerr.CodeTokenExpired)
}

func TestBadSignature(t *testing.T) {
	_, h := setup(t)
	p := newProvider(t, AuthConfig{}, h)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := p.Authenticate(context.Background(), signToken(other, "g-kid-1", "RS256", baseClaims()), nil)
	wantCode(t, err, ssoerr.CodeInvalidSignature)
}

func TestAlgNoneRejected(t *testing.T) {
	key, h := setup(t)
	p := newProvider(t, AuthConfig{}, h)
	_, err := p.Authenticate(context.Background(), signToken(key, "g-kid-1", "none", baseClaims()), nil)
	wantCode(t, err, ssoerr.CodeInvalidSignature)
}

func TestHostedDomainEnforced(t *testing.T) {
	key, h := setup(t)
	p := newProvider(t, AuthConfig{HostedDomains: []string{"example.com"}}, h)

	// Token without the right hd is rejected.
	_, err := p.Authenticate(context.Background(), signToken(key, "g-kid-1", "RS256", baseClaims()), nil)
	wantCode(t, err, ssoerr.CodeInvalidIssuer)

	// Token with a matching hd passes, and hd surfaces as TenantID.
	claims := baseClaims()
	claims["hd"] = "example.com"
	user, err := p.Authenticate(context.Background(), signToken(key, "g-kid-1", "RS256", claims), nil)
	if err != nil {
		t.Fatalf("matching hd should pass: %v", err)
	}
	if user.TenantID != "example.com" {
		t.Fatalf("tenantId = %q, want hd", user.TenantID)
	}
}

func TestMissingToken(t *testing.T) {
	_, h := setup(t)
	p := newProvider(t, AuthConfig{}, h)
	_, err := p.Authenticate(context.Background(), "", nil)
	wantCode(t, err, ssoerr.CodeMissingToken)
}

func TestMissingSubject(t *testing.T) {
	key, h := setup(t)
	p := newProvider(t, AuthConfig{}, h)
	claims := baseClaims()
	delete(claims, "sub")
	_, err := p.Authenticate(context.Background(), signToken(key, "g-kid-1", "RS256", claims), nil)
	wantCode(t, err, ssoerr.CodeAuthentication)
}

func TestMultipleAudiences(t *testing.T) {
	key, h := setup(t)
	p := newProvider(t, AuthConfig{Audiences: []string{"web-client", clientID}}, h)
	claims := baseClaims()
	claims["aud"] = "web-client"
	if _, err := p.Authenticate(context.Background(), signToken(key, "g-kid-1", "RS256", claims), nil); err != nil {
		t.Fatalf("extra audience should be accepted: %v", err)
	}
}

func TestConfigRequiresClientID(t *testing.T) {
	_, err := NewProvider(AuthConfig{})
	wantCode(t, err, ssoerr.CodeConfiguration)
}
