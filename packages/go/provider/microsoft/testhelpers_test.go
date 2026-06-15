package microsoft

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
	"time"

	"github.com/avi-pathak/easy-sso/packages/go/config"
)

// fakeClock is a deterministic clock for tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

var fixedNow = time.Unix(1_700_000_000, 0)

func newClock() *fakeClock { return &fakeClock{t: fixedNow} }

// fakeHTTP serves a canned JWKS document and counts requests so key-rotation
// behavior can be asserted.
type fakeHTTP struct {
	mu       sync.Mutex
	doc      []byte
	status   int
	requests int
}

func (f *fakeHTTP) Do(*http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	status := f.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(f.doc)),
		Header:     make(http.Header),
	}, nil
}

func (f *fakeHTTP) setJWKS(keys ...keyEntry) {
	doc := map[string]any{"keys": keys}
	b, _ := json.Marshal(doc)
	f.mu.Lock()
	f.doc = b
	f.mu.Unlock()
}

func (f *fakeHTTP) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

type keyEntry struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

func jwkFor(kid string, pub *rsa.PublicKey) keyEntry {
	eBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(eBuf, uint32(pub.E))
	// trim leading zero bytes of the exponent
	i := 0
	for i < len(eBuf)-1 && eBuf[i] == 0 {
		i++
	}
	return keyEntry{
		Kty: "RSA",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eBuf[i:]),
		Use: "sig",
		Alg: "RS256",
	}
}

// signToken builds a JWT and signs it RS256 with key. Pass alg="none" / empty kid
// to exercise rejection paths.
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
		// Unsigned / unsupported alg: append empty signature.
		return seg + "."
	}
	digest := sha256.Sum256([]byte(seg))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	return seg + "." + base64.RawURLEncoding.EncodeToString(sig)
}

const testTenant = "11111111-2222-3333-4444-555555555555"

// baseClaims returns a valid v2.0 claim set for testTenant against clientID.
func baseClaims(clientID string) map[string]any {
	return map[string]any{
		"ver": "2.0",
		"iss": "https://login.microsoftonline.com/" + testTenant + "/v2.0",
		"aud": clientID,
		"tid": testTenant,
		"oid": "user-object-id",
		"sub": "subject-123",
		"exp": float64(fixedNow.Add(time.Hour).Unix()),
		"nbf": float64(fixedNow.Add(-time.Minute).Unix()),
		"iat": float64(fixedNow.Add(-time.Minute).Unix()),
	}
}

// newTestProvider wires a provider against a fake JWKS server holding kid->pub.
func newTestProvider(t testingTB, cfg config.MicrosoftAuthConfig, http *fakeHTTP, clk *fakeClock) *Provider {
	cfg.HTTPClient = http
	cfg.Clock = clk
	cfg.JWKS.URI = "https://jwks.test/keys"
	p, err := NewProvider(cfg)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

// testingTB is the subset of *testing.T used by helpers.
type testingTB interface {
	Fatalf(format string, args ...any)
}

func authenticate(p *Provider, token string) (string, error) {
	u, err := p.Authenticate(context.Background(), token, nil)
	if err != nil {
		return "", err
	}
	return u.ID, nil
}
