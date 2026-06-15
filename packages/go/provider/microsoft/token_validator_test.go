package microsoft

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

const clientID = "api-client-id"

func setup(t *testing.T) (*rsa.PrivateKey, *fakeHTTP, *fakeClock) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	h := &fakeHTTP{}
	h.setJWKS(jwkFor("kid-1", &key.PublicKey))
	return key, h, newClock()
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

func TestValidTokenAuthenticates(t *testing.T) {
	key, h, clk := setup(t)
	p := newTestProvider(t, config.MicrosoftAuthConfig{ClientID: clientID, TenantID: testTenant}, h, clk)

	tok := signToken(key, "kid-1", "RS256", baseClaims(clientID))
	id, err := authenticate(p, tok)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if id != "user-object-id" {
		t.Fatalf("id = %q, want oid", id)
	}
}

func TestExpiredToken(t *testing.T) {
	key, h, clk := setup(t)
	p := newTestProvider(t, config.MicrosoftAuthConfig{ClientID: clientID, TenantID: testTenant}, h, clk)

	claims := baseClaims(clientID)
	claims["exp"] = float64(fixedNow.Add(-time.Hour).Unix())
	_, err := authenticate(p, signToken(key, "kid-1", "RS256", claims))
	wantCode(t, err, ssoerr.CodeTokenExpired)
}

func TestNotYetValidToken(t *testing.T) {
	key, h, clk := setup(t)
	p := newTestProvider(t, config.MicrosoftAuthConfig{ClientID: clientID, TenantID: testTenant}, h, clk)

	claims := baseClaims(clientID)
	claims["nbf"] = float64(fixedNow.Add(time.Hour).Unix())
	_, err := authenticate(p, signToken(key, "kid-1", "RS256", claims))
	wantCode(t, err, ssoerr.CodeTokenNotYetValid)
}

func TestWrongAudience(t *testing.T) {
	key, h, clk := setup(t)
	p := newTestProvider(t, config.MicrosoftAuthConfig{ClientID: clientID, TenantID: testTenant}, h, clk)

	claims := baseClaims(clientID)
	claims["aud"] = "some-other-app"
	_, err := authenticate(p, signToken(key, "kid-1", "RS256", claims))
	wantCode(t, err, ssoerr.CodeInvalidAudience)
}

func TestWrongTenant(t *testing.T) {
	key, h, clk := setup(t)
	// Configured for a specific tenant; token is from a different one.
	p := newTestProvider(t, config.MicrosoftAuthConfig{ClientID: clientID, TenantID: "99999999-2222-3333-4444-555555555555"}, h, clk)

	_, err := authenticate(p, signToken(key, "kid-1", "RS256", baseClaims(clientID)))
	wantCode(t, err, ssoerr.CodeInvalidIssuer)
}

func TestBadSignature(t *testing.T) {
	_, h, clk := setup(t)
	p := newTestProvider(t, config.MicrosoftAuthConfig{ClientID: clientID, TenantID: testTenant}, h, clk)

	// Sign with a different key than the one published in the JWKS.
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := authenticate(p, signToken(otherKey, "kid-1", "RS256", baseClaims(clientID)))
	wantCode(t, err, ssoerr.CodeInvalidSignature)
}

func TestAlgNoneRejected(t *testing.T) {
	key, h, clk := setup(t)
	p := newTestProvider(t, config.MicrosoftAuthConfig{ClientID: clientID, TenantID: testTenant}, h, clk)

	_, err := authenticate(p, signToken(key, "kid-1", "none", baseClaims(clientID)))
	wantCode(t, err, ssoerr.CodeInvalidSignature)
}

func TestKeyRotationRefresh(t *testing.T) {
	key, h, clk := setup(t)
	// Publish a stale JWKS that does NOT contain kid-2 yet.
	p := newTestProvider(t, config.MicrosoftAuthConfig{ClientID: clientID, TenantID: testTenant}, h, clk)
	if err := p.jwks.Prime(); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Rotate: the server now serves kid-2 (signed below).
	rotated, _ := rsa.GenerateKey(rand.Reader, 2048)
	h.setJWKS(jwkFor("kid-2", &rotated.PublicKey))

	tok := signToken(rotated, "kid-2", "RS256", baseClaims(clientID))
	id, err := authenticate(p, tok)
	if err != nil {
		t.Fatalf("authenticate after rotation: %v", err)
	}
	if id != "user-object-id" {
		t.Fatalf("id = %q", id)
	}
	_ = key
}

func TestMissingTokenIsMissingTokenError(t *testing.T) {
	_, h, clk := setup(t)
	p := newTestProvider(t, config.MicrosoftAuthConfig{ClientID: clientID, TenantID: testTenant}, h, clk)
	_, err := authenticate(p, "")
	wantCode(t, err, ssoerr.CodeMissingToken)
}

func TestMalformedToken(t *testing.T) {
	_, h, clk := setup(t)
	p := newTestProvider(t, config.MicrosoftAuthConfig{ClientID: clientID, TenantID: testTenant}, h, clk)
	_, err := authenticate(p, "not-a-jwt")
	wantCode(t, err, ssoerr.CodeInvalidToken)
}

func TestRejectedVersion(t *testing.T) {
	key, h, clk := setup(t)
	p := newTestProvider(t, config.MicrosoftAuthConfig{
		ClientID:         clientID,
		TenantID:         testTenant,
		AcceptedVersions: []config.TokenVersion{config.TokenV1},
	}, h, clk)

	// A valid v2.0 token, but only v1.0 is accepted.
	_, err := authenticate(p, signToken(key, "kid-1", "RS256", baseClaims(clientID)))
	wantCode(t, err, ssoerr.CodeInvalidToken)
}
