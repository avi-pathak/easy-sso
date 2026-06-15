package microsoft

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/core"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

// acceptedAlgorithm is the only signing algorithm accepted. Pinning it is a hard
// security boundary: it blocks alg:none and RSA/HMAC confusion attacks. Entra
// signs with RS256, so this is intentionally not configurable.
const acceptedAlgorithm = "RS256"

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// TokenValidator validates Microsoft Entra ID tokens end-to-end: signature,
// issuer, audience, expiry (exp), not-before (nbf), tenant, and token version.
type TokenValidator struct {
	cfg  config.NormalizedMicrosoftConfig
	jwks *JWKSClient
}

// NewTokenValidator constructs a TokenValidator.
func NewTokenValidator(cfg config.NormalizedMicrosoftConfig, jwks *JWKSClient) *TokenValidator {
	return &TokenValidator{cfg: cfg, jwks: jwks}
}

// Validate verifies a token and returns its validated claims. No claim is trusted
// until the signature has been cryptographically verified.
func (v *TokenValidator) Validate(token string) (core.Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ssoerr.NewInvalidTokenError("Token could not be decoded", map[string]any{"cause": "expected 3 segments"})
	}

	header, err := decodeHeader(parts[0])
	if err != nil {
		return nil, err
	}
	claims, err := decodeClaims(parts[1])
	if err != nil {
		return nil, err
	}

	// Step 1: peek (untrusted) to resolve the expected issuer.
	version, err := v.resolveVersion(claims)
	if err != nil {
		return nil, err
	}
	tid, err := requireTid(claims)
	if err != nil {
		return nil, err
	}
	expectedIssuer := ResolveExpectedIssuer(tid, version, v.cfg)

	// Step 2: cryptographic verification + standard claim checks.
	if err := v.verifySignature(parts, header); err != nil {
		return nil, err
	}
	if err := v.verifyClaims(claims, expectedIssuer); err != nil {
		return nil, err
	}

	// Step 3: policy on the now-verified payload.
	if err := AssertTenantAllowed(tid, v.cfg); err != nil {
		return nil, err
	}
	if err := v.assertVersionAccepted(version); err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *TokenValidator) verifySignature(parts []string, header jwtHeader) error {
	if header.Alg != acceptedAlgorithm {
		return ssoerr.NewInvalidSignatureError("Unsupported or unsafe token signing algorithm", map[string]any{"alg": header.Alg})
	}
	if header.Kid == "" {
		return ssoerr.NewInvalidSignatureError("Token header is missing a key id (kid)", nil)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ssoerr.NewInvalidTokenError("Token signature is not valid base64url", nil)
	}
	signingInput := parts[0] + "." + parts[1]

	key, ok, err := v.jwks.GetKey(header.Kid)
	if err != nil {
		return ssoerr.Coerce(err)
	}
	if !ok {
		// A missing kid usually means signing keys rotated since we cached them.
		// Force one refresh and retry before giving up.
		key, ok, err = v.jwks.RefreshKey(header.Kid)
		if err != nil {
			return ssoerr.Coerce(err)
		}
		if !ok {
			return ssoerr.NewInvalidSignatureError("No matching signing key was found for the token", map[string]any{"kid": header.Kid})
		}
	}

	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return ssoerr.NewInvalidSignatureError("Token signature verification failed", nil)
	}
	return nil
}

func (v *TokenValidator) verifyClaims(claims core.Claims, expectedIssuer string) error {
	now := v.cfg.Clock.Now()
	tol := v.cfg.ClockTolerance

	iss, _ := claims.String("iss")
	if iss != expectedIssuer {
		return ssoerr.NewInvalidIssuerError("Token issuer is invalid", map[string]any{"expected": expectedIssuer, "actual": iss})
	}

	if !audienceMatches(claims["aud"], v.cfg.Audiences) {
		return ssoerr.NewInvalidAudienceError("Token audience is invalid", map[string]any{"expected": v.cfg.Audiences})
	}

	exp, ok := claims.Float("exp")
	if !ok {
		return ssoerr.NewInvalidTokenError("Token is missing the exp claim", nil)
	}
	if now.After(time.Unix(int64(exp), 0).Add(tol)) {
		return ssoerr.NewTokenExpiredError("Token has expired", map[string]any{"claim": "exp"})
	}

	if nbf, ok := claims.Float("nbf"); ok {
		if now.Before(time.Unix(int64(nbf), 0).Add(-tol)) {
			return ssoerr.NewTokenNotYetValidError("Token is not yet valid", map[string]any{"claim": "nbf"})
		}
	}
	return nil
}

func audienceMatches(aud any, accepted []string) bool {
	switch a := aud.(type) {
	case string:
		return containsString(accepted, a)
	case []any:
		for _, item := range a {
			if s, ok := item.(string); ok && containsString(accepted, s) {
				return true
			}
		}
	}
	return false
}

func containsString(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

func (v *TokenValidator) resolveVersion(claims core.Claims) (config.TokenVersion, error) {
	if ver, ok := claims.String("ver"); ok {
		switch ver {
		case "2.0":
			return config.TokenV2, nil
		case "1.0":
			return config.TokenV1, nil
		}
	}
	// Fall back to inferring from the issuer shape when ver is absent.
	iss, _ := claims.String("iss")
	if strings.HasSuffix(iss, "/v2.0") {
		return config.TokenV2, nil
	}
	if iss != "" && strings.Contains(iss, v.cfg.V1IssuerHost) {
		return config.TokenV1, nil
	}
	return "", ssoerr.NewInvalidTokenError("Unable to determine token version", nil)
}

func requireTid(claims core.Claims) (string, error) {
	if tid, ok := claims.String("tid"); ok {
		return tid, nil
	}
	return "", ssoerr.NewInvalidIssuerError("Token is missing the tenant id (tid) claim", nil)
}

func (v *TokenValidator) assertVersionAccepted(version config.TokenVersion) error {
	for _, a := range v.cfg.AcceptedVersions {
		if a == version {
			return nil
		}
	}
	return ssoerr.NewInvalidTokenError("Token version is not accepted", map[string]any{
		"accepted": v.cfg.AcceptedVersions,
		"actual":   version,
	})
}

func decodeHeader(seg string) (jwtHeader, error) {
	var h jwtHeader
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return h, ssoerr.NewInvalidTokenError("Token header is not valid base64url", nil)
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return h, ssoerr.NewInvalidTokenError("Token header is not valid JSON", nil)
	}
	return h, nil
}

func decodeClaims(seg string) (core.Claims, error) {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, ssoerr.NewInvalidTokenError("Token payload is not valid base64url", nil)
	}
	var c core.Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, ssoerr.NewInvalidTokenError("Token payload is not valid JSON", nil)
	}
	return c, nil
}
