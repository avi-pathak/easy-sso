package oidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/avi-pathak/easy-sso/packages/go/core"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

// AcceptedAlgorithm is the only signing algorithm accepted. Pinning it is a hard
// security boundary: it blocks alg:none and RSA/HMAC confusion attacks.
const AcceptedAlgorithm = "RS256"

// Header is the protected header of a JWS/JWT (the fields we inspect).
type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Decode splits and base64url-decodes a compact JWT into its header, claims, and
// raw segments. No signature verification is performed.
func Decode(token string) (Header, core.Claims, []string, error) {
	var header Header
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return header, nil, nil, ssoerr.NewInvalidTokenError("Token could not be decoded", map[string]any{"cause": "expected 3 segments"})
	}
	header, err := decodeHeader(parts[0])
	if err != nil {
		return header, nil, nil, err
	}
	claims, err := decodeClaims(parts[1])
	if err != nil {
		return header, nil, nil, err
	}
	return header, claims, parts, nil
}

func decodeHeader(seg string) (Header, error) {
	var h Header
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

// VerifySignature verifies a token's RS256 signature against the JWKS held by
// client. It pins RS256, resolves the signing key by kid (refreshing once on a
// miss to absorb key rotation), and returns a typed AuthError on failure.
func VerifySignature(client *JWKSClient, parts []string, header Header) error {
	if header.Alg != AcceptedAlgorithm {
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

	key, ok, err := client.GetKey(header.Kid)
	if err != nil {
		return ssoerr.Coerce(err)
	}
	if !ok {
		// A missing kid usually means signing keys rotated since we cached them.
		key, ok, err = client.RefreshKey(header.Kid)
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

// ClaimsOptions configures standard-claim validation.
type ClaimsOptions struct {
	// Issuers are the acceptable iss values (the token must match one).
	Issuers []string
	// Audiences are the acceptable aud values (the token must match one).
	Audiences []string
	// Now is the reference time for exp/nbf checks.
	Now time.Time
	// Tolerance is the clock-skew allowance for exp/nbf.
	Tolerance time.Duration
}

// VerifyStandardClaims validates iss, aud, exp, and nbf against opts. The token
// must already have a verified signature.
func VerifyStandardClaims(claims core.Claims, opts ClaimsOptions) error {
	iss, _ := claims.String("iss")
	if !containsString(opts.Issuers, iss) {
		return ssoerr.NewInvalidIssuerError("Token issuer is invalid", map[string]any{"expected": opts.Issuers, "actual": iss})
	}
	if !audienceMatches(claims["aud"], opts.Audiences) {
		return ssoerr.NewInvalidAudienceError("Token audience is invalid", map[string]any{"expected": opts.Audiences})
	}
	exp, ok := claims.Float("exp")
	if !ok {
		return ssoerr.NewInvalidTokenError("Token is missing the exp claim", nil)
	}
	if opts.Now.After(time.Unix(int64(exp), 0).Add(opts.Tolerance)) {
		return ssoerr.NewTokenExpiredError("Token has expired", map[string]any{"claim": "exp"})
	}
	if nbf, ok := claims.Float("nbf"); ok {
		if opts.Now.Before(time.Unix(int64(nbf), 0).Add(-opts.Tolerance)) {
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

// SourcesFor returns custom if non-empty, else def. Used for config-driven claim
// mapping with per-provider defaults.
func SourcesFor(custom, def []string) []string {
	if len(custom) > 0 {
		return custom
	}
	return def
}

// FirstString returns the first source claim whose value is a non-empty string.
func FirstString(claims core.Claims, sources []string) (string, bool) {
	for _, s := range sources {
		if v, ok := claims.String(s); ok {
			return v, true
		}
	}
	return "", false
}

// StringArray collects a string slice from the first matching source. Accepts
// either a real array of strings or a space-delimited string. Returns a non-nil
// (possibly empty) slice.
func StringArray(claims core.Claims, sources []string) []string {
	for _, s := range sources {
		switch v := claims[s].(type) {
		case []any:
			out := make([]string, 0, len(v))
			for _, item := range v {
				if str, ok := item.(string); ok && str != "" {
					out = append(out, str)
				}
			}
			return out
		case []string:
			out := make([]string, 0, len(v))
			for _, str := range v {
				if str != "" {
					out = append(out, str)
				}
			}
			return out
		case string:
			if v != "" {
				return strings.Fields(v)
			}
		}
	}
	return []string{}
}
