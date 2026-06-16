package microsoft

import (
	"strings"

	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/core"
	"github.com/avi-pathak/easy-sso/packages/go/internal/oidc"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

// TokenValidator validates Microsoft Entra ID tokens end-to-end: signature,
// issuer, audience, expiry (exp), not-before (nbf), tenant, and token version.
type TokenValidator struct {
	cfg  config.NormalizedMicrosoftConfig
	jwks *oidc.JWKSClient
}

// NewTokenValidator constructs a TokenValidator.
func NewTokenValidator(cfg config.NormalizedMicrosoftConfig, jwks *oidc.JWKSClient) *TokenValidator {
	return &TokenValidator{cfg: cfg, jwks: jwks}
}

// Validate verifies a token and returns its validated claims. No claim is trusted
// until the signature has been cryptographically verified.
func (v *TokenValidator) Validate(token string) (core.Claims, error) {
	header, claims, parts, err := oidc.Decode(token)
	if err != nil {
		return nil, err
	}

	// Step 1: peek (untrusted) to resolve the expected issuer. With
	// common/organizations the issuer is not fixed — it embeds the real tenant.
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
	if err := oidc.VerifySignature(v.jwks, parts, header); err != nil {
		return nil, err
	}
	if err := oidc.VerifyStandardClaims(claims, oidc.ClaimsOptions{
		Issuers:   []string{expectedIssuer},
		Audiences: v.cfg.Audiences,
		Now:       v.cfg.Clock.Now(),
		Tolerance: v.cfg.ClockTolerance,
	}); err != nil {
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
