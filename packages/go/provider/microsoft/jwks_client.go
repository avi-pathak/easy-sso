package microsoft

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/avi-pathak/easy-sso/packages/go/cache"
	"github.com/avi-pathak/easy-sso/packages/go/config"
	"github.com/avi-pathak/easy-sso/packages/go/ssoerr"
)

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

// keySet maps a key id (kid) to a parsed RSA public key.
type keySet map[string]*rsa.PublicKey

// JWKSClientOptions configures a JWKSClient.
type JWKSClientOptions struct {
	JWKSURI         string
	TTL             time.Duration
	RefreshInterval time.Duration
	HTTPClient      config.HTTPClient
	Clock           cache.Clock
}

// JWKSClient fetches and caches the Microsoft JWKS as parsed RSA public keys.
// Caching, single-flight dedup, TTL, and background refresh are delegated to the
// generic MemoryKeyCache; this type only knows how to fetch and parse a JWKS.
type JWKSClient struct {
	uri    string
	cache  *cache.MemoryKeyCache[keySet]
	client config.HTTPClient
}

// NewJWKSClient constructs a JWKSClient.
func NewJWKSClient(opts JWKSClientOptions) *JWKSClient {
	c := &JWKSClient{uri: opts.JWKSURI, client: opts.HTTPClient}
	c.cache = cache.New[keySet](cache.Options[keySet]{
		TTL:             opts.TTL,
		RefreshInterval: opts.RefreshInterval,
		Clock:           opts.Clock,
		Loader: func(uri string) (keySet, error) {
			return c.fetch(context.Background(), uri)
		},
	})
	return c
}

func (c *JWKSClient) fetch(ctx context.Context, uri string) (keySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, ssoerr.NewAuthenticationError("Failed to build the JWKS request", map[string]any{"uri": uri, "cause": err.Error()})
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, ssoerr.NewAuthenticationError("Failed to reach the JWKS endpoint", map[string]any{"uri": uri, "cause": err.Error()})
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ssoerr.NewAuthenticationError(
			fmt.Sprintf("JWKS endpoint responded with HTTP %d", resp.StatusCode),
			map[string]any{"uri": uri, "status": resp.StatusCode},
		)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ssoerr.NewAuthenticationError("Failed to read the JWKS response", map[string]any{"uri": uri})
	}

	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil || doc.Keys == nil {
		return nil, ssoerr.NewAuthenticationError("JWKS endpoint returned a malformed key set", map[string]any{"uri": uri})
	}

	set := make(keySet, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pub, err := parseRSAKey(k.N, k.E)
		if err != nil {
			continue
		}
		set[k.Kid] = pub
	}
	if len(set) == 0 {
		return nil, ssoerr.NewAuthenticationError("JWKS endpoint returned no usable RSA keys", map[string]any{"uri": uri})
	}
	return set, nil
}

func parseRSAKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// GetKey resolves the RSA public key for kid, loading the JWKS on miss.
func (c *JWKSClient) GetKey(kid string) (*rsa.PublicKey, bool, error) {
	set, err := c.cache.Get(c.uri)
	if err != nil {
		return nil, false, err
	}
	k, ok := set[kid]
	return k, ok, nil
}

// RefreshKey forces a JWKS refresh and resolves kid against the fresh set. Used
// when the cached set lacks a kid (likely a key rotation).
func (c *JWKSClient) RefreshKey(kid string) (*rsa.PublicKey, bool, error) {
	set, err := c.cache.Refresh(c.uri)
	if err != nil {
		return nil, false, err
	}
	k, ok := set[kid]
	return k, ok, nil
}

// Prime eagerly warms the cache. Safe to call at startup; idempotent under load.
func (c *JWKSClient) Prime() error {
	_, err := c.cache.Get(c.uri)
	return err
}

// Dispose releases the underlying cache (timers, entries).
func (c *JWKSClient) Dispose() { c.cache.Dispose() }
