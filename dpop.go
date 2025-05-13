package oauth2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2/internal"
)

// KeyProvider governs how DPoP proofs are created.
// Implementations are expected to manage the private key
// material necessary to sign the JWT-based proof.
type KeyProvider interface {
	// Algorithm returns the JOSE algorithm used for signing.
	Algorithm() string

	// JWK returns the public key in JWK form and an optional key ID.
	JWK() (map[string]any, string, error)

	// Sign signs the provided data. The data will be the
	// base64url-encoded header and body of the DPoP proof.
	Sign(data []byte) ([]byte, error)
}

// RSAKeyProvider is a KeyProvider based on an RSA private key.
type RSAKeyProvider struct {
	Key   *rsa.PrivateKey
	KeyID string
}

// Algorithm returns the signing algorithm.
func (p *RSAKeyProvider) Algorithm() string { return "RS256" }

// JWK implements KeyProvider.
func (p *RSAKeyProvider) JWK() (map[string]any, string, error) {
	if p.Key == nil {
		return nil, "", errors.New("nil rsa key")
	}
	pub := p.Key.Public().(*rsa.PublicKey)
	m := map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	return m, p.KeyID, nil
}

// Sign implements KeyProvider.
func (p *RSAKeyProvider) Sign(data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, p.Key, crypto.SHA256, h[:])
}

// ECKeyProvider is a KeyProvider backed by an ECDSA private key.
type ECKeyProvider struct {
	Key   *ecdsa.PrivateKey
	KeyID string
}

func (p *ECKeyProvider) Algorithm() string {
	switch p.Key.Curve {
	case elliptic.P256():
		return "ES256"
	case elliptic.P384():
		return "ES384"
	case elliptic.P521():
		return "ES512"
	}
	return ""
}

func (p *ECKeyProvider) JWK() (map[string]any, string, error) {
	if p.Key == nil {
		return nil, "", errors.New("nil ecdsa key")
	}
	pub := p.Key.Public().(*ecdsa.PublicKey)
	size := (pub.Curve.Params().BitSize + 7) / 8
	x := append(make([]byte, size-len(pub.X.Bytes())), pub.X.Bytes()...)
	y := append(make([]byte, size-len(pub.Y.Bytes())), pub.Y.Bytes()...)
	m := map[string]any{
		"kty": "EC",
		"crv": curveName(pub.Curve),
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	}
	return m, p.KeyID, nil
}

func (p *ECKeyProvider) Sign(data []byte) ([]byte, error) {
	hFunc := hashForCurve(p.Key.Curve)
	if hFunc == 0 {
		return nil, errors.New("unsupported curve")
	}
	h := hFunc.New()
	h.Write(data)
	digest := h.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, p.Key, digest)
	if err != nil {
		return nil, err
	}
	size := (p.Key.Curve.Params().BitSize + 7) / 8
	rb := append(make([]byte, size-len(r.Bytes())), r.Bytes()...)
	sb := append(make([]byte, size-len(s.Bytes())), s.Bytes()...)
	return append(rb, sb...), nil
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func curveName(c elliptic.Curve) string {
	switch c {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	}
	return ""
}

func hashForCurve(c elliptic.Curve) crypto.Hash {
	switch c {
	case elliptic.P256():
		return crypto.SHA256
	case elliptic.P384():
		return crypto.SHA384
	case elliptic.P521():
		return crypto.SHA512
	}
	return 0
}

func dpopProof(method, rawurl string, kp KeyProvider) (string, error) {
	now := time.Now().Unix()
	hdr := map[string]any{
		"typ": "dpop+jwt",
		"alg": kp.Algorithm(),
	}
	jwk, kid, err := kp.JWK()
	if err != nil {
		return "", err
	}
	if kid != "" {
		hdr["kid"] = kid
	}
	if jwk != nil {
		hdr["jwk"] = jwk
	}
	claims := map[string]any{
		"htu": rawurl,
		"htm": strings.ToUpper(method),
		"iat": now,
		"jti": randomID(),
	}
	hb, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	hEnc := base64.RawURLEncoding.EncodeToString(hb)
	cEnc := base64.RawURLEncoding.EncodeToString(cb)
	data := []byte(hEnc + "." + cEnc)
	sig, err := kp.Sign(data)
	if err != nil {
		return "", err
	}
	return hEnc + "." + cEnc + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

var (
	dpopCache sync.Map
)

func serverSupportsDPoP(ctx context.Context, tokenURL string) bool {
	u, err := url.Parse(tokenURL)
	if err != nil {
		return false
	}
	key := u.Scheme + "://" + u.Host
	if v, ok := dpopCache.Load(key); ok {
		return v.(bool)
	}
	paths := []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"}
	for _, p := range paths {
		metaURL := key + p
		req, _ := http.NewRequestWithContext(ctx, "GET", metaURL, nil)
		res, err := internal.ContextClient(ctx).Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 {
			continue
		}
		var m struct {
			Algs []string `json:"dpop_signing_alg_values_supported"`
		}
		if json.Unmarshal(body, &m) == nil && len(m.Algs) > 0 {
			dpopCache.Store(key, true)
			return true
		}
	}
	dpopCache.Store(key, false)
	return false
}
