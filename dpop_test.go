package oauth2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDPoPProofRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kp := &RSAKeyProvider{Key: key}
	proof, err := dpopProof("POST", "https://example.com/token", kp)
	if err != nil {
		t.Fatal(err)
	}
	checkProof(t, proof, "RS256", "POST", "https://example.com/token")
}

func TestDPoPProofEC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp := &ECKeyProvider{Key: key}
	proof, err := dpopProof("GET", "https://example.com/resource", kp)
	if err != nil {
		t.Fatal(err)
	}
	checkProof(t, proof, "ES256", "GET", "https://example.com/resource")
}

func checkProof(t *testing.T, proof, alg, method, url string) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof has %d parts", len(parts))
	}
	hdrB, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(hdrB, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr["typ"] != "dpop+jwt" {
		t.Errorf("typ field = %v", hdr["typ"])
	}
	if hdr["alg"] != alg {
		t.Errorf("alg field = %v, want %s", hdr["alg"], alg)
	}
	claimsB, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsB, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["htm"] != method {
		t.Errorf("htm = %v", claims["htm"])
	}
	if claims["htu"] != url {
		t.Errorf("htu = %v", claims["htu"])
	}
}

func TestServerSupportsDPoP(t *testing.T) {
	meta := `{"dpop_signing_alg_values_supported":["ES256"]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "well-known") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(meta))
	}))
	defer ts.Close()
	url := ts.URL + "/token"
	if !serverSupportsDPoP(context.Background(), url) {
		t.Fatalf("serverSupportsDPoP returned false")
	}
	// cached path should still return true
	if !serverSupportsDPoP(context.Background(), url) {
		t.Fatalf("cached result false")
	}
}
