package console

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

func TestSAMLIntegrationReadsOnlyFixedPublicMetadata(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var payload []byte
	status, requests := 200, 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		responseStatus, responsePayload := status, payload
		requests++
		mu.Unlock()
		if r.URL.Path != "/saml/metadata" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected metadata request")
		}
		w.Header().Set("Location", "/must-not-follow")
		w.WriteHeader(responseStatus)
		_, _ = w.Write(responsePayload)
	}))
	defer server.Close()
	metadata := saml.EntityDescriptor{EntityID: server.URL + "/saml/metadata", IDPSSODescriptors: []saml.IDPSSODescriptor{{SSODescriptor: saml.SSODescriptor{KeyDescriptors: []saml.KeyDescriptor{{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(der)}}}}}}}, SingleSignOnServices: []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: server.URL + "/saml/sso"}}}}}
	mu.Lock()
	payload, _ = xml.Marshal(metadata)
	mu.Unlock()
	result := inspectSAMLIdentityProvider(t.Context(), server.URL)
	digest := sha256.Sum256(der)
	if result.Status != "available" || result.Certificate == nil || result.Certificate.SHA256 != hex.EncodeToString(digest[:]) || result.Certificate.Status != "valid" || result.CheckedAt.IsZero() {
		t.Fatal(result)
	}
	block, remaining := pem.Decode([]byte(result.Certificate.PEM))
	if block == nil || block.Type != "CERTIFICATE" || len(remaining) != 0 || string(block.Bytes) != string(der) || strings.Contains(result.Certificate.PEM, "PRIVATE") {
		t.Fatal("export differs from published public certificate")
	}
	original := append([]byte(nil), payload...)
	for _, tc := range []struct {
		name    string
		status  int
		payload []byte
	}{
		{"redirect", 302, original}, {"disabled", 404, nil}, {"unavailable", 503, nil}, {"oversized", 200, []byte(strings.Repeat("x", (64<<10)+1))}, {"invalid XML", 200, []byte("bad")},
		{"foreign issuer", 200, []byte(strings.Replace(string(original), metadata.EntityID, "https://foreign.example.invalid/metadata", 1))},
		{"foreign SSO", 200, []byte(strings.Replace(string(original), server.URL+"/saml/sso", "https://foreign.example.invalid/sso", 1))},
		{"invalid certificate", 200, []byte(strings.Replace(string(original), base64.StdEncoding.EncodeToString(der), "invalid", 1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			status, payload = tc.status, tc.payload
			before := requests
			mu.Unlock()
			got := inspectSAMLIdentityProvider(t.Context(), server.URL)
			mu.Lock()
			count := requests - before
			mu.Unlock()
			if got.Status != "unavailable" || got.Certificate != nil || count != 1 {
				t.Fatal(got, count)
			}
		})
	}
}
