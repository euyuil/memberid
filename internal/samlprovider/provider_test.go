package samlprovider

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	dsig "github.com/russellhaering/goxmldsig"
)

func signingFixture(t *testing.T) *config.SAMLSigning {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &config.SAMLSigning{Key: key, Certificate: cert}
}

func redirectRequest(t *testing.T, document []byte, key *rsa.PrivateKey) *http.Request {
	t.Helper()
	var compressed bytes.Buffer
	writer, _ := flate.NewWriter(&compressed, flate.DefaultCompression)
	_, _ = writer.Write(document)
	_ = writer.Close()
	query := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(compressed.Bytes())) + "&RelayState=" + url.QueryEscape("opaque-state")
	if key != nil {
		query += "&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
		hash := sha256.Sum256([]byte(query))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if err != nil {
			t.Fatal(err)
		}
		query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))
	}
	return httptest.NewRequest("GET", "https://idp.example.test/saml/sso?"+query, nil)
}

func TestRequestPolicyAndSignedResponse(t *testing.T) {
	signing := signingFixture(t)
	provider, err := New("https://idp.example.test", signing)
	if err != nil {
		t.Fatal(err)
	}
	sp := identity.SAMLServiceProvider{ID: "example", EntityID: "https://sp.example.test/metadata", ACSURL: "https://sp.example.test/acs", Enabled: true, SigningCertificates: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signing.Certificate.Raw}))}, Revision: 1}
	input := saml.AuthnRequest{ID: "_request", Version: "2.0", IssueInstant: time.Now().UTC(), Destination: "https://idp.example.test/saml/sso", Issuer: &saml.Issuer{Value: sp.EntityID}, AssertionConsumerServiceURL: sp.ACSURL, ProtocolBinding: saml.HTTPPostBinding}
	document, _ := xml.Marshal(input)
	r := redirectRequest(t, document, signing.Key)
	issuer, err := Inspect(r)
	if err != nil || issuer != sp.EntityID {
		t.Fatal("request inspection failed", err)
	}
	txn, status, err := provider.Parse(r, sp, time.Now())
	if err != nil || status != "" {
		t.Fatal("signed request rejected", status, err)
	}
	unsigned := redirectRequest(t, document, nil)
	if _, _, err := provider.Parse(unsigned, sp, time.Now()); err == nil {
		t.Fatal("accepted unsigned request without registration permission")
	}
	sp.AllowUnsignedRequests = true
	for _, extension := range []string{
		`<NameIDPolicy xmlns="urn:unsupported" AllowCreate="true"/>`,
		`<NameIDPolicy xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:x="urn:unsupported" x:AllowCreate="true"/>`,
		`<Extensions xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/>`,
	} {
		modified := strings.Replace(string(document), "</AuthnRequest>", extension+"</AuthnRequest>", 1)
		if _, status, err := provider.Parse(redirectRequest(t, []byte(modified), nil), sp, time.Now()); err == nil && status == "" {
			t.Fatal("accepted unsupported request extension")
		}
	}
	if _, _, err := provider.Parse(unsigned, sp, time.Now()); err != nil {
		t.Fatal("explicit unsigned policy rejected", err)
	}
	tampered := r.Clone(r.Context())
	copyURL := *r.URL
	tampered.URL = &copyURL
	tampered.URL.RawQuery = strings.Replace(r.URL.RawQuery, "opaque-state", "modified", 1)
	if _, _, err := provider.Parse(tampered, sp, time.Now()); err == nil {
		t.Fatal("invalid signature downgraded to unsigned")
	}
	r = WithNonce(r)
	now := time.Now().UTC()
	for _, status := range []string{"", "RequestUnsupported", "NoPassive", "InvalidNameIDPolicy"} {
		body, err := provider.Response(r, txn, sp, Authentication{NameID: "opaque-name", SessionID: "session", AuthenticatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}, status, now)
		if err != nil {
			t.Fatal(err)
		}
		start := strings.Index(string(body), `name="SAMLResponse" value="`)
		if start < 0 {
			t.Fatal("missing response")
		}
		raw := strings.SplitN(string(body)[start+len(`name="SAMLResponse" value="`):], `"`, 2)[0]
		decoded, err := base64.StdEncoding.DecodeString(html.UnescapeString(raw))
		if err != nil {
			t.Fatal(err)
		}
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(decoded); err != nil {
			t.Fatal(err)
		}
		validator := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{signing.Certificate}})
		verified, err := validator.Validate(doc.Root())
		if err != nil {
			t.Fatal("response signature", err)
		}
		var response saml.Response
		if xml.Unmarshal(mustXML(t, verified), &response) != nil {
			t.Fatal("invalid response")
		}
		if response.InResponseTo != "_request" || response.Destination != sp.ACSURL || response.Issuer.Value != "https://idp.example.test/saml/metadata" {
			t.Fatal("incorrect response binding")
		}
		if status != "" {
			if response.Assertion != nil || response.Status.StatusCode.Value == saml.StatusSuccess {
				t.Fatal("successful assertion in error")
			}
			continue
		}
		assertion := verified.FindElement("./Assertion")
		if assertion == nil {
			t.Fatal("no assertion")
		}
		if _, err := validator.Validate(assertion); err != nil {
			t.Fatal("assertion signature", err)
		}
		if response.Assertion.Subject.NameID.Value != "opaque-name" || response.Assertion.Conditions.NotOnOrAfter.Sub(now) > AssertionLifetime || response.Assertion.AuthnStatements[0].AuthnContext.AuthnContextClassRef.Value != ContextUnspecified {
			t.Fatal("incorrect assertion")
		}
	}
	metadata := httptest.NewRecorder()
	provider.Metadata(metadata, httptest.NewRequest("GET", MetadataPath, nil))
	if strings.Contains(metadata.Body.String(), `use="encryption"`) || strings.Contains(metadata.Body.String(), "EncryptionMethod") {
		t.Fatal("advertised unsupported encryption")
	}
	if strings.Contains(metadata.Body.String(), saml.HTTPPostBinding) || strings.Contains(metadata.Body.String(), "SingleLogoutService") {
		t.Fatal("metadata advertised unsupported endpoint")
	}
}

func mustXML(t *testing.T, element *etree.Element) []byte {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(element.Copy())
	data, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBoundedRequestInspection(t *testing.T) {
	for name, document := range map[string]string{
		"entity":          `<!DOCTYPE AuthnRequest [<!ENTITY x SYSTEM "file:///private">]><AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/>`,
		"wrong namespace": `<AuthnRequest xmlns="urn:wrong"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">sp</Issuer></AuthnRequest>`,
		"expanded limit":  strings.Repeat("x", (256<<10)+1),
		"deep":            strings.Repeat("<x>", 40) + strings.Repeat("</x>", 40),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Inspect(redirectRequest(t, []byte(document), nil)); err == nil {
				t.Fatal("accepted malformed XML")
			}
		})
	}
	request := httptest.NewRequest("GET", "https://example.test/saml/sso?SAMLRequest=a&SAMLRequest=b", nil)
	if _, err := Inspect(request); err == nil {
		t.Fatal("duplicate parameter")
	}
}
