package console

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/crewjam/saml"
)

type samlIdentityProvider struct {
	EntityID    string                 `json:"entityId"`
	MetadataURL string                 `json:"metadataUrl"`
	SSOURL      string                 `json:"ssoUrl"`
	Status      string                 `json:"status"`
	CheckedAt   time.Time              `json:"checkedAt"`
	Certificate *samlPublicCertificate `json:"certificate,omitempty"`
}

type samlPublicCertificate struct {
	PEM       string    `json:"pem"`
	SHA256    string    `json:"sha256"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	Status    string    `json:"status"`
}

func (s *Service) registerSAMLIdentityProviderRoute(issuer string) {
	s.routes.HandleFunc("GET /api/organizations/{organizationId}/saml-identity-provider", func(w http.ResponseWriter, r *http.Request) {
		principal := r.Context().Value(sessionKey{}).(session).principal()
		if _, err := s.management.Organization(r.Context(), principal, r.PathValue("organizationId")); err != nil {
			respond(w, nil, err)
			return
		}
		result := inspectSAMLIdentityProvider(r.Context(), issuer)
		// Do not return a delayed read after the administrator loses access.
		_, err := s.management.Organization(r.Context(), principal, r.PathValue("organizationId"))
		respond(w, result, err)
	})
}

// Only the installation's fixed issuer is fetched. No URL, credentials, key
// files or request headers supplied by the browser enter this transport.
func inspectSAMLIdentityProvider(ctx context.Context, issuer string) samlIdentityProvider {
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	result := samlIdentityProvider{EntityID: issuer + "/saml/metadata", MetadataURL: issuer + "/saml/metadata", SSOURL: issuer + "/saml/sso", Status: "unavailable", CheckedAt: time.Now().UTC()}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, result.MetadataURL, nil)
	if err != nil {
		return result
	}
	response, err := client.Do(request)
	if err != nil {
		return result
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return result
	}
	var metadata saml.EntityDescriptor
	if xml.Unmarshal(data, &metadata) != nil || metadata.EntityID != result.EntityID || len(metadata.IDPSSODescriptors) != 1 || (!metadata.ValidUntil.IsZero() && !metadata.ValidUntil.After(result.CheckedAt)) {
		return result
	}
	descriptor := metadata.IDPSSODescriptors[0]
	if len(descriptor.SingleSignOnServices) != 1 || descriptor.SingleSignOnServices[0].Binding != saml.HTTPRedirectBinding || descriptor.SingleSignOnServices[0].Location != result.SSOURL {
		return result
	}
	var certificates []saml.X509Certificate
	for _, key := range descriptor.KeyDescriptors {
		if key.Use == "signing" {
			certificates = append(certificates, key.KeyInfo.X509Data.X509Certificates...)
		}
	}
	// MemberID currently publishes exactly one signing certificate. Reject an
	// unexpected shape rather than choosing an arbitrary key for download.
	if len(certificates) != 1 {
		return result
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(certificates[0].Data), ""))
	if err != nil {
		return result
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return result
	}
	digest := sha256.Sum256(cert.Raw)
	status := "valid"
	switch {
	case result.CheckedAt.Before(cert.NotBefore):
		status = "notYetValid"
	case !result.CheckedAt.Before(cert.NotAfter):
		status = "expired"
	case cert.NotAfter.Sub(result.CheckedAt) <= 30*24*time.Hour:
		status = "expiring"
	}
	result.Status = "available"
	result.Certificate = &samlPublicCertificate{PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})), SHA256: hex.EncodeToString(digest[:]), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, Status: status}
	return result
}
