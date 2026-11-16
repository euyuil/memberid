// Package samlprovider implements MemberID's restricted SAML Web Browser SSO
// profile. Authentication and transactional issuance belong to the host service.
package samlprovider

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	dsig "github.com/russellhaering/goxmldsig"
)

const MetadataPath = "/saml/metadata"
const SSOPath = "/saml/sso"
const AssertionLifetime = 2 * time.Minute
const ClockSkew = time.Minute
const ContextUnspecified = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"

var ErrRequest = errors.New("invalid SAML authentication request")

// Transaction contains only the immutable, validated protocol continuation.
type Transaction struct {
	ServiceProviderID string `json:"serviceProviderId"`
	OrganizationID    string `json:"organizationId"`
	Revision          int64  `json:"revision"`
	RequestID         string `json:"requestId"`
	RelayState        string `json:"relayState"`
	Passive           bool   `json:"passive"`
	AllowCreate       bool   `json:"allowCreate"`
}

type Provider struct {
	signing *config.SAMLSigning
	idp     saml.IdentityProvider
}

type registeredSP struct{ sp identity.SAMLServiceProvider }

func (source registeredSP) GetServiceProvider(_ *http.Request, entityID string) (*saml.EntityDescriptor, error) {
	if entityID != source.sp.EntityID || !source.sp.Enabled || source.sp.Retired {
		return nil, os.ErrNotExist
	}
	return metadata(source.sp), nil
}

func metadata(sp identity.SAMLServiceProvider) *saml.EntityDescriptor {
	signed := !sp.AllowUnsignedRequests
	assertionsSigned := true
	descriptor := saml.SPSSODescriptor{AuthnRequestsSigned: &signed, WantAssertionsSigned: &assertionsSigned, SSODescriptor: saml.SSODescriptor{RoleDescriptor: saml.RoleDescriptor{ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol"}}, AssertionConsumerServices: []saml.IndexedEndpoint{{Binding: saml.HTTPPostBinding, Location: sp.ACSURL, Index: 0}}}
	for _, encoded := range sp.SigningCertificates {
		block, _ := pem.Decode([]byte(encoded))
		descriptor.KeyDescriptors = append(descriptor.KeyDescriptors, saml.KeyDescriptor{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(block.Bytes)}}}}})
	}
	return &saml.EntityDescriptor{EntityID: sp.EntityID, SPSSODescriptors: []saml.SPSSODescriptor{descriptor}}
}

func New(issuer string, signing *config.SAMLSigning) (*Provider, error) {
	if err := signing.Validate(time.Now()); err != nil {
		return nil, err
	}
	metadataURL, _ := url.Parse(issuer + MetadataPath)
	ssoURL, _ := url.Parse(issuer + SSOPath)
	return &Provider{signing: signing, idp: saml.IdentityProvider{Key: signing.Key, Certificate: signing.Certificate, MetadataURL: *metadataURL, SSOURL: *ssoURL, SignatureMethod: dsig.RSASHA256SignatureMethod, RejectSHA1Signatures: true, StrictACSBinding: true, NameIDFormats: []saml.NameIDFormat{saml.PersistentNameIDFormat, saml.UnspecifiedNameIDFormat}, Logger: log.New(io.Discard, "", 0)}}, nil
}

func (provider *Provider) Metadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := provider.signing.Validate(time.Now()); err != nil {
		http.Error(w, "SAML signing is unavailable", http.StatusServiceUnavailable)
		return
	}
	value := provider.idp.Metadata()
	// The upstream metadata also advertises decryption; this input profile
	// accepts neither encrypted messages nor encrypted subjects.
	value.IDPSSODescriptors[0].KeyDescriptors = slices.DeleteFunc(value.IDPSSODescriptors[0].KeyDescriptors, func(key saml.KeyDescriptor) bool { return key.Use != "signing" })
	if value.ValidUntil.After(provider.signing.Certificate.NotAfter) {
		value.ValidUntil = provider.signing.Certificate.NotAfter
	}
	value.IDPSSODescriptors[0].SingleSignOnServices = []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: provider.idp.SSOURL.String()}}
	data, err := xml.Marshal(value)
	if err != nil {
		http.Error(w, "SAML metadata unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

// Inspect bounds parsing before the maintained implementation handles XML or
// signatures. It never resolves a network URL from the incoming document.
func Inspect(r *http.Request) (string, error) {
	if r.Method != http.MethodGet || len(r.URL.RawQuery) > 32<<10 {
		return "", ErrRequest
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", ErrRequest
	}
	for name, values := range query {
		if !slices.Contains([]string{"SAMLRequest", "RelayState", "SigAlg", "Signature"}, name) || len(values) != 1 {
			return "", ErrRequest
		}
	}
	if len(query.Get("RelayState")) > 80 || query.Get("SAMLRequest") == "" {
		return "", ErrRequest
	}
	if query.Has("SigAlg") || query.Has("Signature") {
		if query.Get("SigAlg") != dsig.RSASHA256SignatureMethod || query.Get("Signature") == "" {
			return "", ErrRequest
		}
	}
	compressed, err := base64.StdEncoding.DecodeString(query.Get("SAMLRequest"))
	if err != nil {
		return "", ErrRequest
	}
	reader := flate.NewReader(bytes.NewReader(compressed))
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, (256<<10)+1))
	if err != nil || len(decoded) > 256<<10 {
		return "", ErrRequest
	}
	decoder := xml.NewDecoder(bytes.NewReader(decoded))
	depth, count, roots := 0, 0, 0
	issuer := ""
	inIssuer := false
	children := map[xml.Name]bool{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", ErrRequest
		}
		switch value := token.(type) {
		case xml.Directive:
			return "", ErrRequest
		case xml.ProcInst:
			if value.Target != "xml" {
				return "", ErrRequest
			}
		case xml.StartElement:
			depth++
			count++
			if inIssuer {
				return "", ErrRequest
			}
			attributes := map[xml.Name]bool{}
			for _, attribute := range value.Attr {
				if attributes[attribute.Name] {
					return "", ErrRequest
				}
				attributes[attribute.Name] = true
			}
			if depth > 32 || count > 2048 {
				return "", ErrRequest
			}
			if depth == 1 {
				roots++
				if roots != 1 || value.Name.Local != "AuthnRequest" || value.Name.Space != "urn:oasis:names:tc:SAML:2.0:protocol" {
					return "", ErrRequest
				}
			}
			if depth == 2 {
				if children[value.Name] {
					return "", ErrRequest
				}
				children[value.Name] = true
			}
			if depth == 2 && value.Name.Local == "Issuer" {
				if issuer != "" || value.Name.Space != "urn:oasis:names:tc:SAML:2.0:assertion" {
					return "", ErrRequest
				}
				inIssuer = true
			}
		case xml.CharData:
			if inIssuer {
				issuer += string(value)
			} else if depth == 0 && strings.TrimSpace(string(value)) != "" {
				return "", ErrRequest
			}
		case xml.EndElement:
			if depth == 2 {
				inIssuer = false
			}
			depth--
		}
	}
	if roots != 1 || depth != 0 || issuer == "" || len(issuer) > 1024 {
		return "", ErrRequest
	}
	return issuer, nil
}

// Parse returns a safe continuation and, for supported error delivery, a SAML
// second-level status. Untrusted routing and signature failures stay local.
func (provider *Provider) Parse(r *http.Request, sp identity.SAMLServiceProvider, now time.Time) (*Transaction, string, error) {
	issuer, err := Inspect(r)
	if err != nil || issuer != sp.EntityID {
		return nil, "", ErrRequest
	}
	idp := provider.idp
	idp.ServiceProviderProvider = registeredSP{sp}
	req, err := saml.NewIdpAuthnRequest(&idp, r)
	if err != nil {
		return nil, "", ErrRequest
	}
	req.Now = now
	if err := req.Validate(); err != nil {
		return nil, "", ErrRequest
	}
	input := req.Request
	if input.Destination != idp.SSOURL.String() || input.IssueInstant.Before(now.Add(-5*time.Minute)) || input.IssueInstant.After(now.Add(ClockSkew)) || len(input.ID) > 256 {
		return nil, "", ErrRequest
	}
	txn := &Transaction{ServiceProviderID: sp.ID, OrganizationID: sp.OrganizationID, Revision: sp.Revision, RequestID: input.ID, RelayState: req.RelayState, Passive: input.IsPassive != nil && *input.IsPassive, AllowCreate: input.NameIDPolicy == nil}
	if input.NameIDPolicy != nil {
		policy := input.NameIDPolicy
		txn.AllowCreate = policy.AllowCreate != nil && *policy.AllowCreate
		format, err := nameIDFormat(sp)
		if err != nil {
			return nil, "", err
		}
		if policy.Format != nil && *policy.Format != "" && *policy.Format != string(saml.UnspecifiedNameIDFormat) && *policy.Format != string(format) || policy.SPNameQualifier != nil && *policy.SPNameQualifier != "" && *policy.SPNameQualifier != sp.EntityID {
			return txn, "InvalidNameIDPolicy", nil
		}
	}
	if input.ForceAuthn != nil && *input.ForceAuthn || input.Subject != nil || input.Conditions != nil || input.Scoping != nil || input.AssertionConsumerServiceIndex != "" || input.AttributeConsumingServiceIndex != "" {
		return txn, "RequestUnsupported", nil
	}
	if input.ProtocolBinding != "" && input.ProtocolBinding != saml.HTTPPostBinding {
		return txn, "UnsupportedBinding", nil
	}
	if input.RequestedAuthnContext != nil {
		return txn, "NoAuthnContext", nil
	}
	// Reject unimplemented child extensions rather than silently weakening them.
	decoder := xml.NewDecoder(bytes.NewReader(req.RequestBuffer))
	depth := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", ErrRequest
		}
		switch v := token.(type) {
		case xml.StartElement:
			depth++
			if depth == 1 {
				for _, attribute := range v.Attr {
					if attribute.Name.Space == "xmlns" || attribute.Name.Local == "xmlns" {
						continue
					}
					if attribute.Name.Space != "" || !slices.Contains([]string{"ID", "Version", "IssueInstant", "Destination", "ForceAuthn", "IsPassive", "ProtocolBinding", "AssertionConsumerServiceURL", "AssertionConsumerServiceIndex", "AttributeConsumingServiceIndex", "ProviderName"}, attribute.Name.Local) {
						return txn, "RequestUnsupported", nil
					}
				}
			}
			if depth == 2 {
				allowed := v.Name == (xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:assertion", Local: "Issuer"}) || v.Name == (xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:protocol", Local: "NameIDPolicy"})
				if !allowed {
					return txn, "RequestUnsupported", nil
				}
				for _, attribute := range v.Attr {
					if attribute.Name.Space == "xmlns" || attribute.Name.Local == "xmlns" {
						continue
					}
					names := []string{"Format", "NameQualifier", "SPNameQualifier", "SPProvidedID"}
					if v.Name.Local == "NameIDPolicy" {
						names = []string{"Format", "SPNameQualifier", "AllowCreate"}
					}
					if attribute.Name.Space != "" || !slices.Contains(names, attribute.Name.Local) {
						return txn, "RequestUnsupported", nil
					}
				}
			}
			if depth > 2 {
				return txn, "RequestUnsupported", nil
			}
		case xml.EndElement:
			depth--
		}
	}
	return txn, "", nil
}

type Authentication struct {
	NameID, SessionID, DisplayName, Email string
	AuthenticatedAt, ExpiresAt            time.Time
}

func nameIDFormat(sp identity.SAMLServiceProvider) (saml.NameIDFormat, error) {
	switch sp.NameIDFormat {
	case "", "persistent":
		return saml.PersistentNameIDFormat, nil
	case "unspecified":
		return saml.UnspecifiedNameIDFormat, nil
	default:
		return "", ErrRequest
	}
}

// Response signs in memory; the host must commit transaction consumption before
// exposing the returned form to the browser.
func (provider *Provider) Response(r *http.Request, txn *Transaction, sp identity.SAMLServiceProvider, auth Authentication, status string, now time.Time) ([]byte, error) {
	if err := provider.signing.Validate(now); err != nil {
		return nil, err
	}
	format, err := nameIDFormat(sp)
	if err != nil {
		return nil, err
	}
	md := metadata(sp)
	idp := provider.idp
	req := &saml.IdpAuthnRequest{IDP: &idp, HTTPRequest: r, Request: saml.AuthnRequest{ID: txn.RequestID}, RelayState: txn.RelayState, ServiceProviderMetadata: md, SPSSODescriptor: &md.SPSSODescriptors[0], ACSEndpoint: &md.SPSSODescriptors[0].AssertionConsumerServices[0], Now: now}
	if status != "" {
		top := saml.StatusResponder
		if slices.Contains([]string{"RequestUnsupported", "UnsupportedBinding", "InvalidNameIDPolicy"}, status) {
			top = saml.StatusRequester
		}
		if err := req.MakeErrorResponse(top, "urn:oasis:names:tc:SAML:2.0:status:"+status, ""); err != nil {
			return nil, err
		}
	} else {
		expires := now.Add(AssertionLifetime)
		if auth.ExpiresAt.Before(expires) {
			expires = auth.ExpiresAt
		}
		if !expires.After(now) || auth.NameID == "" {
			return nil, ErrRequest
		}
		req.Assertion = &saml.Assertion{ID: "_" + rand.Text(), Version: "2.0", IssueInstant: now, Issuer: saml.Issuer{Value: idp.MetadataURL.String()}, Subject: &saml.Subject{NameID: &saml.NameID{Format: string(format), NameQualifier: idp.MetadataURL.String(), SPNameQualifier: sp.EntityID, Value: auth.NameID}, SubjectConfirmations: []saml.SubjectConfirmation{{Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer", SubjectConfirmationData: &saml.SubjectConfirmationData{InResponseTo: txn.RequestID, Recipient: sp.ACSURL, NotOnOrAfter: expires}}}}, Conditions: &saml.Conditions{NotBefore: now.Add(-ClockSkew), NotOnOrAfter: expires, AudienceRestrictions: []saml.AudienceRestriction{{Audience: saml.Audience{Value: sp.EntityID}}}}, AuthnStatements: []saml.AuthnStatement{{AuthnInstant: auth.AuthenticatedAt, SessionIndex: auth.SessionID, SessionNotOnOrAfter: &auth.ExpiresAt, AuthnContext: saml.AuthnContext{AuthnContextClassRef: &saml.AuthnContextClassRef{Value: ContextUnspecified}}}}}
		attributes := []saml.Attribute{}
		for _, claim := range []struct{ name, value string }{{"DisplayName", auth.DisplayName}, {"Email", auth.Email}} {
			if slices.Contains(sp.Attributes, claim.name) && claim.value != "" {
				attributes = append(attributes, saml.Attribute{Name: claim.name, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", Values: []saml.AttributeValue{{Type: "xs:string", Value: claim.value}}})
			}
		}
		if len(attributes) > 0 {
			req.Assertion.AttributeStatements = []saml.AttributeStatement{{Attributes: attributes}}
		}
		if err := req.MakeAssertionEl(); err != nil {
			return nil, err
		}
	}
	form, err := req.PostBinding()
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	err = postTemplate.Execute(&output, struct{ URL, SAMLResponse, RelayState, Nonce string }{form.URL, form.SAMLResponse, form.RelayState, nonce(r)})
	return output.Bytes(), err
}

type nonceKey struct{}

func WithNonce(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), nonceKey{}, config.RandomSecret()))
}
func nonce(r *http.Request) string { v, _ := r.Context().Value(nonceKey{}).(string); return v }
func Write(w http.ResponseWriter, r *http.Request, acs string, body []byte) {
	target, _ := url.Parse(acs)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce(r)+"'; form-action "+target.Scheme+"://"+target.Host+"; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body)
}

var postTemplate = template.Must(template.New("post").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Continue · MemberID</title><form id="saml-response" method="post" action="{{.URL}}"><input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}"><input type="hidden" name="RelayState" value="{{.RelayState}}"><button type="submit">Continue to application</button></form><script nonce="{{.Nonce}}">document.getElementById('saml-response').submit();</script></html>`))
