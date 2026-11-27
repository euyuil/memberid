//go:build integration

package oidcprovider

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/samlprovider"
	dsig "github.com/russellhaering/goxmldsig"
)

func enableSAML(t *testing.T, f *fixture) identity.SAMLServiceProvider {
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
	f.service.configuration.SAML = &config.SAML{Enabled: true}
	f.service.configuration.SAMLSigning = &config.SAMLSigning{Key: key, Certificate: cert}
	f.service.saml, err = samlprovider.New(f.server.URL, f.service.configuration.SAMLSigning)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := f.store.PutSAMLServiceProvider(t.Context(), identity.OperatorPrincipal(), identity.SAMLServiceProvider{EntityID: "https://sp.example.test/metadata", OrganizationID: f.member.OrganizationID, ACSURL: "https://sp.example.test/acs", Enabled: true, AllowUnsignedRequests: true, Attributes: []string{"DisplayName"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

func samlURL(t *testing.T, f *fixture, sp identity.SAMLServiceProvider, change func(*saml.AuthnRequest)) string {
	t.Helper()
	input := saml.AuthnRequest{ID: "_" + rand.Text(), Version: "2.0", IssueInstant: time.Now().UTC(), Destination: f.server.URL + samlprovider.SSOPath, Issuer: &saml.Issuer{Value: sp.EntityID}, AssertionConsumerServiceURL: sp.ACSURL, ProtocolBinding: saml.HTTPPostBinding}
	if change != nil {
		change(&input)
	}
	data, err := xml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer, _ := flate.NewWriter(&compressed, flate.DefaultCompression)
	_, _ = writer.Write(data)
	_ = writer.Close()
	return samlprovider.SSOPath + "?" + url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(compressed.Bytes())}, "RelayState": {"https://untrusted.example.test/not-a-redirect"}}.Encode()
}

func samlPage(t *testing.T, f *fixture, sp identity.SAMLServiceProvider) reply {
	t.Helper()
	response := f.call(f.browser, "GET", samlURL(t, f, sp, nil), nil, nil)
	f.status(response, 303)
	page := f.call(f.browser, "GET", response.header.Get("Location"), nil, nil)
	f.status(page, 200)
	return page
}

// Validate each signed element before interpreting its attributes. This fixture
// deliberately does not use the IdP library's ServiceProvider response parser.
func verifySAMLResponse(t *testing.T, f *fixture, sp identity.SAMLServiceProvider, result reply) saml.Response {
	t.Helper()
	f.status(result, 200)
	data, err := base64.StdEncoding.DecodeString(hidden(t, result.body, "SAMLResponse"))
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		t.Fatal(err)
	}
	validator := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{f.service.configuration.SAMLSigning.Certificate}})
	verified, err := validator.Validate(doc.Root())
	if err != nil {
		t.Fatal("response signature", err)
	}
	doc.SetRoot(verified)
	data, err = doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	var response saml.Response
	if err := xml.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if response.Issuer == nil || response.Issuer.Value != f.server.URL+samlprovider.MetadataPath || response.Destination != sp.ACSURL || response.InResponseTo == "" || response.ID == "" {
		t.Fatal("incorrect response binding")
	}
	if response.Status.StatusCode.Value == saml.StatusSuccess {
		el := verified.FindElement("./Assertion")
		if el == nil {
			t.Fatal("missing assertion")
		}
		if _, err := validator.Validate(el); err != nil {
			t.Fatal("assertion signature", err)
		}
		a := response.Assertion
		format := saml.PersistentNameIDFormat
		if sp.NameIDFormat == "unspecified" {
			format = saml.UnspecifiedNameIDFormat
		}
		if a == nil || a.Issuer.Value != response.Issuer.Value || a.Subject.NameID.Format != string(format) || a.Subject.NameID.NameQualifier != response.Issuer.Value || a.Subject.NameID.SPNameQualifier != sp.EntityID {
			t.Fatal("incorrect subject")
		}
		now := time.Now()
		if !a.Conditions.NotOnOrAfter.After(now) || a.Conditions.NotOnOrAfter.After(now.Add(2*time.Minute)) || a.Conditions.NotBefore.After(now) || a.Conditions.AudienceRestrictions[0].Audience.Value != sp.EntityID {
			t.Fatal("incorrect conditions")
		}
		confirmation := a.Subject.SubjectConfirmations[0].SubjectConfirmationData
		if confirmation.Recipient != sp.ACSURL || confirmation.InResponseTo != response.InResponseTo || !confirmation.NotOnOrAfter.Equal(a.Conditions.NotOnOrAfter) {
			t.Fatal("incorrect subject confirmation")
		}
		if a.AuthnStatements[0].AuthnContext.AuthnContextClassRef.Value != samlprovider.ContextUnspecified {
			t.Fatal("invented authentication context")
		}
	} else if response.Assertion != nil {
		t.Fatal("error contained assertion")
	}
	if result.header.Get("Cache-Control") != "no-store" || strings.Contains(result.header.Get("Content-Security-Policy"), "untrusted.example.test") {
		t.Fatal("unsafe response policy")
	}
	return response
}

func TestSAMLPasswordSessionCanContinueIntoOIDC(t *testing.T) {
	f := newFixture(t)
	sp := enableSAML(t, f)
	password, err := f.store.SetMemberPassword(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, "example")
	if err != nil {
		t.Fatal(err)
	}
	page := samlPage(t, f, sp)
	page = f.submit(page.body, "password", url.Values{"username": {"example"}, "password": {password}})
	f.status(page, 200)
	response := verifySAMLResponse(t, f, sp, f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}}))
	if response.Assertion == nil {
		t.Fatal("password-authenticated SAML request did not issue an assertion")
	}
	page, verifier := f.loginPage("example-web", "openid")
	tokens := f.exchange("example-web", f.complete(page, f.member.ID), verifier)
	f.status(tokens, 200)
	claims := f.signedClaims(jsonObject(t, tokens)["id_token"].(string))
	methods, ok := claims["amr"].([]any)
	if claims["sub"] != f.member.ID || !ok || len(methods) != 1 || methods[0] != "pwd" {
		t.Fatal("OIDC did not reuse the password-authenticated Member session")
	}
}

func TestSAMLSharedPhoneSessionAndIndependentSubjects(t *testing.T) {
	f := newConfiguredFixture(t, true)
	sp := enableSAML(t, f)
	f.status(f.call(f.browser, "GET", samlprovider.MetadataPath, nil, nil), 200)
	page := f.verifyPhone(samlPage(t, f, sp))
	result := f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}})
	first := verifySAMLResponse(t, f, sp, result)
	name := first.Assertion.Subject.NameID.Value
	if name == f.member.ID || name == "" {
		t.Fatal("not an opaque pairwise identifier")
	}
	f.status(f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}}), 400)
	// The existing OIDC flow consumes the same browser SSO without another SMS.
	oidcPage, verifier := f.loginPage("example-web", "openid offline_access")
	code := f.complete(oidcPage, f.member.ID)
	f.status(f.exchange("example-web", code, verifier), 200)
	page = samlPage(t, f, sp)
	second := verifySAMLResponse(t, f, sp, f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}}))
	if name != second.Assertion.Subject.NameID.Value || !first.Assertion.AuthnStatements[0].AuthnInstant.Equal(second.Assertion.AuthnStatements[0].AuthnInstant) {
		t.Fatal("SSO changed stable identity or authentication time")
	}
	// Recreate the protocol service using the same state and signing material.
	var err error
	f.service.saml, err = samlprovider.New(f.server.URL, f.service.configuration.SAMLSigning)
	if err != nil {
		t.Fatal(err)
	}
	page = samlPage(t, f, sp)
	third := verifySAMLResponse(t, f, sp, f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}}))
	if name != third.Assertion.Subject.NameID.Value {
		t.Fatal("restart changed NameID")
	}
	// The other Member has the same verified phone but belongs to another organization.
	other := sp
	other.ID = ""
	other.EntityID = "https://other.example.test/metadata"
	other.OrganizationID = f.otherMember.OrganizationID
	other.Revision = 0
	other, err = f.store.PutSAMLServiceProvider(t.Context(), identity.OperatorPrincipal(), other, false)
	if err != nil {
		t.Fatal(err)
	}
	page = samlPage(t, f, other)
	f.status(f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}}), 200)
	fourth := verifySAMLResponse(t, f, other, f.submit(page.body, "continue", url.Values{"member": {f.otherMember.ID}, "consent": {"yes"}}))
	if name == fourth.Assertion.Subject.NameID.Value {
		t.Fatal("independent Members merged")
	}
}

func TestSAMLProtocolErrorsAndAdmission(t *testing.T) {
	f := newFixture(t)
	f.status(f.call(f.browser, "GET", samlprovider.MetadataPath, nil, nil), 404)
	sp := enableSAML(t, f)
	for name, change := range map[string]func(*saml.AuthnRequest){
		"unknown SP":  func(r *saml.AuthnRequest) { r.Issuer.Value = "https://unknown.example.test" },
		"destination": func(r *saml.AuthnRequest) { r.Destination = "https://wrong.example.test" },
		"ACS":         func(r *saml.AuthnRequest) { r.AssertionConsumerServiceURL = "https://wrong.example.test/acs" },
		"expired":     func(r *saml.AuthnRequest) { r.IssueInstant = time.Now().Add(-6 * time.Minute) },
		"future":      func(r *saml.AuthnRequest) { r.IssueInstant = time.Now().Add(2 * time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			result := f.call(f.browser, "GET", samlURL(t, f, sp, change), nil, nil)
			f.status(result, 400)
			if strings.Contains(result.body, "SAMLResponse") {
				t.Fatal("untrusted request received protocol response")
			}
		})
	}
	force := true
	result := f.call(f.browser, "GET", samlURL(t, f, sp, func(r *saml.AuthnRequest) { r.ForceAuthn = &force }), nil, nil)
	response := verifySAMLResponse(t, f, sp, result)
	if response.Status.StatusCode.StatusCode.Value != saml.StatusRequestUnsupported {
		t.Fatal("ForceAuthn was not explicitly unsupported")
	}
	passiveURL := samlURL(t, f, sp, func(r *saml.AuthnRequest) { r.IsPassive = &force })
	result = f.call(f.browser, "GET", passiveURL, nil, nil)
	f.status(result, 303)
	response = verifySAMLResponse(t, f, sp, f.call(f.browser, "GET", result.header.Get("Location"), nil, nil))
	if response.Status.StatusCode.StatusCode.Value != saml.StatusNoPassive {
		t.Fatal("passive request prompted")
	}
	f.status(f.call(f.browser, "GET", passiveURL, nil, nil), 400)
	page := samlPage(t, f, sp)
	id := hidden(t, page.body, "request")
	f.status(f.call(browserClient(), "GET", "/login?request="+id, nil, nil), 400)
	// An OIDC authorization callback must not accept a SAML interaction ID.
	callback := f.call(f.browser, "GET", "/oauth/authorize/callback?id="+id, nil, nil)
	if callback.status < 400 || strings.Contains(callback.header.Get("Location"), "code=") {
		t.Fatal("SAML transaction used as OIDC authorization")
	}
}

func TestSAMLConcurrentAdmissionAndPassiveError(t *testing.T) {
	f := newFixture(t)
	sp := enableSAML(t, f)
	requestID := "_" + rand.Text()
	start := samlURL(t, f, sp, func(input *saml.AuthnRequest) {
		passive := true
		input.ID, input.IsPassive = requestID, &passive
	})
	parallelGET := func(path string) []reply {
		results := make(chan reply, 2)
		var group sync.WaitGroup
		for range 2 {
			group.Go(func() { results <- f.call(f.browser, "GET", path, nil, nil) })
		}
		group.Wait()
		return []reply{<-results, <-results}
	}
	var location string
	for _, result := range parallelGET(start) {
		if result.status == 303 && location == "" {
			location = result.header.Get("Location")
		} else {
			f.status(result, 400)
			if result.header.Get("Set-Cookie") != "" {
				t.Fatal("rejected admission changed the browser binding")
			}
		}
	}
	target, err := url.Parse(location)
	if err != nil || !strings.HasPrefix(target.Query().Get("request"), samlLoginPrefix) {
		t.Fatal("missing sealed continuation")
	}
	f.status(f.call(browserClient(), "GET", location, nil, nil), 400)
	tampered := samlLoginPrefix + "x" + strings.TrimPrefix(target.Query().Get("request"), samlLoginPrefix)
	f.status(f.call(f.browser, "GET", organizationLoginURL(sp.OrganizationID, tampered), nil, nil), 400)
	responses := 0
	for _, result := range parallelGET(location) {
		if result.status == 200 {
			responses++
			response := verifySAMLResponse(t, f, sp, result)
			if response.Status.StatusCode.StatusCode.Value != saml.StatusNoPassive || response.Assertion != nil || response.InResponseTo != requestID {
				t.Fatal("unexpected passive response")
			}
		} else {
			f.status(result, 400)
		}
	}
	if responses != 1 {
		t.Fatalf("emitted %d protocol errors", responses)
	}
	var markers int
	if err := f.store.Database().QueryRow(t.Context(), `SELECT count(*) FROM authentication_requests
		WHERE saml_service_provider_id=$1 AND saml_request_id=$2 AND data='{}' AND consumed_at IS NOT NULL`, sp.ID, requestID).Scan(&markers); err != nil || markers != 1 {
		t.Fatal("expected one consumed replay marker", markers, err)
	}
}

func TestSAMLLoginContextStaysInBrowser(t *testing.T) {
	f := newFixture(t)
	sp := enableSAML(t, f)
	// Enforce the storage boundary on every intermediate transition as well as
	// admission and issuance, so a later update cannot hide an earlier write.
	if _, err := f.store.Database().Exec(t.Context(), `ALTER TABLE authentication_requests
		ADD CHECK (protocol <> 'saml' OR data = '{}')`); err != nil {
		t.Fatal(err)
	}
	initial := samlPage(t, f, sp)
	pending := f.submit(initial.body, "send", url.Values{"phone": {"19900000001"}})
	f.status(pending, 200)
	f.status(f.submit(initial.body, "cancel", nil), 400)
	verified := f.submit(pending.body, "verify", url.Values{"code": {f.sender.latest()}})
	f.status(verified, 200)
	verifySAMLResponse(t, f, sp, f.submit(verified.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}}))
	f.status(f.submit(verified.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}}), 400)
}

func TestSAMLStoredRequestCanFinishAfterUpgrade(t *testing.T) {
	f := newFixture(t)
	sp := enableSAML(t, f)
	// Use a browser with a binding and seed a pending row in the prior format.
	f.call(f.browser, "GET", "/login", nil, nil)
	origin, _ := url.Parse(f.server.URL)
	var browser string
	for _, cookie := range f.browser.Jar.Cookies(origin) {
		if cookie.Name == f.service.cookieName("browser") {
			browser = cookie.Value
		}
	}
	if browser == "" {
		t.Fatal("missing browser binding")
	}
	id, requestID := newID(), "_"+rand.Text()
	_, err := f.store.Database().Exec(t.Context(), `INSERT INTO authentication_requests
		(id,protocol,client_id,saml_service_provider_id,saml_request_id,data,expires_at)
		VALUES($1,'saml',$2,$2,$3,jsonb_build_object('id',$1::text,'clientId',$2::text,'browserHash',$4::text,
		'csrf',$5::text,'providerOrganizationId',$6::text,'saml',jsonb_build_object('serviceProviderId',$2::text,
		'requestId',$3::text,'organizationId',$6::text,'revision',$7::bigint,'passive',true)),now()+interval '10 minutes')`,
		id, sp.ID, requestID, config.SecretHash(browser), config.RandomSecret(), sp.OrganizationID, sp.Revision)
	if err != nil {
		t.Fatal(err)
	}
	location := organizationLoginURL(sp.OrganizationID, id)
	response := verifySAMLResponse(t, f, sp, f.call(f.browser, "GET", location, nil, nil))
	if response.InResponseTo != requestID || response.Status.StatusCode.StatusCode.Value != saml.StatusNoPassive {
		t.Fatal("legacy request lost its SAML correlation")
	}
	f.status(f.call(f.browser, "GET", location, nil, nil), 400)
}

func TestSAMLConcurrentCompletionAndPolicyChanges(t *testing.T) {
	for _, change := range []string{"concurrent", "registration", "member", "session"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			sp := enableSAML(t, f)
			page := f.verifyPhone(samlPage(t, f, sp))
			switch change {
			case "registration":
				sp.Enabled = false
				if _, err := f.store.PutSAMLServiceProvider(t.Context(), identity.OperatorPrincipal(), sp, false); err != nil {
					t.Fatal(err)
				}
			case "member":
				if _, err := f.store.SetManualBlock(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, true); err != nil {
					t.Fatal(err)
				}
			case "session":
				if _, err := f.store.Database().Exec(t.Context(), "UPDATE authentication_sessions SET revoked_at=now()"); err != nil {
					t.Fatal(err)
				}
			}
			if change != "concurrent" {
				r := f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}})
				if strings.Contains(r.body, "SAMLResponse") {
					t.Fatal("issued assertion after invalidation")
				}
				return
			}
			var group sync.WaitGroup
			results := make(chan reply, 2)
			for range 2 {
				group.Go(func() {
					results <- f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}})
				})
			}
			group.Wait()
			close(results)
			successes := 0
			for result := range results {
				if strings.Contains(result.body, "SAMLResponse") {
					verifySAMLResponse(t, f, sp, result)
					successes++
				}
			}
			if successes != 1 {
				t.Fatalf("issued %d responses", successes)
			}
		})
	}
}

func TestSAMLExternalAuthentication(t *testing.T) {
	for _, method := range []string{"dingtalk", "feishu"} {
		t.Run(method, func(t *testing.T) {
			f := newFixture(t)
			sp := enableSAML(t, f)
			providerID := ""
			phone := f.service.phone
			if method == "dingtalk" {
				enableDingTalk(t, f, false)
			} else {
				key, _ := base64.StdEncoding.DecodeString(f.service.configuration.Secrets.ProviderKey)
				apps, err := identity.NewFeishuApplications(f.store, key, new(testFeishu))
				if err != nil {
					t.Fatal(err)
				}
				if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, true); err != nil {
					t.Fatal(err)
				}
				f.tokens()
				var grantID string
				if err := f.store.Database().QueryRow(t.Context(), "SELECT id FROM oidc_grants WHERE data->>'memberId'=$1", f.member.ID).Scan(&grantID); err != nil {
					t.Fatal(err)
				}
				enabled := true
				management := identity.NewManagementService(f.store, nil, apps, 0)
				app, err := management.ConfigureProvider(t.Context(), identity.ManagementPrincipal(f.member.ID, grantID), f.member.OrganizationID, "feishu", "", identity.ProviderInput{DisplayName: "Feishu", ClientID: "cli_first", TenantID: "example-tenant", ClientSecret: config.RandomSecret(), Enabled: &enabled})
				if err != nil {
					t.Fatal(err)
				}
				providerID = app.ID
				f.service.feishu = apps
				f.service.phone = nil
				f.browser = browserClient()
			}
			page := samlPage(t, f, sp)
			start := f.submit(page.body, method, url.Values{"organization": {f.member.OrganizationID}, "provider": {providerID}})
			f.status(start, 303)
			location, _ := url.Parse(start.header.Get("Location"))
			callback := "/login/" + method + "/callback?" + url.Values{"state": {location.Query().Get("state")}, "code": {"synthetic-code"}}.Encode()
			f.status(f.call(browserClient(), "GET", callback, nil, nil), 400)
			result := f.call(f.browser, "GET", callback, nil, nil)
			f.status(result, 303)
			page = f.call(f.browser, "GET", result.header.Get("Location"), nil, nil)
			f.status(page, 200)
			var memberID string
			if err := f.store.Database().QueryRow(t.Context(), "SELECT b.member_id FROM member_auth_factor_bindings b JOIN authentication_factors f ON f.id=b.authentication_factor_id WHERE b.organization_id=$1 AND f.type=$2 AND b.status='active'", sp.OrganizationID, method).Scan(&memberID); err != nil {
				t.Fatal(err)
			}
			first := verifySAMLResponse(t, f, sp, f.submit(page.body, "continue", url.Values{"member": {memberID}, "consent": {"yes"}}))
			f.status(f.call(f.browser, "GET", callback, nil, nil), 400)
			// Only an explicit operator binding connects the verified phone to this
			// Member. Authentication method changes must retain the same NameID.
			factor, err := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8619900000002")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.BindFactor(t.Context(), identity.OperatorPrincipal(), sp.OrganizationID, memberID, factor.ID); err != nil {
				t.Fatal(err)
			}
			f.service.phone, f.browser = phone, browserClient()
			page = samlPage(t, f, sp)
			page = f.submit(page.body, "send", url.Values{"phone": {"19900000002"}})
			f.status(page, 200)
			page = f.submit(page.body, "verify", url.Values{"code": {f.sender.latest()}})
			f.status(page, 200)
			second := verifySAMLResponse(t, f, sp, f.submit(page.body, "continue", url.Values{"member": {memberID}, "consent": {"yes"}}))
			if first.Assertion.Subject.NameID.Value != second.Assertion.Subject.NameID.Value {
				t.Fatal("authentication method changed the Member's NameID")
			}
		})
	}
}

func TestSAMLPolicyChangeDuringProviderIO(t *testing.T) {
	f := newFixture(t)
	sp := enableSAML(t, f)
	provider, _ := enableDingTalk(t, f, false)
	page := samlPage(t, f, sp)
	start := f.submit(page.body, "dingtalk", url.Values{"organization": {sp.OrganizationID}})
	f.status(start, 303)
	location, _ := url.Parse(start.header.Get("Location"))
	provider.before = func() {
		sp.Enabled = false
		if _, err := f.store.PutSAMLServiceProvider(t.Context(), identity.OperatorPrincipal(), sp, false); err != nil {
			t.Error(err)
		}
	}
	result := f.call(f.browser, "GET", "/login/dingtalk/callback?"+url.Values{"state": {location.Query().Get("state")}, "code": {"synthetic-code"}}.Encode(), nil, nil)
	if strings.Contains(result.body, "SAMLResponse") {
		t.Fatal("issued after SP disable during provider I/O")
	}
	var count int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM authentication_factors WHERE type='dingtalk'").Scan(&count); err != nil || count != 0 {
		t.Fatal("admitted provider identity after SP disable", err)
	}
}

func TestSAMLPassiveAndAllowCreate(t *testing.T) {
	f := newFixture(t)
	sp := enableSAML(t, f)
	f.tokens()
	create, passive := false, true
	requestURL := samlURL(t, f, sp, func(r *saml.AuthnRequest) { r.NameIDPolicy = &saml.NameIDPolicy{AllowCreate: &create} })
	start := f.call(f.browser, "GET", requestURL, nil, nil)
	page := f.call(f.browser, "GET", start.header.Get("Location"), nil, nil)
	result := verifySAMLResponse(t, f, sp, f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}}))
	if result.Status.StatusCode.StatusCode.Value != saml.StatusInvalidNameIDPolicy {
		t.Fatal("created mapping against NameIDPolicy")
	}
	sp.Preauthorized = true
	var err error
	sp, err = f.store.PutSAMLServiceProvider(t.Context(), identity.OperatorPrincipal(), sp, false)
	if err != nil {
		t.Fatal(err)
	}
	start = f.call(f.browser, "GET", samlURL(t, f, sp, func(r *saml.AuthnRequest) { r.IsPassive = &passive }), nil, nil)
	result = verifySAMLResponse(t, f, sp, f.call(f.browser, "GET", start.header.Get("Location"), nil, nil))
	if result.Status.StatusCode.Value != saml.StatusSuccess {
		t.Fatal("valid preauthorized SSO failed")
	}
}

func TestSAMLCompletionBoundaries(t *testing.T) {
	for _, kind := range []string{"wrong browser", "other organization", "expired interaction", "fresh authentication"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			sp := enableSAML(t, f)
			page := f.verifyPhone(samlPage(t, f, sp))
			member := f.member.ID
			switch kind {
			case "wrong browser":
				f.browser = browserClient()
			case "other organization":
				member = f.otherMember.ID
			case "expired interaction":
				if _, err := f.store.Database().Exec(t.Context(), "UPDATE authentication_requests SET expires_at=now()-interval '1 second' WHERE saml_service_provider_id=$1", sp.ID); err != nil {
					t.Fatal(err)
				}
			case "fresh authentication":
				force := true
				result := verifySAMLResponse(t, f, sp, f.call(f.browser, "GET", samlURL(t, f, sp, func(r *saml.AuthnRequest) { r.ForceAuthn = &force }), nil, nil))
				if result.Status.StatusCode.StatusCode.Value != saml.StatusRequestUnsupported || result.Assertion != nil {
					t.Fatal("ForceAuthn reused the existing session")
				}
				return
			}
			result := f.submit(page.body, "continue", url.Values{"member": {member}, "consent": {"yes"}})
			if strings.Contains(result.body, "SAMLResponse") {
				t.Fatal("invalid completion issued a response")
			}
		})
	}
}

func TestSAMLExpiryDuringCompletion(t *testing.T) {
	for _, delay := range []string{"directory", "row lock"} {
		for _, expiry := range []string{"request", "session", "absolute session"} {
			t.Run(delay+"/"+expiry, func(t *testing.T) {
				f := newConfiguredFixture(t, true)
				sp := enableSAML(t, f)
				provider, _ := enableDingTalk(t, f, false)
				_, _, memberID := directoryLogin(t, f)
				page := samlPage(t, f, sp)
				var elapsed atomic.Int64
				now := time.Now()
				f.service.now = func() time.Time { return now.Add(time.Duration(elapsed.Load())) }
				query := "UPDATE authentication_requests SET expires_at=$1 WHERE saml_service_provider_id=$2"
				args := []any{now.Add(time.Minute), sp.ID}
				if expiry != "request" {
					column := "expires_at"
					if expiry == "absolute session" {
						column = "absolute_expires_at"
					}
					query, args = "UPDATE authentication_sessions SET "+column+"=$1", args[:1]
				}
				if _, err := f.store.Database().Exec(t.Context(), query, args...); err != nil {
					t.Fatal(err)
				}
				advance := func() { elapsed.Store(int64(2 * time.Minute)) }
				var result reply
				complete := func() reply {
					return f.submit(page.body, "continue", url.Values{"member": {memberID}, "consent": {"yes"}})
				}
				if delay == "directory" {
					provider.directoryBefore = advance
					result = complete()
				} else {
					tx, err := f.store.Database().Begin(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback(t.Context())
					if _, err := tx.Exec(t.Context(), "SELECT id FROM saml_service_providers WHERE id=$1 FOR UPDATE", sp.ID); err != nil {
						t.Fatal(err)
					}
					done := make(chan reply, 1)
					go func() { done <- complete() }()
					deadline := time.Now().Add(10 * time.Second)
					for {
						var waiting bool
						if err := f.store.Database().QueryRow(t.Context(), "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock')").Scan(&waiting); err != nil {
							t.Fatal(err)
						}
						if waiting {
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("completion did not reach the locked SP")
						}
						time.Sleep(10 * time.Millisecond)
					}
					advance()
					if err := tx.Commit(t.Context()); err != nil {
						t.Fatal(err)
					}
					result = <-done
				}
				if strings.Contains(result.body, "SAMLResponse") {
					t.Fatal("issued after expiry during completion")
				}
				var consumed bool
				if err := f.store.Database().QueryRow(t.Context(), "SELECT consumed_at IS NOT NULL FROM authentication_requests WHERE saml_service_provider_id=$1", sp.ID).Scan(&consumed); err != nil || consumed {
					t.Fatal("expired completion was committed", err)
				}
			})
		}
	}
}
