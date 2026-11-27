//go:build integration

package oidcprovider

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/dingtalk"
	"github.com/zhizhun-tech/memberid/internal/identity"
)

type samlIdentityFixture struct {
	*fixture
	sp        identity.SAMLServiceProvider
	ding      *testDingTalk
	feishu    *testFeishu
	providers map[string]string
	factors   map[string]string
	password  string
}

// Bind the synthetic provider subjects explicitly to one existing Member. No
// contact matching or account merging participates in the authentication tests.
func newSAMLIdentityFixture(t *testing.T) *samlIdentityFixture {
	t.Helper()
	f := newConfiguredFixture(t, true)
	s := &samlIdentityFixture{fixture: f, sp: enableSAML(t, f), providers: map[string]string{}, factors: map[string]string{}}
	s.ding, _ = enableDingTalk(t, f, true)
	s.feishu = new(testFeishu)
	key, _ := base64.StdEncoding.DecodeString(f.service.configuration.Secrets.ProviderKey)
	apps, err := identity.NewFeishuApplications(f.store, key, s.feishu)
	if err != nil {
		t.Fatal(err)
	}
	f.service.feishu = apps
	if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, true); err != nil {
		t.Fatal(err)
	}
	s.password, err = f.store.SetMemberPassword(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, "saml-member")
	if err != nil {
		t.Fatal(err)
	}
	page, verifier := f.loginPage("example-web", "openid")
	page = f.submit(page.body, "password", url.Values{"username": {"saml-member"}, "password": {s.password}})
	f.status(page, 200)
	f.status(f.exchange("example-web", f.complete(page, f.member.ID), verifier), 200)
	var grantID string
	if err := f.store.Database().QueryRow(t.Context(), "SELECT id FROM oidc_grants WHERE data->>'memberId'=$1", f.member.ID).Scan(&grantID); err != nil {
		t.Fatal(err)
	}
	enabled := true
	management := identity.NewManagementService(f.store, nil, apps, 0)
	if _, err := management.ConfigureProvider(t.Context(), identity.ManagementPrincipal(f.member.ID, grantID), f.member.OrganizationID, "feishu", "", identity.ProviderInput{DisplayName: "Synthetic Feishu", ClientID: "cli_first", TenantID: "example-tenant", ClientSecret: config.RandomSecret(), Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	providers, err := f.store.Providers(t.Context(), f.member.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range providers {
		s.providers[provider.Type] = provider.ID
		subject := "example-union"
		if provider.Type == "feishu" {
			subject = "ou_example"
		}
		factor, err := f.store.EnsureFactor(t.Context(), provider.Type, provider.ID, subject)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.BindFactor(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, factor.ID); err != nil {
			t.Fatal(err)
		}
		s.factors[provider.Type] = factor.ID
	}
	bindings, err := f.store.Bindings(t.Context(), f.member.OrganizationID, f.member.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range bindings {
		s.factors[binding.FactorType] = binding.FactorID
	}
	f.browser = browserClient()
	return s
}

func (s *samlIdentityFixture) startExternal(method string) string {
	s.t.Helper()
	page := samlPage(s.t, s.fixture, s.sp)
	start := s.submit(page.body, method, url.Values{"organization": {s.member.OrganizationID}, "provider": {s.providers[method]}})
	s.status(start, 303)
	location, err := url.Parse(start.header.Get("Location"))
	if err != nil {
		s.t.Fatal(err)
	}
	return "/login/" + method + "/callback?" + url.Values{"state": {location.Query().Get("state")}, "code": {"synthetic-code"}}.Encode()
}

func (s *samlIdentityFixture) authenticate(method string) reply {
	s.t.Helper()
	s.browser = browserClient()
	if method == "dingtalk" || method == "feishu" {
		result := s.call(s.browser, "GET", s.startExternal(method), nil, nil)
		s.status(result, 303)
		page := s.call(s.browser, "GET", result.header.Get("Location"), nil, nil)
		s.status(page, 200)
		return page
	}
	page := samlPage(s.t, s.fixture, s.sp)
	if method == "phone" {
		return s.verifyPhone(page)
	}
	page = s.submit(page.body, "password", url.Values{"username": {"saml-member"}, "password": {s.password}})
	s.status(page, 200)
	return page
}

func (s *samlIdentityFixture) completeSAML(page reply) reply {
	return s.submit(page.body, "continue", url.Values{"member": {s.member.ID}, "consent": {"yes"}})
}

// Faults change synthetic identity state directly so management safeguards
// (such as preserving the last administrator) cannot mask issuance checks.
func (s *samlIdentityFixture) invalidate(kind, method string) {
	s.t.Helper()
	query, args := "", []any{s.member.OrganizationID}
	switch kind {
	case "organization":
		query = "UPDATE organizations SET status='disabled',lifecycle_revision=lifecycle_revision+1 WHERE id=$1"
	case "member":
		query, args = "UPDATE members SET manual_block=true,eligibility_revision=eligibility_revision+1 WHERE id=$1", []any{s.member.ID}
	case "departure":
		query, args = "UPDATE members SET external_departure=true,eligibility_revision=eligibility_revision+1 WHERE id=$1", []any{s.member.ID}
	case "factor":
		query, args = "UPDATE authentication_factors SET status='disabled' WHERE id=$1", []any{s.factors[method]}
	case "binding":
		query, args = "UPDATE member_auth_factor_bindings SET status='revoked',revoked_at=clock_timestamp() WHERE member_id=$1 AND authentication_factor_id=$2", []any{s.member.ID, s.factors[method]}
	case "provider":
		query = "UPDATE " + method + "_applications SET enabled=false,revision=revision+1 WHERE organization_id=$1"
	case "authorization":
		query = "UPDATE " + method + "_applications SET authorization_status='revoked',authorization_revision=authorization_revision+1 WHERE organization_id=$1"
	case "credentials":
		query = "UPDATE " + method + "_applications SET revision=revision+1 WHERE organization_id=$1"
	default:
		s.t.Fatal("unknown invalidation")
	}
	if _, err := s.store.Database().Exec(s.t.Context(), query, args...); err != nil {
		s.t.Fatal(err)
	}
}

func TestSAMLSharedIdentityAndAuthenticationTime(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			testSAMLSharedIdentityAndAuthenticationTime(t, legacy)
		})
	}
}

func testSAMLSharedIdentityAndAuthenticationTime(t *testing.T, legacy bool) {
	s := newSAMLIdentityFixture(t)
	s.sp.Attributes = []string{"Email"}
	if legacy {
		s.sp.NameIDFormat = "unspecified"
	}
	var err error
	s.sp, err = s.store.PutSAMLServiceProvider(t.Context(), identity.OperatorPrincipal(), s.sp, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.PutMemberEmail(t.Context(), identity.OperatorPrincipal(), s.member.OrganizationID, s.member.ID, identity.MemberEmailInput{Address: "managed@example.test"}); err != nil {
		t.Fatal(err)
	}
	var elapsed atomic.Int64
	s.service.now = func() time.Time { return time.Now().Add(time.Duration(elapsed.Load())) }
	recorder := enableAuthenticationEvents(t, s.fixture)
	nameID := ""
	if legacy {
		nameID = "legacy-account-42"
		if _, err := s.store.ProvisionSAMLNameID(t.Context(), identity.OperatorPrincipal(), s.sp.OrganizationID, s.sp.ID, s.member.ID, nameID, s.sp.Revision); err != nil {
			t.Fatal(err)
		}
	}
	for _, method := range []string{"phone", "dingtalk", "feishu", "password"} {
		t.Run(method, func(t *testing.T) {
			page := s.authenticate(method)
			first := verifySAMLResponse(t, s.fixture, s.sp, s.completeSAML(page))
			assertSAMLEmail(t, first, "managed@example.test")
			if nameID == "" {
				nameID = first.Assertion.Subject.NameID.Value
			}
			if first.Assertion.Subject.NameID.Value != nameID {
				t.Fatal("explicitly bound methods changed NameID")
			}
			auth := first.Assertion.AuthnStatements[0]
			// Advance the issuance clock so an accidental authentication-time
			// reset cannot pass just because requests completed in one second.
			elapsed.Store(int64(2 * time.Minute))
			oidcPage, verifier := s.loginPage("example-web", "openid email offline_access")
			tokens := s.exchange("example-web", s.complete(oidcPage, s.member.ID), verifier)
			s.status(tokens, 200)
			claims := s.signedClaims(jsonObject(t, tokens)["id_token"].(string))
			userinfo := jsonObject(t, s.userinfo(jsonObject(t, tokens)["access_token"].(string)))
			if claims["email"] != nil || claims["email_verified"] != nil || userinfo["email"] != nil || userinfo["email_verified"] != nil {
				t.Fatal("administrator email leaked into OIDC claims")
			}
			if claims["sub"] != s.member.ID || int64(claims["auth_time"].(float64)) != auth.AuthnInstant.Unix() {
				t.Fatal("OIDC changed the authenticated Member or original time")
			}
			elapsed.Store(int64(4 * time.Minute))
			refreshed := s.refresh("example-web", jsonObject(t, tokens)["refresh_token"].(string), "")
			s.status(refreshed, 200)
			claims = s.signedClaims(jsonObject(t, refreshed)["id_token"].(string))
			if int64(claims["auth_time"].(float64)) != auth.AuthnInstant.Unix() {
				t.Fatal("refresh invented fresh authentication")
			}
			elapsed.Store(0)
			second := verifySAMLResponse(t, s.fixture, s.sp, s.completeSAML(samlPage(t, s.fixture, s.sp)))
			assertSAMLEmail(t, second, "managed@example.test")
			if second.Assertion.Subject.NameID.Value != nameID || !second.Assertion.AuthnStatements[0].AuthnInstant.Equal(auth.AuthnInstant) || second.Assertion.AuthnStatements[0].SessionIndex != auth.SessionIndex {
				t.Fatal("SAML did not retain shared session evidence")
			}
		})
	}
	recorder.Close(time.Second)
	verified, issued := 0, 0
	for _, event := range authenticationEvents(t, s.fixture) {
		if event.Type == "authentication.verify" && event.Outcome == "succeeded" {
			verified++
		}
		if event.Type == "saml.assertion.issue" && event.Outcome == "succeeded" {
			issued++
			if event.Method == "" || event.MemberID != s.member.ID || event.OrganizationID != s.member.OrganizationID || event.ClientID != s.sp.ID || event.BindingID == "" || event.SessionID == "" || event.InteractionID == "" || event.RequestID == "" || event.GrantID != "" {
				t.Fatal("incomplete SAML authentication context")
			}
			if event.Method == "dingtalk" || event.Method == "feishu" {
				if event.ProviderID != s.providers[event.Method] {
					t.Fatal("provider correlation lost")
				}
			} else if event.ProviderID != "" {
				t.Fatal("invented external provider")
			}
		}
	}
	if verified != 4 || issued != 8 {
		t.Fatalf("SSO reuse must not invent verification: verified=%d issued=%d", verified, issued)
	}
}

func TestSAMLFeishuSourceInvalidatedBeforeIssuance(t *testing.T) {
	for _, kind := range []string{"provider", "authorization"} {
		t.Run(kind, func(t *testing.T) {
			s := newSAMLIdentityFixture(t)
			page := s.authenticate("feishu")
			s.invalidate(kind, "feishu")
			if result := s.completeSAML(page); strings.Contains(result.body, "SAMLResponse") {
				t.Fatal("invalidated Feishu verification issued an assertion")
			}
		})
	}
}

func TestSAMLCurrentEligibility(t *testing.T) {
	for _, when := range []string{"before login", "after verification", "during directory I/O"} {
		for _, kind := range []string{"organization", "member", "departure", "factor", "binding", "provider", "authorization"} {
			t.Run(when+"/"+kind, func(t *testing.T) {
				s := newSAMLIdentityFixture(t)
				page := s.authenticate("dingtalk")
				if when == "during directory I/O" {
					s.ding.directoryBefore = func() { s.invalidate(kind, "dingtalk") }
				} else {
					s.invalidate(kind, "dingtalk")
				}
				if when == "before login" {
					response := s.fixture.call(s.fixture.browser, "GET", samlURL(t, s.fixture, s.sp, nil), nil, nil)
					s.fixture.status(response, 303)
					page = s.fixture.call(s.fixture.browser, "GET", response.header.Get("Location"), nil, nil)
					if kind == "organization" {
						s.fixture.status(page, 404)
						return
					}
					s.fixture.status(page, 200)
				}
				result := s.completeSAML(page)
				if strings.Contains(result.body, "SAMLResponse") {
					t.Fatal("ineligible identity issued an assertion")
				}
				var consumed bool
				if err := s.store.Database().QueryRow(t.Context(), "SELECT bool_or(consumed_at IS NOT NULL) FROM authentication_requests WHERE saml_service_provider_id=$1", s.sp.ID).Scan(&consumed); err != nil || consumed {
					t.Fatal("ineligible interaction committed", err)
				}
			})
		}
	}
}

func TestSAMLUpstreamInvalidation(t *testing.T) {
	for _, method := range []string{"dingtalk", "feishu"} {
		for _, kind := range []string{"organization", "member", "factor", "binding", "provider", "authorization", "credentials"} {
			t.Run(method+"/"+kind, func(t *testing.T) {
				s := newSAMLIdentityFixture(t)
				callback := s.startExternal(method)
				before := func() { s.invalidate(kind, method) }
				if method == "dingtalk" {
					s.ding.before = before
				} else {
					s.feishu.before = before
				}
				var countBefore, countAfter int
				if err := s.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM authentication_sessions").Scan(&countBefore); err != nil {
					t.Fatal(err)
				}
				result := s.call(s.browser, "GET", callback, nil, nil)
				// Feishu directory policy can reject the proof before admission,
				// rendering the existing retry page without authenticating.
				verificationFailed := method == "feishu" && result.status == 200 && strings.Contains(result.body, "Unable to verify the Feishu identity")
				if (!verificationFailed && result.status < 400) || result.header.Get("Set-Cookie") != "" || strings.Contains(result.body, "SAMLResponse") {
					t.Fatal("invalidated callback established authentication", result.status)
				}
				if err := s.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM authentication_sessions").Scan(&countAfter); err != nil || countAfter != countBefore {
					t.Fatal("failed callback created a session", err)
				}
			})
		}
	}
}

func TestSAMLIndependentAuthenticationSources(t *testing.T) {
	for _, method := range []string{"dingtalk", "feishu"} {
		for _, kind := range []string{"provider", "authorization"} {
			t.Run(method+"/"+kind, func(t *testing.T) {
				s := newSAMLIdentityFixture(t)
				first := verifySAMLResponse(t, s.fixture, s.sp, s.completeSAML(s.authenticate(method)))
				s.invalidate(kind, method)
				if result := s.completeSAML(samlPage(t, s.fixture, s.sp)); strings.Contains(result.body, "SAMLResponse") {
					t.Fatal("disabled source reused SSO")
				}
				other := "feishu"
				if method == "feishu" {
					other = "dingtalk"
				}
				for _, alternative := range []string{"phone", "password", other} {
					response := verifySAMLResponse(t, s.fixture, s.sp, s.completeSAML(s.authenticate(alternative)))
					if response.Assertion.Subject.NameID.Value != first.Assertion.Subject.NameID.Value {
						t.Fatal("independent source changed Member identity")
					}
				}
			})
		}
	}
}

func TestSAMLDirectoryFailurePolicy(t *testing.T) {
	for _, mode := range []string{"unavailable", "not a member", "authorization revoked"} {
		t.Run(mode, func(t *testing.T) {
			s := newSAMLIdentityFixture(t)
			s.completeSAML(s.authenticate("dingtalk"))
			s.ding.directoryError = errors.New("synthetic private provider diagnostic")
			if mode == "not a member" {
				s.ding.directoryError = dingtalk.ErrNotMember
			}
			if mode == "authorization revoked" {
				s.ding.directoryError = dingtalk.ErrAuthorizationDenied
			}
			if result := s.completeSAML(samlPage(t, s.fixture, s.sp)); strings.Contains(result.body, "SAMLResponse") {
				t.Fatal("provider contradiction or outage admitted directory identity")
			}
			result := s.completeSAML(s.authenticate("phone"))
			if mode == "not a member" {
				if strings.Contains(result.body, "SAMLResponse") {
					t.Fatal("definitive departure ignored for linked phone")
				}
			} else {
				verifySAMLResponse(t, s.fixture, s.sp, result)
			}
		})
	}
}
