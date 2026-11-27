//go:build integration

package oidcprovider

import (
	"net/url"
	"testing"

	"github.com/crewjam/saml"
	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestSAMLLegacyNameIDAllowCreateAndPolicy(t *testing.T) {
	f := newFixture(t)
	sp := enableSAML(t, f)
	sp.NameIDFormat = "unspecified"
	var err error
	sp, err = f.store.PutSAMLServiceProvider(t.Context(), identity.OperatorPrincipal(), sp, false)
	if err != nil {
		t.Fatal(err)
	}
	const oldValue = "old<&>账户-42"
	if _, err := f.store.ProvisionSAMLNameID(t.Context(), identity.OperatorPrincipal(), sp.OrganizationID, sp.ID, f.member.ID, oldValue, sp.Revision); err != nil {
		t.Fatal(err)
	}
	f.tokens()
	allow := false
	format := string(saml.UnspecifiedNameIDFormat)
	start := f.call(f.browser, "GET", samlURL(t, f, sp, func(r *saml.AuthnRequest) {
		r.NameIDPolicy = &saml.NameIDPolicy{Format: &format, AllowCreate: &allow}
	}), nil, nil)
	f.status(start, 303)
	page := f.call(f.browser, "GET", start.header.Get("Location"), nil, nil)
	result := verifySAMLResponse(t, f, sp, f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}}))
	if result.Status.StatusCode.Value != saml.StatusSuccess || result.Assertion.Subject.NameID.Value != oldValue {
		t.Fatal("pre-provisioned value was not reused with AllowCreate=false")
	}
	format = string(saml.PersistentNameIDFormat)
	result = verifySAMLResponse(t, f, sp, f.call(f.browser, "GET", samlURL(t, f, sp, func(r *saml.AuthnRequest) {
		r.NameIDPolicy = &saml.NameIDPolicy{Format: &format}
	}), nil, nil))
	if result.Status.StatusCode.StatusCode.Value != saml.StatusInvalidNameIDPolicy {
		t.Fatal("incompatible format did not produce a signed policy error")
	}
}
