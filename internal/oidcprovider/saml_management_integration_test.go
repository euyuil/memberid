//go:build integration

package oidcprovider

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestSAMLConsoleManagementAndInFlightInvalidation(t *testing.T) {
	f := newFixture(t)
	sp := enableSAML(t, f)
	if err := f.store.SetAdministrator(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, f.member.ID, true); err != nil {
		t.Fatal(err)
	}
	server := consoleFixture(t, f)
	consoleLoginTo(t, f, server, f.member.ID, "/organizations/"+sp.OrganizationID+"/saml-service-providers")
	csrf := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)["csrf"].(string)
	base := "/api/organizations/" + sp.OrganizationID + "/saml-service-providers"
	path := base + "/" + sp.ID
	foreign := "/api/organizations/" + f.otherMember.OrganizationID + "/saml-service-providers"
	consoleJSON(t, f, server, "GET", base, "", "", 200)
	consoleJSON(t, f, server, "GET", path, "", "", 200)
	consoleJSON(t, f, server, "GET", foreign, "", "", 403)
	consoleJSON(t, f, server, "GET", foreign+"/"+sp.ID, "", "", 403)
	input := identity.SAMLServiceProviderInput{ID: sp.ID, EntityID: sp.EntityID, ACSURL: sp.ACSURL, Enabled: true, AllowUnsignedRequests: true, SigningCertificates: []string{}, Attributes: []string{}, Revision: sp.Revision}
	body := func() string {
		value, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		return string(value)
	}
	consoleJSON(t, f, server, "PUT", path, "wrong-csrf", body(), 403)
	consoleJSON(t, f, server, "PUT", foreign+"/"+sp.ID, csrf, body(), 403)
	consoleJSON(t, f, server, "POST", foreign+"/"+sp.ID+"/retire", csrf, `{"revision":1}`, 403)
	// The same SSO browser starts a request before the administrator changes trust.
	page := samlPage(t, f, sp)
	input.ACSURL = "https://sp.example.test/changed-acs"
	changed := consoleJSON(t, f, server, "PUT", path, csrf, body(), 200)
	if changed["revision"] != float64(2) {
		t.Fatal(changed)
	}
	result := f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}})
	if strings.Contains(result.body, "SAMLResponse") {
		t.Fatal("old continuation issued after ACS change")
	}
	f.status(f.call(f.browser, "GET", samlURL(t, f, sp, nil), nil, nil), 400)
	consoleJSON(t, f, server, "PUT", path, csrf, body(), 409)
	sp.ACSURL, sp.Revision = input.ACSURL, 2
	page = samlPage(t, f, sp)
	verified := verifySAMLResponse(t, f, sp, f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}}))
	if verified.Assertion == nil {
		t.Fatal("current registration did not work")
	}
	page = samlPage(t, f, sp)
	consoleJSON(t, f, server, "POST", path+"/retire", csrf, `{"revision":2}`, 200)
	result = f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}})
	if strings.Contains(result.body, "SAMLResponse") {
		t.Fatal("retired registration issued assertion")
	}
	f.status(f.call(f.browser, "GET", samlURL(t, f, sp, nil), nil, nil), 400)
	input.ID, input.EntityID, input.Revision = "console-created", "https://created.example.test", 0
	consoleJSON(t, f, server, "POST", base, csrf, body(), 400)
	input.ID = ""
	created := consoleJSON(t, f, server, "POST", base, csrf, body(), 200)
	if !identity.ValidID(created["id"].(string), identity.ApplicationKind) {
		t.Fatal("missing generated SP ID")
	}
	// Retaining the browser cookie does not retain a revoked management grant.
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE oidc_grants SET revoked_at=clock_timestamp() WHERE data->>'memberId'=$1", f.member.ID); err != nil {
		t.Fatal(err)
	}
	consoleJSON(t, f, server, "GET", base, "", "", 401)
	input.EntityID = "https://revoked.example.test"
	consoleJSON(t, f, server, "POST", base, csrf, body(), 401)
}
