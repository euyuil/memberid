//go:build integration

package oidcprovider

import (
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestOIDCOrganizationLaunch(t *testing.T) {
	f := newFixture(t)
	ctx, operator := t.Context(), identity.OperatorPrincipal()
	a, b := f.member, f.otherMember
	ownerPassword, err := f.store.SetMemberPassword(ctx, operator, a.OrganizationID, a.ID, "casey")
	if err != nil {
		t.Fatal(err)
	}
	app, err := f.store.CreateOIDCClient(ctx, operator, identity.OIDCClientRegistration{
		OwnerOrganizationID: a.OrganizationID, DisplayName: "Shared workspace",
		Client: identity.OIDCClient{SecretSHA256: config.SecretHash(f.secret), SubjectKind: "member", OrganizationID: a.OrganizationID, RedirectURIs: []string{callback}, AllowOrganizationScope: true},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	management := identity.NewManagementService(f.store, nil, nil, 0)
	if err := management.SetOIDCPublication(ctx, operator, a.OrganizationID, app.ClientID, true); err != nil {
		t.Fatal(err)
	}
	parameter := url.Values{"memberid_organization": {b.OrganizationID}}
	const scope = "openid memberid.organization"
	denied := func(client string, params url.Values) {
		t.Helper()
		start, _ := f.authorization(client, scope, params)
		target, err := url.Parse(start.header.Get("Location"))
		if err != nil || target.Query().Get("error") != "invalid_request" || target.Query().Get("code") != "" || target.Query().Get("state") != "example-state" {
			t.Fatal("expected protocol rejection", start.status, target.Redacted())
		}
	}
	denied(app.ClientID, parameter)
	denied("example-web", parameter)
	denied(app.ClientID, url.Values{"memberid_organization": {""}})
	enroll := func(enabled bool) {
		t.Helper()
		if err := management.SetOIDCEnablement(ctx, operator, b.OrganizationID, app.ClientID, enabled); err != nil {
			t.Fatal(err)
		}
	}
	const loginName = "subscriber-b"
	f.seedOrganizationSlug(b.OrganizationID, loginName)
	start, _ := f.authorization(app.ClientID, scope, nil)
	f.status(start, 302)
	common := f.call(f.browser, "GET", start.header.Get("Location"), nil, nil)
	f.status(common, 200)
	if declined := f.selectOrganization(common, loginName); !strings.Contains(declined.body, "Enter a valid organization login name or ID.") {
		t.Fatal("unsubscribed organization was selected by name")
	}
	qualified := f.submit(common.body, "password", url.Values{"username": {"casey@" + loginName}, "password": {"incorrect"}})
	f.status(qualified, 200)
	if !strings.Contains(qualified.body, "Enter a valid organization login name or ID.") {
		t.Fatal("qualified password login admitted an unsubscribed organization")
	}
	enroll(true)
	// The interactive selector accepts login names. Protocol hints require a permanent ID.
	denied(app.ClientID, url.Values{"memberid_organization": {loginName}})
	launch := func(selection string) (reply, string) {
		scoped := selection == ""
		t.Helper()
		var extra url.Values
		if scoped {
			extra = parameter
		}
		start, verifier := f.authorization(app.ClientID, scope, extra)
		f.status(start, 302)
		page := f.call(f.browser, "GET", start.header.Get("Location"), nil, nil)
		if page.status == 303 {
			page = f.call(f.browser, "GET", page.header.Get("Location"), nil, nil)
		}
		f.status(page, 200)
		if scoped == strings.Contains(page.body, `value="choose-organization"`) {
			t.Fatal("organization selection did not match launch")
		}
		if !scoped {
			page = f.selectOrganization(page, selection)
		} else if strings.Contains(page.body, `id="phone"`) {
			foreign := f.submit(page.body, "password", url.Values{"username": {"casey@" + a.OrganizationID}, "password": {ownerPassword}})
			f.status(foreign, 200)
			if !strings.Contains(foreign.body, "does not match this organization") {
				t.Fatal("qualified username overrode the application launch organization")
			}
		}
		if strings.Contains(page.body, `id="phone"`) {
			page = f.verifyPhone(page)
		}
		return page, verifier
	}
	for _, selection := range []string{"", b.OrganizationID, loginName} {
		page, verifier := launch(selection)
		wrong := f.submit(page.body, "continue", url.Values{"member": {a.ID}, "consent": {"yes"}})
		f.status(wrong, 200)
		if !strings.Contains(wrong.body, "Select an available Member identity.") {
			t.Fatal("foreign Member selection was not rejected")
		}
		result := f.exchange(app.ClientID, f.complete(page, b.ID), verifier)
		f.status(result, 200)
		claims := f.signedClaims(jsonObject(t, result)["id_token"].(string))
		if claims["organizationId"] != b.OrganizationID || claims["sub"] != b.ID || claims["nonce"] != "example-nonce" {
			t.Fatal("incorrect signed organization, Member or nonce")
		}
	}
	pending, _ := launch("")
	enroll(false)
	enroll(true)
	refused := f.submit(pending.body, "continue", url.Values{"member": {b.ID}, "consent": {"yes"}})
	if refused.status < 400 {
		t.Fatal("old scoped launch survived interrupted enrollment")
	}
	disabled := "disabled"
	if _, err := f.store.UpdateOrganization(ctx, operator, b.OrganizationID, identity.OrganizationChange{Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	denied(app.ClientID, parameter)
}

func TestSAMLTenantDestinationAndMemberBinding(t *testing.T) {
	f := newFixture(t)
	ctx, operator := t.Context(), identity.OperatorPrincipal()
	sp := enableSAML(t, f)
	b := f.otherMember
	path := "/saml/organizations/" + b.OrganizationID + "/sso"
	scoped := func() string {
		request := samlURL(t, f, sp, func(input *saml.AuthnRequest) { input.Destination = f.server.URL + path })
		return path + strings.TrimPrefix(request, "/saml/sso")
	}
	f.status(f.call(f.browser, "GET", scoped(), nil, nil), 404)
	sp.Published = true
	var err error
	sp, err = f.store.PutSAMLServiceProvider(ctx, operator, sp, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetSAMLEnablement(ctx, operator, b.OrganizationID, sp.ID, true); err != nil {
		t.Fatal(err)
	}
	f.status(f.call(f.browser, "GET", strings.Replace(scoped(), path, "/saml/sso", 1), nil, nil), 400)
	f.status(f.call(f.browser, "GET", strings.Replace(samlURL(t, f, sp, nil), "/saml/sso", path, 1), nil, nil), 400)
	password, err := f.store.SetMemberPassword(ctx, operator, b.OrganizationID, b.ID, "casey")
	if err != nil {
		t.Fatal(err)
	}
	commonStart := f.call(f.browser, "GET", samlURL(t, f, sp, nil), nil, nil)
	f.status(commonStart, 303)
	commonPage := f.call(f.browser, "GET", commonStart.header.Get("Location"), nil, nil)
	fields := url.Values{"username": {"casey@" + b.OrganizationID}, "password": {"incorrect"}}
	retry := f.submit(commonPage.body, "password", fields)
	f.status(retry, 200)
	if !strings.Contains(retry.body, `action="/login/`+b.OrganizationID+`"`) {
		t.Fatal("SAML password retry lost its organization")
	}
	fields.Set("password", password)
	consent := f.submit(retry.body, "password", fields)
	verifySAMLResponse(t, f, sp, f.submit(consent.body, "continue", url.Values{"member": {b.ID}, "consent": {"yes"}}))
	f.browser = browserClient()
	start := f.call(f.browser, "GET", scoped(), nil, nil)
	f.status(start, 303)
	page := f.verifyPhone(f.call(f.browser, "GET", start.header.Get("Location"), nil, nil))
	refused := f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}})
	if strings.Contains(refused.body, "SAMLResponse") || !strings.Contains(refused.body, "Select an available Member identity.") {
		t.Fatal("foreign Member selected")
	}
	disabled := "disabled"
	if _, err := f.store.UpdateOrganization(ctx, operator, b.OrganizationID, identity.OrganizationChange{Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	f.status(f.call(f.browser, "GET", scoped(), nil, nil), 404)
	if result := f.submit(page.body, "continue", url.Values{"member": {b.ID}, "consent": {"yes"}}); strings.Contains(result.body, "SAMLResponse") {
		t.Fatal("disabled organization issued assertion")
	}
}
