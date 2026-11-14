//go:build integration

package oidcprovider

import (
	"github.com/euyuil/memberid/internal/identity"
	"net/url"
	"testing"
)

func requireAuthorizationError(t *testing.T, response reply, kind string) {
	t.Helper()
	location, err := url.Parse(response.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if response.status != 302 || location.Scheme+"://"+location.Host+location.Path != callback || location.Query().Get("error") != kind || location.Query().Get("state") != "example-state" || location.Query().Has("code") {
		t.Fatalf("expected authorization error %s, got status %d and location %s", kind, response.status, location)
	}
}

func TestAuthorizationHintBindsSubject(t *testing.T) {
	f := newFixture(t)
	original := f.tokens()
	extra := url.Values{"id_token_hint": {original["id_token"].(string)}}
	r, verifier := f.authorization("example-web", "openid", extra)
	f.status(r, 302)
	page := f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
	f.status(page, 200)
	code := f.complete(page, f.member.ID)
	r = f.exchange("example-web", code, verifier)
	f.status(r, 200)
	if f.signedClaims(jsonObject(t, r)["id_token"].(string))["sub"] != f.member.ID {
		t.Fatal("matching hint changed the subject")
	}

	member, err := f.store.CreateMember(t.Context(), identity.OperatorPrincipal(), f.member.OrganizationID, "", "Another person")
	if err != nil {
		t.Fatal(err)
	}
	factor, err := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8619900000002")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.BindFactor(t.Context(), identity.OperatorPrincipal(), member.OrganizationID, member.ID, factor.ID); err != nil {
		t.Fatal(err)
	}
	f.browser = browserClient()
	r, _ = f.authorization("example-web", "openid", extra)
	f.status(r, 302)
	page = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
	f.status(page, 200)
	page = f.submit(page.body, "send", url.Values{"phone": {"19900000002"}})
	f.status(page, 200)
	page = f.submit(page.body, "verify", url.Values{"code": {f.sender.latest()}})
	f.status(page, 200)
	r = f.submit(page.body, "continue", url.Values{"member": {member.ID}, "consent": {"yes"}})
	requireAuthorizationError(t, r, "login_required")

	f.service.configuration.Clients[0].Preauthorized = true
	extra.Set("prompt", "none")
	r, _ = f.authorization("example-web", "openid", extra)
	f.status(r, 302)
	r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
	requireAuthorizationError(t, r, "login_required")
}
