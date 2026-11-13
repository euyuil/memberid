//go:build integration

package oidcprovider

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/console"
	"github.com/euyuil/memberid/internal/identity"
)

func consoleFixture(t *testing.T, f *fixture) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	origin := "http://" + server.Listener.Addr().String()
	registration := config.Client{ID: "console", SecretSHA256: config.SecretHash(f.secret), RedirectURIs: []string{origin + "/auth/callback"}, SubjectKind: "member", Preauthorized: true}
	f.service.configuration.Clients = append(f.service.configuration.Clients, registration)
	h, err := console.New(t.Context(), f.store, f.service.configuration, console.Settings{Origin: origin, ClientID: "console"}, f.secret)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = h
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func consoleLogin(t *testing.T, f *fixture, server *httptest.Server, member string) reply {
	t.Helper()
	r := f.call(f.browser, "GET", server.URL+"/auth/login", nil, nil)
	f.status(r, 303)
	r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
	f.status(r, 302)
	r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
	f.status(r, 200)
	if !strings.Contains(r.body, "Select your identity") {
		r = f.verifyPhone(r)
	}
	r = f.submit(r.body, "continue", url.Values{"member": {member}, "consent": {"yes"}})
	f.status(r, 303)
	r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
	f.status(r, 302)
	callback := r.header.Get("Location")
	wrong := f.call(browserClient(), "GET", callback, nil, nil)
	f.status(wrong, 400)
	r = f.call(f.browser, "GET", callback, nil, nil)
	f.status(r, 303)
	replay := f.call(f.browser, "GET", callback, nil, nil)
	f.status(replay, 400)
	return r
}

func consoleJSON(t *testing.T, f *fixture, server *httptest.Server, method, path, csrf, body string, want int) map[string]any {
	t.Helper()
	r, e := http.NewRequest(method, server.URL+path, strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", server.URL)
	r.Header.Set("X-CSRF-Token", csrf)
	response, e := f.browser.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != want {
		t.Fatalf("%s %s: %d want %d: %s", method, path, response.StatusCode, want, data)
	}
	var value map[string]any
	if e = json.Unmarshal(data, &value); e != nil {
		t.Fatal(e)
	}
	return value
}

func TestConsoleOIDCOrganizationScopeAndRevocation(t *testing.T) {
	f := newFixture(t)
	if e := f.store.SetAdministrator(t.Context(), identity.ManagementActor{}, f.member.OrganizationID, f.member.ID, true); e != nil {
		t.Fatal(e)
	}
	server := consoleFixture(t, f)
	r := consoleLogin(t, f, server, f.member.ID)
	if r.header.Get("Location") != "/" {
		t.Fatal("console login failed", r.header)
	}
	v := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)
	csrf := v["csrf"].(string)
	if v["actor"].(map[string]any)["platform"] != false {
		t.Fatal("tenant acquired platform authority")
	}
	page := consoleJSON(t, f, server, "GET", "/api/organizations", "", "", 200)
	if len(page["items"].([]any)) != 1 {
		t.Fatal("cross organization directory")
	}
	base := "/api/organizations/" + f.member.OrganizationID
	consoleJSON(t, f, server, "GET", "/api/organizations/"+f.otherMember.OrganizationID, "", "", 403)
	consoleJSON(t, f, server, "GET", "/api/organizations/org_system", "", "", 403)
	consoleJSON(t, f, server, "GET", "/api/events?organizationId="+f.otherMember.OrganizationID, "", "", 403)
	consoleJSON(t, f, server, "POST", "/api/organizations", csrf, `{"name":"Forbidden"}`, 403)
	consoleJSON(t, f, server, "PATCH", base, "invalid", `{"name":"Rejected"}`, 403)
	consoleJSON(t, f, server, "PATCH", base, csrf, `{"status":"disabled"}`, 403)
	consoleJSON(t, f, server, "PATCH", base, csrf, `{"name":"Renamed"}`, 200)
	consoleJSON(t, f, server, "POST", base+"/members", csrf, `{"displayName":"New member","isAdmin":true}`, 400)
	created := consoleJSON(t, f, server, "POST", base+"/members", csrf, `{"displayName":"New member"}`, 200)
	consoleJSON(t, f, server, "PUT", base+"/members/"+created["id"].(string)+"/administrator", csrf, `{"enabled":true}`, 403)
	consoleJSON(t, f, server, "PUT", base+"/members/"+f.member.ID+"/administrator", csrf, `{"enabled":false}`, 409)
	// Organization administrators can delegate only to an eligible local Member.
	factor, err := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8619900000002")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.BindFactor(t.Context(), f.member.OrganizationID, created["id"].(string), factor.ID); err != nil {
		t.Fatal(err)
	}
	consoleJSON(t, f, server, "PUT", base+"/members/"+created["id"].(string)+"/administrator", csrf, `{"enabled":true}`, 200)
	consoleJSON(t, f, server, "PUT", base+"/members/"+created["id"].(string)+"/administrator", csrf, `{"enabled":false}`, 200)
	// External loss of eligibility invalidates an already authenticated console.
	if _, e := f.store.SetExternalDeparture(t.Context(), f.member.OrganizationID, f.member.ID, true); e != nil {
		t.Fatal(e)
	}
	consoleJSON(t, f, server, "GET", "/api/session", "", "", 401)
}

func TestConsoleMemberSearchAcrossPagesAndWithinOrganization(t *testing.T) {
	f := newFixture(t)
	if err := f.store.SetAdministrator(t.Context(), identity.ManagementActor{}, f.member.OrganizationID, f.member.ID, true); err != nil {
		t.Fatal(err)
	}
	server := consoleFixture(t, f)
	consoleLogin(t, f, server, f.member.ID)
	base := "/api/organizations/" + f.member.OrganizationID + "/members"

	// Choose the search target from the second page so its position is deterministic.
	for range 50 {
		if _, err := f.store.CreateMember(t.Context(), f.member.OrganizationID, "", "Other member"); err != nil {
			t.Fatal(err)
		}
	}
	initial := consoleJSON(t, f, server, "GET", base, "", "", 200)
	next, ok := initial["nextAfter"].(string)
	if !ok || next == "" || len(initial["items"].([]any)) != 50 {
		t.Fatalf("unfiltered directory did not preserve its first page: %+v", initial)
	}
	page := consoleJSON(t, f, server, "GET", base+"?after="+url.QueryEscape(next), "", "", 200)
	members := page["items"].([]any)
	if len(members) != 1 {
		t.Fatalf("expected one member on the second page, got %d", len(members))
	}
	targetID := members[0].(map[string]any)["id"].(string)
	name := "Needle 100%"
	if _, err := f.store.UpdateMember(t.Context(), f.member.OrganizationID, targetID, identity.MemberChange{DisplayName: &name}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.SetExternalDeparture(t.Context(), f.member.OrganizationID, targetID, true); err != nil {
		t.Fatal(err)
	}
	assertMembers := func(query url.Values, want ...string) {
		t.Helper()
		response := consoleJSON(t, f, server, "GET", base+"?"+query.Encode(), "", "", 200)
		items := response["items"].([]any)
		if len(items) != len(want) {
			t.Fatalf("filter %v returned %d Members, want %d", query, len(items), len(want))
		}
		for i, id := range want {
			if item := items[i].(map[string]any); item["id"] != id {
				t.Fatalf("filter %v returned Member %v, want %s", query, item["id"], id)
			}
		}
	}
	assertMembers(url.Values{"q": {"  nEeDle 100% "}, "status": {"blocked"}, "administrator": {"no"}}, targetID)
	assertMembers(url.Values{"q": {targetID}}, targetID)
	assertMembers(url.Values{"q": {targetID}, "status": {"blocked"}}, targetID)
	assertMembers(url.Values{"q": {"%"}}, targetID)
	assertMembers(url.Values{"q": {"needle"}, "status": {"active"}})
	assertMembers(url.Values{"status": {"active"}, "administrator": {"yes"}}, f.member.ID)
	assertMembers(url.Values{"q": {f.otherMember.ID}})
	consoleJSON(t, f, server, "GET", base+"?status=disabled", "", "", 400)
	consoleJSON(t, f, server, "GET", "/api/organizations/"+f.otherMember.OrganizationID+"/members?q=example", "", "", 403)
}

func TestConsolePlatformLoginAndPersonalAudit(t *testing.T) {
	f := newFixture(t)
	m, e := f.store.CreateMember(t.Context(), identity.SystemOrganizationID, "", "Platform operator")
	if e != nil {
		t.Fatal(e)
	}
	factor, e := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8619900000001")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.BindFactor(t.Context(), m.OrganizationID, m.ID, factor.ID); e != nil {
		t.Fatal(e)
	}
	if e = f.store.SetAdministrator(t.Context(), identity.ManagementActor{}, m.OrganizationID, m.ID, true); e != nil {
		t.Fatal(e)
	}
	server := consoleFixture(t, f)
	r := consoleLogin(t, f, server, m.ID)
	if r.header.Get("Location") != "/" {
		t.Fatal(r.header)
	}
	v := consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)
	csrf := v["csrf"].(string)
	if v["actor"].(map[string]any)["platform"] != true {
		t.Fatal("platform scope missing")
	}
	consoleJSON(t, f, server, "PATCH", "/api/organizations/org_system", csrf, `{"status":"disabled"}`, 403)
	created := consoleJSON(t, f, server, "POST", "/api/organizations", csrf, `{"name":"Created by operator"}`, 200)
	events := consoleJSON(t, f, server, "GET", "/api/events?organizationId="+created["id"].(string), "", "", 200)
	if events["items"].([]any)[0].(map[string]any)["actor"] != m.ID {
		t.Fatal("initiating identity was lost")
	}
	consoleJSON(t, f, server, "POST", "/api/logout", csrf, `{}`, 200)
	consoleJSON(t, f, server, "GET", "/api/session", "", "", 401)
}

func TestConsoleRejectsOrdinaryMember(t *testing.T) {
	f := newFixture(t)
	server := consoleFixture(t, f)
	r := consoleLogin(t, f, server, f.member.ID)
	if r.header.Get("Location") != "/?error=not_administrator" {
		t.Fatal(r.header)
	}
	consoleJSON(t, f, server, "GET", "/api/session", "", "", 401)
}

func TestConsoleInvalidatesExistingSession(t *testing.T) {
	for _, change := range []string{"administrator", "member", "organization", "grant", "sso", "console idle", "console absolute"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			if err := f.store.SetAdministrator(t.Context(), identity.ManagementActor{}, f.member.OrganizationID, f.member.ID, true); err != nil {
				t.Fatal(err)
			}
			server := consoleFixture(t, f)
			if r := consoleLogin(t, f, server, f.member.ID); r.header.Get("Location") != "/" {
				t.Fatal(r.header)
			}
			consoleJSON(t, f, server, "GET", "/api/session", "", "", 200)
			// Simulate an authoritative concurrent change outside this browser.
			queries := map[string]string{
				"administrator":    "DELETE FROM administrators",
				"member":           "UPDATE members SET manual_block=true",
				"organization":     "UPDATE organizations SET status='disabled' WHERE id<>'org_system'",
				"grant":            "UPDATE oidc_grants SET revoked_at=clock_timestamp()",
				"sso":              "UPDATE oidc_sessions SET revoked_at=clock_timestamp()",
				"console idle":     "UPDATE console_sessions SET expires_at=clock_timestamp()-interval '1 second'",
				"console absolute": "UPDATE console_sessions SET absolute_expires_at=clock_timestamp()-interval '1 second'",
			}
			if _, err := f.store.Database().Exec(t.Context(), queries[change]); err != nil {
				t.Fatal(err)
			}
			consoleJSON(t, f, server, "GET", "/api/session", "", "", 401)
		})
	}
}
