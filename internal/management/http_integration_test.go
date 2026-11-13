//go:build integration

package management

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/testdb"
)

type fixture struct {
	store  *identity.Store
	server *httptest.Server
	secret string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	databaseURL := testdb.Create(t)
	if err := identity.Initialize(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	store, err := identity.Open(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	secret := config.RandomSecret()
	handler, err := New(store, config.SecretHash(secret), nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &fixture{store, server, secret}
}
func (f *fixture) call(t *testing.T, method, path, body string, want int, target any) {
	t.Helper()
	request, err := http.NewRequest(method, f.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+f.secret)
	request.Header.Set("Content-Type", "application/json")
	response, err := f.server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, response.StatusCode, want, data)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("missing cache protection")
	}
	if target != nil && json.Unmarshal(data, target) != nil {
		t.Fatalf("invalid response: %s", data)
	}
}
func (f *fixture) provision(t *testing.T) (identity.Organization, identity.Member) {
	t.Helper()
	var organization identity.Organization
	f.call(t, "POST", "/v1/organizations", `{"name":"Example organization"}`, 201, &organization)
	var member identity.Member
	f.call(t, "POST", "/v1/organizations/"+organization.ID+"/members", `{"displayName":"Example member"}`, 201, &member)
	return organization, member
}

func TestManagementAuthenticationAndListenerSeparation(t *testing.T) {
	f := newFixture(t)
	for _, headers := range []map[string]string{
		{}, {"Authorization": "Bearer " + config.RandomSecret()},
		{"Authorization": "Basic " + f.secret}, {"Cookie": "memberid_session=" + f.secret},
		{"Authorization": "Bearer " + f.secret, "Origin": "https://client.example.invalid"},
	} {
		request, _ := http.NewRequest("POST", f.server.URL+"/v1/organizations", strings.NewReader(`{"name":"Unauthorized"}`))
		for name, value := range headers {
			request.Header.Set(name, value)
		}
		response, err := f.server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		expected := 401
		if headers["Origin"] != "" {
			expected = 403
		}
		if response.StatusCode != expected {
			t.Fatalf("unauthorized mutation: %d", response.StatusCode)
		}
	}
	var organizations identity.Page[identity.Organization]
	f.call(t, "GET", "/v1/organizations", "", 200, &organizations)
	if len(organizations.Items) != 1 || organizations.Items[0].ID != identity.SystemOrganizationID {
		t.Fatal("unauthorized request created an identity")
	}
	for _, path := range []string{"/.well-known/openid-configuration", "/oauth/token", "/login", "/v1/factors"} {
		f.call(t, "POST", path, `{}`, 404, nil)
	}
	f.call(t, "GET", "/healthz", "", 200, nil)
	f.call(t, "GET", "/healthz?access_token="+f.secret, "", 400, nil)
	f.call(t, "GET", "/v1/organizations?limit=101", "", 400, nil)
	f.call(t, "GET", "/v1/organizations?limit=1&limit=2", "", 400, nil)
	f.call(t, "GET", "/v1/organizations?unknown=value", "", 400, nil)
	f.call(t, "GET", "/v1/organizations?after=bad", "", 400, nil)
	f.call(t, "POST", "/v1/organizations", `{"name":"a","Name":"b"}`, 400, nil)
}

func TestManagementOrganizationIsolationAndEligibility(t *testing.T) {
	f := newFixture(t)
	first, member := f.provision(t)
	second, other := f.provision(t)
	factor, err := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8613800000000")
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/organizations/" + first.ID + "/members/" + member.ID
	var binding identity.Binding
	bind := `{"authenticationFactorId":"` + factor.ID + `"}`
	f.call(t, "POST", path+"/bindings", bind, 200, &binding)
	if binding.ID == "" || binding.MemberID != member.ID {
		t.Fatal("binding identity missing")
	}
	f.call(t, "POST", "/v1/organizations/"+second.ID+"/members/"+other.ID+"/bindings", bind, 200, nil)
	f.call(t, "GET", "/v1/organizations/"+second.ID+"/members/"+member.ID, "", 404, nil)
	f.call(t, "PATCH", "/v1/organizations/"+second.ID+"/members/"+member.ID, `{"manualBlocked":true}`, 404, nil)
	f.call(t, "DELETE", "/v1/organizations/"+second.ID+"/members/"+member.ID+"/bindings/"+factor.ID, "", 404, nil)
	body := `{"organizationId":"` + first.ID + `","memberId":"` + member.ID + `","authenticationFactorId":"` + factor.ID + `","authenticationFactorType":"phone"}`
	check := func(want bool) {
		t.Helper()
		var eligibility identity.Eligibility
		f.call(t, "POST", "/v1/eligibility", body, 200, &eligibility)
		if eligibility.Eligible != want || want && eligibility.BindingID != binding.ID || !want && eligibility.BindingID != "" {
			t.Fatalf("eligibility=%+v, want %v", eligibility, want)
		}
	}
	check(true)
	var changed identity.Member
	f.call(t, "PATCH", path, `{"displayName":"Renamed member","manualBlocked":true}`, 200, &changed)
	if changed.ID != member.ID || changed.DisplayName != "Renamed member" {
		t.Fatal("update changed identity or missed display name")
	}
	check(false)
	if _, err := f.store.SetExternalDeparture(t.Context(), first.ID, member.ID, true); err != nil {
		t.Fatal(err)
	}
	f.call(t, "PATCH", path, `{"manualBlocked":false}`, 200, &changed)
	if changed.Status != "blocked" || len(changed.BlockSources) != 1 || changed.BlockSources[0] != "externalDeparture" {
		t.Fatal("manual unblock erased provider departure")
	}
	check(false)
	if _, err := f.store.SetExternalDeparture(t.Context(), first.ID, member.ID, false); err != nil {
		t.Fatal(err)
	}
	check(true)
	f.call(t, "PATCH", "/v1/organizations/"+first.ID, `{"status":"disabled"}`, 200, nil)
	check(false)
	f.call(t, "PATCH", "/v1/organizations/"+first.ID, `{"status":"enabled"}`, 200, nil)
	check(true)
	var wrongType identity.Eligibility
	f.call(t, "POST", "/v1/eligibility", strings.Replace(body, `"phone"`, `"dingtalk"`, 1), 200, &wrongType)
	if wrongType.Eligible {
		t.Fatal("wrong factor type accepted")
	}
	f.call(t, "DELETE", path+"/bindings/"+factor.ID, "", 204, nil)
	check(false)
	f.call(t, "DELETE", path+"/bindings/"+factor.ID, "", 204, nil)
	f.call(t, "POST", path+"/bindings", bind, 409, nil)
	var bindings struct {
		Items []identity.Binding `json:"items"`
	}
	f.call(t, "GET", path+"/bindings", "", 200, &bindings)
	if len(bindings.Items) != 1 || bindings.Items[0].Status != "revoked" || bindings.Items[0].ID != binding.ID {
		t.Fatal("revoked relationship was lost")
	}
	f.call(t, "GET", "/v1/factors/"+factor.ID, "", 200, nil)
	if _, err := f.store.Database().Exec(t.Context(), "UPDATE authentication_factors SET status='disabled' WHERE id=$1", factor.ID); err != nil {
		t.Fatal(err)
	}
	f.call(t, "POST", "/v1/organizations/"+second.ID+"/members/"+other.ID+"/bindings", bind, 403, nil)
}

func TestManagementPaginationAndConflicts(t *testing.T) {
	f := newFixture(t)
	organization, _ := f.provision(t)
	_, _ = f.provision(t)
	var member identity.Member
	path := "/v1/organizations/" + organization.ID + "/members"
	f.call(t, "POST", path, `{"displayName":"Second member"}`, 201, &member)
	f.call(t, "POST", path, `{"id":"`+member.ID+`","displayName":"Duplicate member"}`, 409, nil)
	after := ""
	seen := map[string]bool{}
	for {
		var page identity.Page[identity.Member]
		query := "?limit=1"
		if after != "" {
			query += "&after=" + after
		}
		f.call(t, "GET", path+query, "", 200, &page)
		if len(page.Items) != 1 || seen[page.Items[0].ID] || page.Items[0].OrganizationID != organization.ID {
			t.Fatal("incorrect or repeated page")
		}
		seen[page.Items[0].ID] = true
		if page.NextAfter == "" {
			break
		}
		after = page.NextAfter
		if len(seen) > 2 {
			t.Fatal("unbounded pagination")
		}
	}
	if len(seen) != 2 {
		t.Fatalf("seen %d Members", len(seen))
	}
	var page identity.Page[identity.Organization]
	f.call(t, "GET", "/v1/organizations?limit=1", "", 200, &page)
	if len(page.Items) != 1 || page.NextAfter != page.Items[0].ID {
		t.Fatal("missing organization cursor")
	}
	nextAfter := page.NextAfter
	page = identity.Page[identity.Organization]{}
	f.call(t, "GET", "/v1/organizations?after="+nextAfter, "", 200, &page)
	if len(page.Items) != 2 || page.Items[1].ID != identity.SystemOrganizationID || page.NextAfter != "" {
		t.Fatal("incorrect final organization page")
	}
	f.call(t, "PATCH", path+"/"+member.ID, `{"status":"active"}`, 400, nil)
	f.call(t, "PATCH", path+"/"+member.ID, `{}`, 400, nil)
	f.store.Close()
	var failure map[string]string
	f.call(t, "GET", path, "", 500, &failure)
	if len(failure) != 1 || failure["error"] != "internal_error" {
		t.Fatal("storage details exposed")
	}
}
