//go:build integration

package management

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestSAMLRegistrationManagementHTTP(t *testing.T) {
	f := newFixture(t)
	org, _ := f.provision(t)
	other, _ := f.provision(t)
	base := "/v1/organizations/" + org.ID + "/saml-service-providers"
	input := identity.SAMLServiceProviderInput{DisplayName: "Example SP", EntityID: "https://sp.example.test/metadata", ACSURL: "https://sp.example.test/acs", Enabled: true, AllowUnsignedRequests: true, SigningCertificates: []string{}, Attributes: []string{}}
	body := func() string {
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	var sp identity.SAMLServiceProvider
	f.call(t, "POST", base, body(), 201, &sp)
	if sp.OrganizationID != org.ID || sp.Revision != 1 {
		t.Fatal(sp)
	}
	f.call(t, "POST", base, body(), 409, nil)
	input.ID = sp.ID
	f.call(t, "GET", base+"/"+input.ID, "", 200, &sp)
	f.call(t, "GET", "/v1/organizations/"+other.ID+"/saml-service-providers/"+input.ID, "", 404, nil)
	var page identity.Page[identity.SAMLServiceProvider]
	f.call(t, "GET", base+"?limit=1", "", 200, &page)
	if len(page.Items) != 1 {
		t.Fatal(page)
	}
	for _, query := range []string{"?limit=0", "?limit=101", "?limit=1&limit=2", "?organizationId=" + other.ID, "?after=", "?after=%ZZ"} {
		f.call(t, "GET", base+query, "", 400, nil)
	}
	input.Revision = 1
	input.NameIDFormat = "unspecified"
	input.Enabled = false
	input.ACSURL = "https://sp.example.test/new-acs"
	f.call(t, "PUT", base+"/"+input.ID, body(), 200, &sp)
	if sp.Enabled || sp.ACSURL != input.ACSURL || sp.Revision != 2 || sp.NameIDFormat != "unspecified" {
		t.Fatal(sp)
	}
	f.call(t, "PUT", base+"/"+input.ID, body(), 409, nil)
	f.call(t, "PUT", base+"/wrong-id", body(), 400, nil)
	input.Revision = 2
	input.NameIDFormat = "emailAddress"
	f.call(t, "PUT", base+"/"+input.ID, body(), 400, nil)
	input.NameIDFormat = "unspecified"
	for _, extra := range []string{`"organizationId":"` + other.ID + `"`, `"retired":true`, `"actor":"installation-operator"`, `"nameIdFormat":"emailAddress"`, `"enabled":true`} {
		f.call(t, "PUT", base+"/"+input.ID, strings.TrimSuffix(body(), "}")+","+extra+"}", 400, nil)
	}
	for _, invalid := range []string{"https://*.example.test/acs", "http://127.0.0.1/acs", "https://sp.example.test/acs#fragment", "javascript:alert(1)"} {
		input.ACSURL = invalid
		f.call(t, "PUT", base+"/"+input.ID, body(), 400, nil)
	}
	input.ACSURL = sp.ACSURL
	input.SigningCertificates = []string{"-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----"}
	f.call(t, "PUT", base+"/"+input.ID, body(), 400, nil)
	input.SigningCertificates = []string{}
	input.AllowUnsignedRequests = false
	f.call(t, "PUT", base+"/"+input.ID, body(), 400, nil)
	f.call(t, "POST", base+"/"+input.ID+"/retire", `{"revision":1}`, 409, nil)
	f.call(t, "POST", base+"/"+input.ID+"/retire", `{"revision":2}`, 200, &sp)
	if !sp.Retired || sp.Enabled || sp.Revision != 3 {
		t.Fatal(sp)
	}
	f.call(t, "POST", base+"/"+input.ID+"/retire", `{"revision":3}`, 409, nil)
	input.AllowUnsignedRequests, input.Enabled, input.Revision = true, true, 3
	f.call(t, "PUT", base+"/"+input.ID, body(), 409, nil)
	history, err := f.store.ManagementEvents(t.Context(), org.ID, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range history {
		if event.Action == "saml.serviceProvider.configure" {
			count++
			if event.Actor != "installation-manager" {
				t.Fatal("wrong actor", event)
			}
		}
	}
	if count != 3 {
		t.Fatal("failed requests were audited as changes", count)
	}
}
