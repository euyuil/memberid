package oidcprovider

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestWriteHTMLPage(t *testing.T) {
	login := pageData{
		ProviderEnabled: true, Providers: []identity.Provider{{Type: "dingtalk"}},
		Request: &authorizationRequest{}, Nonce: "example-nonce",
	}
	brokenProvider := struct {
		pageData
		Providers []string
	}{login, []string{"missing provider fields"}}
	for _, tc := range []struct {
		page           *template.Template
		valid, invalid any
	}{
		{loginPage, login, brokenProvider},
		{accountPage, accountPageData{}, struct{}{}},
		{phoneAccountPage, phoneAccountPageData{}, struct{}{}},
		{accountHomePage, map[string]any{"Member": identity.Member{}}, struct{}{}},
		{logoutPage, map[string]string{"Request": "example-confirmation"}, struct{}{}},
	} {
		t.Run(tc.page.Name(), func(t *testing.T) {
			var want bytes.Buffer
			if err := tc.page.Execute(&want, tc.valid); err != nil {
				t.Fatal(err)
			}
			success := httptest.NewRecorder()
			success.Header().Set("Content-Security-Policy", "default-src 'none'")
			writeHTMLPage(success, tc.page, tc.valid)
			if success.Code != http.StatusOK || !bytes.Equal(success.Body.Bytes(), want.Bytes()) ||
				success.Header().Get("Content-Type") != "text/html; charset=utf-8" || success.Header().Get("Content-Security-Policy") != "default-src 'none'" {
				t.Fatal("successful render changed the response")
			}
			failure := httptest.NewRecorder()
			writeHTMLPage(failure, tc.page, tc.invalid)
			if failure.Code != http.StatusInternalServerError || failure.Body.String() != "Unable to display this page.\n" ||
				failure.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
				t.Fatal("template failure must return a generic text error and discard partial HTML")
			}
		})
	}
}

func TestLoginPageShowsOnlyCurrentStep(t *testing.T) {
	tests := []struct {
		name    string
		data    pageData
		visible []string
		hidden  []string
	}{
		{
			name:    "organization selection",
			data:    pageData{PasswordEnabled: true, PhoneEnabled: true, ProviderEnabled: true, OrganizationRequired: true},
			visible: []string{`id="organization"`, `value="choose-organization"`, `id="username"`},
			hidden:  []string{`id="phone"`, `id="code"`, `id="member"`, `value="cancel"`, `value="continue"`},
		},
		{
			name:    "authentication choices",
			data:    pageData{PasswordEnabled: true, PhoneEnabled: true, ProviderEnabled: true, Action: "/login/org_example", Providers: []identity.Provider{{ID: "provider", Type: "dingtalk", DisplayName: "DingTalk"}}},
			visible: []string{`id="username"`, `id="phone"`},
			hidden:  []string{`id="organization"`, `id="code"`, `id="member"`, `value="cancel"`, `value="continue"`},
		},
		{
			name:    "phone verification",
			data:    pageData{PasswordEnabled: true, PhoneEnabled: true, ProviderEnabled: true, Pending: true, PhonePending: true},
			visible: []string{`id="phone"`, `id="code"`, `value="cancel"`},
			hidden:  []string{`id="username"`, `id="organization"`, `id="member"`, `value="continue"`},
		},
		{
			name:    "external verification",
			data:    pageData{PasswordEnabled: true, PhoneEnabled: true, ProviderEnabled: true, Pending: true},
			visible: []string{`value="cancel"`},
			hidden:  []string{`id="username"`, `id="phone"`, `id="organization"`, `id="code"`, `id="member"`, `value="continue"`},
		},
		{
			name:    "verified identity",
			data:    pageData{PasswordEnabled: true, PhoneEnabled: true, ProviderEnabled: true, Verified: true},
			visible: []string{`id="member"`, `value="continue"`, `value="cancel"`},
			hidden:  []string{`id="username"`, `id="phone"`, `id="organization"`, `id="code"`},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := test.data
			data.Request = &authorizationRequest{}
			var body bytes.Buffer
			if err := loginPage.Execute(&body, data); err != nil {
				t.Fatal(err)
			}
			for _, marker := range test.visible {
				if !strings.Contains(body.String(), marker) {
					t.Errorf("visible control %s is missing", marker)
				}
			}
			for _, marker := range test.hidden {
				if strings.Contains(body.String(), marker) {
					t.Errorf("inactive control %s is rendered", marker)
				}
			}
		})
	}
}
