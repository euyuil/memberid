package oidcprovider

import (
	"bytes"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/identity"
)

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
			visible: []string{`id="organization"`, `value="choose-organization"`},
			hidden:  []string{`id="username"`, `id="phone"`, `id="code"`, `id="member"`, `value="cancel"`, `value="continue"`},
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
