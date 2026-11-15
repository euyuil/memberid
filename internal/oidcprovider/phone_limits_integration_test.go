//go:build integration

package oidcprovider

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/identity"
)

func setPhoneLimits(t *testing.T, f *fixture, limits identity.PhoneSendLimits) {
	t.Helper()
	key, _ := base64.StdEncoding.DecodeString(f.service.configuration.Secrets.PhoneCodeKey)
	phone, err := identity.NewPhoneVerifier(f.store, key, f.sender, limits)
	if err != nil {
		t.Fatal(err)
	}
	f.service.phone = phone
}

func assertPhoneLimited(t *testing.T, f *fixture, response reply) {
	t.Helper()
	f.status(response, 200)
	if !strings.Contains(response.body, "Please wait before requesting another") {
		t.Fatal("send quota not enforced", response.body)
	}
	var count int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM phone_challenges").Scan(&count); err != nil || count != 1 {
		t.Fatal("denied send created another challenge", count, err)
	}
}

func TestPhoneLoginSendQuotas(t *testing.T) {
	for _, dimension := range []string{"transaction", "browser", "source", "client", "installation"} {
		t.Run(dimension, func(t *testing.T) {
			f := newFixture(t)
			limits := identity.PhoneSendLimits{}
			switch dimension {
			case "transaction":
				limits.Transaction = 1
			case "browser":
				limits.Browser = 1
			case "source":
				limits.Source = 1
			case "client":
				limits.Client = 1
			case "installation":
				limits.Installation = 1
			}
			setPhoneLimits(t, f, limits)
			page, _ := f.loginPage("example-web", "openid")
			f.status(f.submit(page.body, "send", url.Values{"phone": {"19900000001"}}), 200)
			page = f.submit(page.body, "cancel", nil)
			f.status(page, 200)
			if dimension != "transaction" {
				client := "second-web"
				if dimension != "browser" {
					f.browser = browserClient()
				}
				if dimension == "client" {
					client = "example-web"
				}
				page, _ = f.loginPage(client, "openid")
			}
			form := url.Values{"request": {hidden(t, page.body, "request")}, "csrf": {hidden(t, page.body, "csrf")}, "action": {"send"}, "phone": {"19900000002"}}
			result := f.call(f.browser, "POST", "/login", form, map[string]string{"Origin": f.server.URL, "X-Forwarded-For": "198.51.100.2"})
			assertPhoneLimited(t, f, result)
		})
	}
}

func TestPhoneAccountAndLoginShareSendQuota(t *testing.T) {
	for _, accountFirst := range []bool{false, true} {
		name := "login first"
		if accountFirst {
			name = "account first"
		}
		t.Run(name, func(t *testing.T) {
			f, account := phoneAccountFixture(t)
			setPhoneLimits(t, f, identity.PhoneSendLimits{Browser: 1})
			// Force an interactive login while retaining the same browser and account session.
			authorization, _ := f.authorization("example-web", "openid", url.Values{"prompt": {"login"}})
			f.status(authorization, 302)
			login := f.call(f.browser, "GET", authorization.header.Get("Location"), nil, nil)
			f.status(login, 200)
			if accountFirst {
				sendAccountPhone(f, account)
				assertPhoneLimited(t, f, f.submit(login.body, "send", url.Values{"phone": {"19900000004"}}))
			} else {
				f.status(f.submit(login.body, "send", url.Values{"phone": {"19900000004"}}), 200)
				assertPhoneLimited(t, f, phoneAccountSubmit(f, account, "send", url.Values{"phone": {linkPhoneNumber}}))
			}
		})
	}
}
