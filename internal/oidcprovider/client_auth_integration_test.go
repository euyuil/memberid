//go:build integration

package oidcprovider

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestClientAuthenticationChallenge(t *testing.T) {
	f := newConfiguredFixture(t, true)
	page, verifier := f.loginPage("example-web", "openid offline_access")
	code := f.complete(f.verifyPhone(page), f.member.ID)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callback}, "code_verifier": {verifier}}
	check := func(path string, body url.Values) {
		t.Helper()
		for _, credentials := range []string{"example-web:incorrect-synthetic-secret", "unknown:" + f.secret, ""} {
			headers := map[string]string{}
			if credentials != "" {
				headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
			}
			r := f.call(browserClient(), "POST", path, body, headers)
			f.status(r, 401)
			if r.header.Get("WWW-Authenticate") != `Basic realm="MemberID"` {
				t.Fatalf("missing Basic authentication challenge at %s", path)
			}
			if path != "/oauth/introspect" && jsonObject(t, r)["error"] != "invalid_client" {
				t.Fatalf("unexpected client authentication error at %s", path)
			}
		}
	}
	check("/oauth/token", form)
	r := f.exchange("example-web", code, verifier)
	f.status(r, 200)
	if r.header.Get("WWW-Authenticate") != "" {
		t.Fatal("successful exchange includes a challenge")
	}
	tokens := jsonObject(t, r)
	check("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}})
	for _, path := range []string{"/oauth/introspect", "/oauth/revoke"} {
		body := url.Values{"token": {tokens["access_token"].(string)}}
		check(path, body)
		r = f.call(browserClient(), "POST", path, body, map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("example-web:"+f.secret))})
		f.status(r, 200)
		if r.header.Get("WWW-Authenticate") != "" {
			t.Fatal("successful request includes a challenge")
		}
	}
	r = f.exchange("example-web", "invalid-code", verifier)
	f.status(r, 400)
	if r.header.Get("WWW-Authenticate") != "" {
		t.Fatal("non-authentication error includes a challenge")
	}
}
