//go:build integration

package oidcprovider

import (
	"net/url"
	"reflect"
	"testing"
)

func TestAuthorizationResponseModes(t *testing.T) {
	f := newFixture(t)
	metadata := jsonObject(t, f.call(browserClient(), "GET", "/.well-known/openid-configuration", nil, nil))
	if !reflect.DeepEqual(metadata["response_modes_supported"], []any{"query", "fragment"}) {
		t.Fatal("Discovery does not match the supported response modes")
	}
	for _, mode := range []string{"form_post", "unknown"} {
		r, _ := f.authorization("example-web", "openid", url.Values{"response_mode": {mode}})
		location, _ := url.Parse(r.header.Get("Location"))
		if r.status != 302 || location.Path != "/callback" || location.Query().Get("error") != "invalid_request" || location.Query().Get("state") != "example-state" {
			t.Fatalf("unsupported mode %s was not rejected before login", mode)
		}
	}
	for _, mode := range []string{"", "query", "fragment"} {
		r, _ := f.authorization("example-web", "openid", url.Values{"response_mode": {mode}, "prompt": {"none"}})
		f.status(r, 302)
		r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
		f.status(r, 302)
		location, _ := url.Parse(r.header.Get("Location"))
		values := location.Query()
		if mode == "fragment" {
			values, _ = url.ParseQuery(location.Fragment)
			if location.RawQuery != "" {
				t.Fatal("fragment error leaked into query")
			}
		}
		if values.Get("error") != "login_required" || values.Get("state") != "example-state" {
			t.Fatalf("mode %s did not preserve the interaction error and state", mode)
		}
	}
	_ = f.tokens()
	for _, mode := range []string{"query", "fragment"} {
		r, verifier := f.authorization("example-web", "openid", url.Values{"response_mode": {mode}})
		f.status(r, 302)
		page := f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
		f.status(page, 200)
		r = f.submit(page.body, "continue", url.Values{"member": {f.member.ID}, "consent": {"yes"}})
		f.status(r, 303)
		r = f.call(f.browser, "GET", r.header.Get("Location"), nil, nil)
		f.status(r, 302)
		location, _ := url.Parse(r.header.Get("Location"))
		values := location.Query()
		if mode == "fragment" {
			values, _ = url.ParseQuery(location.Fragment)
			if location.RawQuery != "" {
				t.Fatal("fragment code leaked into query")
			}
		}
		if values.Get("code") == "" || values.Get("state") != "example-state" {
			t.Fatal("missing code or state")
		}
		f.status(f.exchange("example-web", values.Get("code"), verifier), 200)
	}
}
