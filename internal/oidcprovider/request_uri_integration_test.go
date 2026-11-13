//go:build integration

package oidcprovider

import (
	"net/url"
	"testing"
)

func requireRequestURIError(t *testing.T, response reply, kind string) {
	t.Helper()
	location, err := url.Parse(response.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if response.status != 302 || location.Scheme+"://"+location.Host+location.Path != callback || location.Query().Get("error") != kind || location.Query().Get("state") != "example-state" || location.Query().Has("code") {
		t.Fatalf("expected authorization error %s, got status %d and location %s", kind, response.status, location)
	}
}

func TestAuthorizationRejectsRequestURI(t *testing.T) {
	f := newFixture(t)
	metadata := jsonObject(t, f.call(browserClient(), "GET", "/.well-known/openid-configuration", nil, nil))
	if metadata["request_uri_parameter_supported"] != false {
		t.Fatal("Discovery advertises unsupported request_uri")
	}
	extra := url.Values{"request_uri": {"https://request.example.test/object.jwt"}}
	r, _ := f.authorization("example-web", "openid", extra)
	requireRequestURIError(t, r, "request_uri_not_supported")

	for _, override := range []url.Values{{"client_id": {"unknown"}}, {"redirect_uri": {"https://unregistered.example.test/callback"}}} {
		override.Set("request_uri", extra.Get("request_uri"))
		r, _ := f.authorization("example-web", "openid", override)
		if r.status != 400 || r.header.Get("Location") != "" {
			t.Fatal("unsupported request_uri redirected without a registered client callback")
		}
	}

	extra.Set("request_uri", "")
	r, _ = f.authorization("example-web", "openid", extra)
	f.status(r, 302)
	location, _ := url.Parse(r.header.Get("Location"))
	if location.Path != "/login" {
		t.Fatal("empty request_uri must be treated as absent")
	}
}
