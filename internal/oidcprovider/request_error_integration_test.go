//go:build integration

package oidcprovider

import (
	"encoding/json"
	"mime"
	"net/http"
	"strings"
	"testing"
)

func TestMalformedClientEndpointRequests(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"/oauth/token", "/oauth/introspect", "/oauth/revoke"} {
		for _, test := range []struct{ name, query, body string }{
			{"duplicate body", "", "grant_type=authorization_code&grant_type=authorization_code"},
			{"duplicate query and body", "?token=one", "token=two"},
			{"malformed body", "", "token=%zz"},
			{"malformed query", "?token=%zz", ""},
			{"oversized body", "", "token=" + strings.Repeat("x", 32<<10)},
			{"oversized query", "?token=" + strings.Repeat("x", 32<<10), ""},
		} {
			t.Run(path+"/"+test.name, func(t *testing.T) {
				request, err := http.NewRequest("POST", f.server.URL+path+test.query, strings.NewReader(test.body))
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.SetBasicAuth("example-web", f.secret)
				response, err := browserClient().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
				if response.StatusCode != 400 || err != nil || mediaType != "application/json" {
					t.Fatalf("expected JSON HTTP 400, got %d %s", response.StatusCode, mediaType)
				}
				var payload map[string]any
				if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				if payload["error"] != "invalid_request" {
					t.Fatalf("unexpected OAuth error: %v", payload)
				}
				if response.Header.Get("Cache-Control") != "no-store" {
					t.Fatal("error response is cacheable")
				}
			})
		}
	}
}
