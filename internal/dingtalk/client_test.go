package dingtalk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func TestAuthorizationContract(t *testing.T) {
	client := New()
	calls := 0
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.String() != "https://api.dingtalk.com/v1.0/oauth2/example-corp/token" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" {
			t.Fatal("incorrect authorization request")
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 3 || body["client_id"] != "example-client" || body["client_secret"] != "synthetic-secret" || body["grant_type"] != "client_credentials" {
			t.Fatal("incorrect authorization body")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"access_token":"synthetic-token","expires_in":7200}`)), Header: make(http.Header)}, nil
	})
	for range 2 {
		if err := client.CheckAuthorization(t.Context(), "example-corp", "example-client", "synthetic-secret"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatal("authorization verification was cached")
	}
}

func TestAuthorizationFailureRedactionAndNoRetry(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  int
		body    string
		failure error
		want    error
	}{
		{"denied", 400, `{"code":"unauthorized.client","message":"private provider message"}`, nil, ErrAuthorizationDenied},
		{"invalid client", 400, `{"code":"invalid.client","message":"private provider message"}`, nil, ErrUnavailable},
		{"unknown", 500, `{"code":"server.error","message":"private provider message"}`, nil, ErrUnavailable},
		{"misleading denial", 500, `{"code":"unauthorized.client"}`, nil, ErrUnavailable},
		{"no token", 200, `{"expires_in":7200}`, nil, ErrUnavailable},
		{"no expiry", 200, `{"access_token":"synthetic-token"}`, nil, ErrUnavailable},
		{"overflow expiry", 200, `{"access_token":"synthetic-token","expires_in":9223372036854775807}`, nil, ErrUnavailable},
		{"mixed error", 200, `{"access_token":"synthetic-token","expires_in":7200,"code":"server.error"}`, nil, ErrUnavailable},
		{"malformed", 200, `private provider message`, nil, ErrUnavailable},
		{"oversized", 200, strings.Repeat("x", (64<<10)+1), nil, ErrUnavailable},
		{"network", 0, "", errors.New("private network address and credential"), ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := New()
			client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if test.failure != nil {
					return nil, test.failure
				}
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
			})
			err := client.CheckAuthorization(t.Context(), "example-corp", "example-client", "synthetic-secret")
			if err != test.want || calls != 1 {
				t.Fatal("provider failure was retried or disclosed")
			}
		})
	}
}

func TestAuthorizationRejectsRedirectAndCanceledRequest(t *testing.T) {
	destinationCalls := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls++; w.WriteHeader(200) }))
	defer destination.Close()
	client := New()
	calls := 0
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Context().Err() != nil {
			return nil, r.Context().Err()
		}
		return &http.Response{StatusCode: 307, Header: http.Header{"Location": []string{destination.URL}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	if err := client.CheckAuthorization(t.Context(), "example-corp", "example-client", "synthetic-secret"); err != ErrUnavailable {
		t.Fatal(err)
	}
	if calls != 1 || destinationCalls != 0 {
		t.Fatal("credentials followed a redirect")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := client.CheckAuthorization(ctx, "example-corp", "example-client", "synthetic-secret"); err != ErrUnavailable {
		t.Fatal(err)
	}
}

func TestCredentialInputCannotChangeEndpoint(t *testing.T) {
	for _, value := range []string{"", "../other", "x/y", "x?token=y", "x#fragment", "x%2fy", "x.example:443", "x\nheader", strings.Repeat("x", 257)} {
		if ValidCredentials(value, "example-client", "synthetic-secret") || ValidCredentials("example-corp", value, "synthetic-secret") {
			t.Fatal("invalid identifier accepted")
		}
	}
	for _, secret := range []string{"", " ", "line\nbreak", "trailing ", strings.Repeat("x", 4097), string([]byte{255})} {
		if ValidCredentials("example-corp", "example-client", secret) {
			t.Fatal("invalid secret accepted")
		}
	}
	client := New()
	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid input reached provider")
		return nil, ErrUnavailable
	})
	if err := client.CheckAuthorization(t.Context(), "../other", "example-client", "synthetic-secret"); err != ErrUnavailable {
		t.Fatal(err)
	}
}
