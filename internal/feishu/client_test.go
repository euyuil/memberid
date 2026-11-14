package feishu

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (fn transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func response(status int, payload string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload))}
}

func TestFeishuExchangeAndUserInfo(t *testing.T) {
	callback := "https://memberid.example.invalid/login/feishu/callback"
	verifier := oauth2.GenerateVerifier()
	location, err := url.Parse(AuthorizationURL("cli_example", callback, "example-state", verifier))
	if err != nil || location.Query().Get("code_challenge") != oauth2.S256ChallengeFromVerifier(verifier) {
		t.Fatal("Feishu challenge does not match the verifier", err)
	}
	client := New()
	var requests int
	client.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		switch r.URL.String() {
		case loginTokenURL:
			var body map[string]string
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json; charset=utf-8" || json.NewDecoder(r.Body).Decode(&body) != nil ||
				body["client_id"] != "cli_example" || body["client_secret"] != "example-secret" || body["grant_type"] != "authorization_code" ||
				body["code"] != "example-code" || body["code_verifier"] != verifier || body["redirect_uri"] != callback {
				t.Fatal("unexpected authorization code exchange")
			}
			return response(200, `{"code":0,"access_token":"example-token","expires_in":3600,"token_type":"Bearer"}`), nil
		case userInfoURL:
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer example-token" {
				t.Fatal("unexpected user info request")
			}
			return response(200, `{"code":0,"data":{"tenant_key":"example-tenant","open_id":"ou_example","name":"Example Member","mobile":"+8619900000001"}}`), nil
		default:
			t.Fatalf("unexpected destination %s", r.URL)
			return nil, nil
		}
	})
	profile, err := client.Login(t.Context(), "cli_example", "example-secret", callback, "example-code", verifier)
	if err != nil || profile != (Profile{"example-tenant", "ou_example", "Example Member"}) || requests != 2 {
		t.Fatal("login did not yield scoped user identity", err)
	}
}

func TestFeishuAuthorizationCheckClassifiesOnlyDefinitiveFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		payload string
		want    error
	}{
		{"active", 200, `{"code":0,"access_token":"example-token","expires_in":3600,"token_type":"Bearer"}`, nil},
		{"missing installation", 400, `{"code":20009}`, ErrAuthorizationDenied},
		{"disabled application", 400, `{"code":20069}`, ErrAuthorizationDenied},
		{"secret rejected", 400, `{"code":20002,"error_description":"credential diagnostic"}`, ErrUnavailable},
		{"invalid envelope", 200, `{"access_token":"example-token","expires_in":3600,"token_type":"Bearer"}`, ErrUnavailable},
		{"oversized", 200, strings.Repeat("x", (64<<10)+1), ErrUnavailable},
		{"redirect", 307, "", ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := New()
			requests := 0
			client.http.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
				requests++
				if r.URL.String() != applicationTokenURL || r.Method != http.MethodPost || r.ParseForm() != nil ||
					r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != "cli_example" || r.PostForm.Get("client_secret") != "example-secret" {
					t.Fatal("unexpected credential-validation request")
				}
				res := response(tc.status, tc.payload)
				res.Header.Set("Location", "https://unexpected.example.invalid")
				return res, nil
			})
			if err := client.CheckAuthorization(t.Context(), "cli_example", "example-secret"); !errors.Is(err, tc.want) || requests != 1 {
				t.Fatal("unexpected authorization result", err, requests)
			}
		})
	}
}
