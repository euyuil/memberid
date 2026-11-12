package dingtalk

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func loginResponses() []string {
	return []string{`{"accessToken":"synthetic-user-token","corpId":"example-corp"}`, `{"unionId":"example-union","mobile":"untrusted-contact","email":"unverified@example.invalid"}`, `{"access_token":"synthetic-application-token","expires_in":7200}`, `{"errcode":0,"result":{"userid":"example-employee","contact_type":0}}`, `{"errcode":0,"result":{"userid":"example-employee","unionid":"example-union","name":"Example Member","dept_id_list":[17,23]}}`}
}

func loginTransport(t *testing.T, responses []string) (*Client, *int) {
	t.Helper()
	client := New()
	calls := new(int)
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		index := *calls
		*calls++
		if index >= len(responses) {
			t.Fatal("unexpected additional provider call")
		}
		paths := []string{"/v1.0/oauth2/userAccessToken", "/v1.0/contact/users/me", "/v1.0/oauth2/example-corp/token", "/topapi/user/getbyunionid", "/topapi/v2/user/get"}
		if r.URL.Path != paths[index] {
			t.Fatal("wrong provider request order")
		}
		if index < 3 && r.URL.Host != "api.dingtalk.com" || index >= 3 && r.URL.Host != "oapi.dingtalk.com" || r.URL.Scheme != "https" {
			t.Fatal("provider request changed origin")
		}
		if index == 1 {
			if r.Method != "GET" || r.Header.Get("x-acs-dingtalk-access-token") != "synthetic-user-token" {
				t.Fatal("wrong user credential transport")
			}
		} else {
			if r.Method != "POST" {
				t.Fatal("wrong provider request method")
			}
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Fatal("invalid provider JSON")
			}
			switch index {
			case 0:
				if len(body) != 4 || body["grantType"] != "authorization_code" || body["clientId"] != "example-client" || body["clientSecret"] != "synthetic-secret" || body["code"] != "synthetic-code" {
					t.Fatal("wrong code exchange")
				}
			case 2:
				if body["grant_type"] != "client_credentials" || body["client_id"] != "example-client" || body["client_secret"] != "synthetic-secret" {
					t.Fatal("wrong corporation credential")
				}
			case 3:
				if body["unionid"] != "example-union" {
					t.Fatal("wrong subject lookup")
				}
			case 4:
				if body["userid"] != "example-employee" {
					t.Fatal("wrong Member lookup")
				}
			}
		}
		if index >= 3 && (r.URL.Query().Get("access_token") != "synthetic-application-token" || r.Header.Get("x-acs-dingtalk-access-token") != "") {
			t.Fatal("directory request used the user token")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(responses[index]))}, nil
	})
	return client, calls
}

func TestLoginVerifiesCorporationAndDirectoryMembership(t *testing.T) {
	client, calls := loginTransport(t, loginResponses())
	member, err := client.Login(t.Context(), "example-corp", "example-client", "synthetic-secret", "synthetic-code")
	if err != nil || *calls != 5 || member.UnionID != "example-union" || member.UserID != "example-employee" || member.DisplayName != "Example Member" || !reflect.DeepEqual(member.DepartmentIDs, []string{"17", "23"}) {
		t.Fatal("failed verified membership", err)
	}
}

func TestLoginRejectsUncertainOrConflictingEvidence(t *testing.T) {
	for _, test := range []struct {
		name     string
		step     int
		response string
	}{
		{"wrong corporation", 0, `{"accessToken":"synthetic-user-token","corpId":"different-corp"}`},
		{"missing corporation", 0, `{"accessToken":"synthetic-user-token"}`},
		{"missing union", 1, `{"mobile":"untrusted-contact","email":"unverified@example.invalid"}`},
		{"directory denial", 3, `{"errcode":60121,"errmsg":"private directory details"}`},
		{"missing status", 3, `{"result":{"userid":"example-employee","contact_type":0}}`},
		{"external contact", 3, `{"errcode":0,"result":{"userid":"example-employee","contact_type":1}}`},
		{"unknown contact", 3, `{"errcode":0,"result":{"userid":"example-employee"}}`},
		{"wrong union", 4, `{"errcode":0,"result":{"userid":"example-employee","unionid":"different-union"}}`},
		{"wrong employee", 4, `{"errcode":0,"result":{"userid":"different-employee","unionid":"example-union"}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			responses := loginResponses()
			responses[test.step] = test.response
			client, calls := loginTransport(t, responses)
			member, err := client.Login(t.Context(), "example-corp", "example-client", "synthetic-secret", "synthetic-code")
			if err != ErrUnavailable || member.UnionID != "" || *calls != test.step+1 {
				t.Fatal("uncertain evidence admitted or retried", err)
			}
		})
	}
}

func TestOptionalDepartmentEvidencePreservesUnknownAndEmpty(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want []string
	}{{"null", nil}, {`"unavailable"`, nil}, {`[17,17]`, nil}, {`[0]`, nil}, {`["17"]`, nil}, {`[]`, []string{}}, {`[17,23]`, []string{"17", "23"}}} {
		if actual := departments(json.RawMessage(test.raw)); !reflect.DeepEqual(actual, test.want) {
			t.Fatal("optional department state changed")
		}
	}
	responses := loginResponses()
	responses[4] = `{"errcode":"0","result":{"userid":"example-employee","unionid":"example-union","dept_id_list":"unavailable"}}`
	client, _ := loginTransport(t, responses)
	member, err := client.Login(t.Context(), "example-corp", "example-client", "synthetic-secret", "synthetic-code")
	if err != nil || member.DepartmentIDs != nil {
		t.Fatal("optional evidence invalidated membership", err)
	}
}
