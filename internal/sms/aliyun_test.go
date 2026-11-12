package sms

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transport func(*http.Request) (*http.Response, error)

func (call transport) RoundTrip(request *http.Request) (*http.Response, error) { return call(request) }

func settings() map[string]string {
	return map[string]string{"MEMBERID_PHONE_ENABLED": "true", "MEMBERID_SMS_ACCESS_KEY_ID": "example-id", "MEMBERID_SMS_ACCESS_KEY_SECRET": "example-credential", "MEMBERID_SMS_SIGN_NAME": "Example 签名 +", "MEMBERID_SMS_TEMPLATE_CODE": "EXAMPLE-TEMPLATE"}
}
func TestOptionalConfiguration(t *testing.T) {
	empty := func(string) string { return "" }
	if sender, err := FromEnvironment(empty); sender != nil || err != nil {
		t.Fatal("disabled phone provider required configuration")
	}
	for _, name := range []string{"MEMBERID_SMS_ACCESS_KEY_ID", "MEMBERID_SMS_ACCESS_KEY_SECRET", "MEMBERID_SMS_SIGN_NAME", "MEMBERID_SMS_TEMPLATE_CODE"} {
		values := settings()
		delete(values, name)
		if _, err := FromEnvironment(func(key string) string { return values[key] }); err == nil {
			t.Fatal("enabled provider accepted incomplete settings")
		}
	}
	values := settings()
	values["MEMBERID_PHONE_ENABLED"] = "yes"
	if _, err := FromEnvironment(func(key string) string { return values[key] }); err == nil {
		t.Fatal("invalid enable flag was accepted")
	}
}

func TestRequestAndProviderDenials(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		failure error
		success bool
	}{
		{"accepted", 200, `{"Code":"OK","Success":true}`, nil, true},
		{"missing status", 200, `{"Code":"OK"}`, nil, false},
		{"denied", 200, `{"Code":"Denied","Success":true,"Message":"private-response"}`, nil, false},
		{"unsuccessful", 200, `{"Code":"OK","Success":false}`, nil, false},
		{"redirect", 302, `{"Code":"OK","Success":true}`, nil, false},
		{"server failure", 500, `{"Code":"OK","Success":true}`, nil, false},
		{"invalid JSON", 200, `{"Code":"OK","Success":true} extra`, nil, false},
		{"oversized", 200, strings.Repeat(" ", 1<<20) + `{}`, nil, false},
		{"transport failure", 0, "", errors.New("private transport details"), false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			values := settings()
			sender, err := FromEnvironment(func(key string) string { return values[key] })
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			sender.client.Transport = transport(func(request *http.Request) (*http.Response, error) {
				calls++
				q := request.URL.Query()
				if request.Method != "POST" || request.URL.Scheme != "https" || request.URL.Host != "dypnsapi.aliyuncs.com" || strings.Contains(request.URL.RawQuery, "+") {
					t.Error("incorrect provider request")
				}
				if q.Get("PhoneNumber") != "19900000001" || q.Get("CountryCode") != "86" || q.Get("TemplateParam") != `{"code":"012345","min":"5"}` || q.Get("SignName") != values["MEMBERID_SMS_SIGN_NAME"] {
					t.Error("changed local code or template")
				}
				if q.Get("AutoRetry") != "0" || q.Get("ReturnVerifyCode") != "false" || q.Get("Interval") != "60" || q.Get("ValidTime") != "300" {
					t.Error("unsafe provider defaults")
				}
				if request.Header.Get("x-acs-signature-nonce") == "" || !strings.HasPrefix(request.Header.Get("Authorization"), "ACS3-HMAC-SHA256 Credential=example-id,") {
					t.Error("missing signature")
				}
				if test.failure != nil {
					return nil, test.failure
				}
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body)), Header: http.Header{"Location": {"https://unexpected.example.invalid/"}}}, nil
			})
			err = sender.Send(context.Background(), "+8619900000001", "012345")
			if (err == nil) != test.success || err != nil && !errors.Is(err, ErrUnavailable) {
				t.Fatalf("incorrect or unredacted result: %v", err)
			}
			if calls != 1 {
				t.Fatal("provider delivery was retried")
			}
		})
	}
}

func TestCanonicalSignature(t *testing.T) {
	request, err := http.NewRequest("POST", "https://dypnsapi.aliyuncs.com/?PhoneNumber=19900000001&SignName=Example%20Sign&TemplateParam=%7B%22code%22%3A%22012345%22%7D", nil)
	if err != nil {
		t.Fatal(err)
	}
	sign(request, AliyunConfig{AccessKeyID: "example-id", AccessKeySecret: "example-credential"}, "2030-01-01T00:00:00Z", "example-nonce")
	// Independently calculated with .NET SHA-256 and HMAC-SHA256.
	if !strings.HasSuffix(request.Header.Get("Authorization"), "Signature=28e28ded9ebcdc382aaef362a70416c08a4a527ac691dd3b93c08f8e6e67b8e9") {
		t.Fatal("canonical request signature changed")
	}
}
