//go:build integration

package main

import (
	"io"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/testdb"
)

func TestOIDCStartsWithDingTalkWithoutPhoneCredentials(t *testing.T) {
	databaseURL := testdb.Create(t)
	if err := identity.Initialize(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEMBERID_DATABASE_URL", databaseURL)
	t.Setenv("MEMBERID_PHONE_ENABLED", "false")
	t.Setenv("MEMBERID_DINGTALK_ENABLED", "true")
	for _, key := range []string{"MEMBERID_SMS_ACCESS_KEY_ID", "MEMBERID_SMS_ACCESS_KEY_SECRET", "MEMBERID_SMS_SIGN_NAME", "MEMBERID_SMS_TEMPLATE_CODE"} {
		t.Setenv(key, "")
	}
	directory := filepath.Join(t.TempDir(), "installation")
	if err := config.Initialize(directory, "https://login.example.invalid", false); err != nil {
		t.Fatal(err)
	}
	if err := run(t.Context(), []string{"client", "add", "--directory", directory, "--id", "example-web", "--redirect", "https://app.example.invalid/callback"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	handler, closeStore, err := authenticationHandler(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer closeStore()
	request := httptest.NewRequest("GET", "https://login.example.invalid/.well-known/openid-configuration", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatal("DingTalk-only provider did not serve discovery")
	}
	t.Setenv("MEMBERID_DINGTALK_ENABLED", "invalid")
	if _, closeStore, err := authenticationHandler(t.Context(), directory); err == nil {
		closeStore()
		t.Fatal("invalid provider switch accepted")
	}
	t.Setenv("MEMBERID_DINGTALK_ENABLED", "false")
	if _, closeStore, err := authenticationHandler(t.Context(), directory); err == nil {
		closeStore()
		t.Fatal("OIDC started with no authentication providers")
	}
}
