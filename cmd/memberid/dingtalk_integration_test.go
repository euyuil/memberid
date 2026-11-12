//go:build integration

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/testdb"
)

type applicationTransport func(*http.Request) (*http.Response, error)

func (transport applicationTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return transport(r)
}

func TestDingTalkOperatorCommands(t *testing.T) {
	databaseURL := testdb.Create(t)
	t.Setenv("MEMBERID_DATABASE_URL", databaseURL)
	if err := identity.Initialize(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	store, err := identity.Open(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	organization, err := store.CreateOrganization(t.Context(), "", "Example organization")
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "installation")
	if err := config.Initialize(directory, "https://login.example.invalid", false); err != nil {
		t.Fatal(err)
	}
	secret := rand.Text()
	secretFile := filepath.Join(t.TempDir(), "provider-secret")
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	prior := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = prior })
	calls := 0
	denied := false
	http.DefaultTransport = applicationTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://api.dingtalk.com/v1.0/oauth2/example-corp/token" {
			t.Fatal("unexpected provider request")
		}
		var request map[string]string
		if json.NewDecoder(r.Body).Decode(&request) != nil || request["client_secret"] != secret {
			t.Fatal("CLI did not read the protected secret file")
		}
		if denied {
			return &http.Response{StatusCode: 400, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":"unauthorized.client"}`))}, nil
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"synthetic-token","expires_in":7200}`))}, nil
	})
	var output, diagnostic bytes.Buffer
	configure := []string{"dingtalk", "configure", "--directory", directory, "--organization", organization.ID, "--corp", "example-corp", "--client", "example-client", "--secret-file", secretFile, "--expected-revision", "0"}
	if err := run(t.Context(), configure, &output, &diagnostic); err != nil {
		t.Fatal(err)
	}
	var info identity.DingTalkApplication
	if json.Unmarshal(output.Bytes(), &info) != nil || info.Revision != 1 || strings.Contains(output.String()+diagnostic.String(), secret) {
		t.Fatal("invalid or secret-bearing CLI output")
	}
	output.Reset()
	if err := run(t.Context(), []string{"dingtalk", "inspect", "--directory", directory, "--organization", organization.ID}, &output, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || json.Unmarshal(output.Bytes(), &info) != nil || info.Revision != 1 {
		t.Fatal("inspection contacted provider or lost metadata")
	}
	output.Reset()
	if err := run(t.Context(), configure, &output, &diagnostic); err == nil || calls != 1 {
		t.Fatal("stale configuration was accepted or sent to provider")
	}
	for _, args := range [][]string{{"dingtalk"}, {"dingtalk", "delete"}, {"dingtalk", "configure", "--directory", directory, "--organization", organization.ID}, {"dingtalk", "inspect", "--directory", directory, "--organization", "invalid"}} {
		if err := run(t.Context(), args, &output, &diagnostic); err == nil {
			t.Fatal("invalid operator command accepted")
		}
	}
	for _, status := range []string{"revoked", "active"} {
		denied = status == "revoked"
		output.Reset()
		if err := run(t.Context(), []string{"dingtalk", "sync", "--directory", directory, "--organization", organization.ID}, &output, &diagnostic); err != nil {
			t.Fatal(err)
		}
		if json.Unmarshal(output.Bytes(), &info) != nil || info.AuthorizationStatus != status || info.Revision != 1 || strings.Contains(output.String()+diagnostic.String(), secret) {
			t.Fatal("invalid or secret-bearing synchronization result")
		}
	}
	output.Reset()
	if err := run(t.Context(), []string{"dingtalk", "reconcile", "--directory", directory, "--organization", organization.ID}, &output, &diagnostic); err != nil {
		t.Fatal(err)
	}
	var reconciliation identity.DingTalkReconciliation
	if json.Unmarshal(output.Bytes(), &reconciliation) != nil || reconciliation.Application.OrganizationID != organization.ID || reconciliation.Application.AuthorizationStatus != "active" || reconciliation.Checked != 0 || strings.Contains(output.String()+diagnostic.String(), secret) {
		t.Fatal("invalid reconciliation output")
	}
	if calls != 4 {
		t.Fatal("synchronization did not make fresh authorization checks")
	}
}
