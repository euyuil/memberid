package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallationDoesNotOverwrite(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "installation")
	if err := Initialize(directory, "https://login.example.invalid", false); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(directory)
	if err != nil || len(loaded.Clients) != 0 || loaded.SigningKey.N.BitLen() != 3072 {
		t.Fatalf("installation load: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(directory, "signing-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Initialize(directory, "https://replacement.example.invalid", false); err == nil {
		t.Fatal("overwrote existing installation")
	}
	after, err := os.ReadFile(filepath.Join(directory, "signing-key.pem"))
	if err != nil || string(before) != string(after) {
		t.Fatal("refused initialization changed a key")
	}
	managementSecret, err := os.ReadFile(filepath.Join(directory, "management-secret"))
	if err != nil || SecretHash(strings.TrimSpace(string(managementSecret))) != loaded.Secrets.ManagementSecretSHA256 {
		t.Fatal("management verifier mismatch")
	}
	if runtime.GOOS != "windows" {
		for _, file := range []string{"signing-key.pem", "secrets.json", "clients.json", "management-secret"} {
			info, err := os.Stat(filepath.Join(directory, file))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("unprotected file %s: %v", file, err)
			}
		}
	}
}

func TestClientPolicy(t *testing.T) {
	client := Client{ID: "example", SubjectKind: "member", SecretSHA256: SecretHash(RandomSecret()), RedirectURIs: []string{"https://app.example.invalid/callback"}}
	if err := ValidateClients([]Client{client}, false); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		modify func(*Client)
	}{
		{"plain HTTP", func(c *Client) { c.RedirectURIs = []string{"http://app.example.invalid/callback"} }},
		{"loopback disabled", func(c *Client) { c.RedirectURIs = []string{"http://127.0.0.1:8080/callback"} }},
		{"wildcard", func(c *Client) { c.RedirectURIs = []string{"https://*.example.invalid/callback"} }},
		{"fragment", func(c *Client) { c.RedirectURIs = []string{"https://app.example.invalid/callback#"} }},
		{"userinfo", func(c *Client) { c.RedirectURIs = []string{"https://account@app.example.invalid/callback"} }},
		{"no callback", func(c *Client) { c.RedirectURIs = nil }},
		{"same callback twice", func(c *Client) { c.RedirectURIs = append(c.RedirectURIs, c.RedirectURIs[0]) }},
		{"public client", func(c *Client) { c.SecretSHA256 = "" }},
		{"foreign subject", func(c *Client) { c.SubjectKind = "user" }},
		{"unrestricted factor", func(c *Client) { c.SubjectKind = "factor" }},
		{"incomplete evidence", func(c *Client) { c.EvidenceScope = "identity" }},
		{"standard scope override", func(c *Client) { c.EvidenceScope = "openid"; c.EvidenceAudience = "https://api.example.invalid" }},
		{"unsafe logout", func(c *Client) { c.PostLogoutRedirectURIs = []string{"//app.example.invalid/logout"} }},
		{"unsafe account return", func(c *Client) { c.AccountReturnURIs = []string{"javascript:alert(1)"} }},
		{"invalid organization", func(c *Client) { c.OrganizationID = "organization" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			copy := client
			test.modify(&copy)
			if ValidateClients([]Client{copy}, false) == nil {
				t.Fatal("accepted invalid client policy")
			}
		})
	}
	if ValidateClients([]Client{client, client}, false) == nil {
		t.Fatal("accepted duplicate clients")
	}
	client.RedirectURIs = []string{"http://127.0.0.1:8080/callback"}
	if err := ValidateClients([]Client{client}, true); err != nil {
		t.Fatal(err)
	}
	client.SubjectKind = "factor"
	client.EvidenceScope = "identity"
	client.EvidenceAudience = "https://api.example.invalid/identity"
	if err := ValidateClients([]Client{client}, true); err != nil {
		t.Fatal(err)
	}
}

func TestIssuerAndFileBoundaries(t *testing.T) {
	value := Installation{Issuer: "https://login.example.invalid", SigningKeyFile: "private.pem", PublicKeysFile: "public.pem", SecretsFile: "secrets.json", ClientsFile: "clients.json"}
	for _, issuer := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "https://login.example.invalid/", "https://login.example.invalid?", "https://login.example.invalid/#", "https://login.example.invalid:0", "https://login.example.invalid:65536"} {
		copy := value
		copy.Issuer = issuer
		if copy.Validate() == nil {
			t.Fatalf("accepted invalid issuer %q", issuer)
		}
	}
	for _, reference := range []string{"../private.pem", "/private.pem", `C:\private.pem`, "..", ""} {
		copy := value
		copy.SigningKeyFile = reference
		if copy.Validate() == nil {
			t.Fatal("accepted nonlocal file reference")
		}
	}
	value.Issuer = "http://127.0.0.1:8080"
	value.AllowLoopbackHTTP = true
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidConfigurationIsRedacted(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "settings.json")
	sensitive := RandomSecret()
	if err := os.WriteFile(file, []byte(`{"unknown":"`+sensitive+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var target Installation
	err := ReadJSON(file, &target)
	if err == nil || strings.Contains(err.Error(), sensitive) {
		t.Fatal("invalid configuration was accepted or disclosed")
	}
}

func TestClientMutationRefusesLocksAndInvalidUpdates(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "installation")
	if err := Initialize(directory, "https://login.example.invalid", false); err != nil {
		t.Fatal(err)
	}
	registry := filepath.Join(directory, "clients.json")
	before, _ := os.ReadFile(registry)
	err := ChangeClients(directory, func(clients []Client) ([]Client, error) { return append(clients, Client{ID: "invalid"}), nil })
	if err == nil {
		t.Fatal("accepted invalid registry update")
	}
	after, _ := os.ReadFile(registry)
	if string(before) != string(after) {
		t.Fatal("invalid update changed the registry")
	}
	lock := filepath.Join(directory, ".clients.lock")
	if err := os.WriteFile(lock, []byte("owned by another operator"), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	if ChangeClients(directory, func(clients []Client) ([]Client, error) { called = true; return clients, nil }) == nil || called {
		t.Fatal("ignored another operator's lock")
	}
	if _, err := os.Stat(lock); err != nil {
		t.Fatal("removed another operator's lock")
	}
	var clients []Client
	if json.Unmarshal(after, &clients) != nil || len(clients) != 0 {
		t.Fatal("changed registry")
	}
}

func TestSigningMaterialValidation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "installation")
	if err := Initialize(directory, "https://login.example.invalid", false); err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(directory, "public-keys.pem")
	public, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range [][]byte{nil, []byte("invalid"), append(append([]byte{}, public...), public...)} {
		if err := os.WriteFile(publicPath, content, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(directory); err == nil {
			t.Fatal("accepted missing, invalid, or duplicate public material")
		}
	}
	if err := os.WriteFile(publicPath, public, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "signing-key.pem"), public, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(directory); err == nil {
		t.Fatal("accepted public material as a signing key")
	}
}
