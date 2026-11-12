package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/euyuil/memberid/internal/config"
)

func TestExportJWKSCommand(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "installation")
	if err := config.Initialize(directory, "https://login.example.invalid", false); err != nil {
		t.Fatal(err)
	}
	retained, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&retained.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicFile := filepath.Join(directory, "public-keys.pem")
	public, err := os.ReadFile(publicFile)
	if err != nil {
		t.Fatal(err)
	}
	retainedPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})
	if err := os.WriteFile(publicFile, append(public, retainedPEM...), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		contents, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		before[entry.Name()] = contents
	}
	// Export is available before database or authentication-provider setup.
	t.Setenv("MEMBERID_DATABASE_URL", "not-a-database-url")
	t.Setenv("MEMBERID_SMS_ENABLED", "invalid")
	args := []string{"config", "export-jwks", "--directory", directory}
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), args, &stdout, &stderr); err != nil || stderr.Len() != 0 {
		t.Fatal("offline public export failed", err)
	}
	first := append([]byte{}, stdout.Bytes()...)
	var result jose.JSONWebKeySet
	if err := json.Unmarshal(first, &result); err != nil || len(result.Keys) != 2 {
		t.Fatal("active and retained public keys were not exported", err)
	}
	ids := []string{}
	for _, key := range result.Keys {
		publicKey, ok := key.Key.(*rsa.PublicKey)
		if !ok || !key.IsPublic() || key.Algorithm != "RS256" || key.Use != "sig" || loaded.PublicKeys[key.KeyID] == nil || !publicKey.Equal(loaded.PublicKeys[key.KeyID]) {
			t.Fatal("export changed public key material or metadata")
		}
		ids = append(ids, key.KeyID)
	}
	if !slices.IsSorted(ids) || !slices.Contains(ids, loaded.KeyID) || !slices.Contains(ids, config.KeyID(&retained.PublicKey)) {
		t.Fatal("export did not preserve stable active and retained key identifiers")
	}
	stdout.Reset()
	if err := run(t.Context(), args, &stdout, &stderr); err != nil || !bytes.Equal(first, stdout.Bytes()) {
		t.Fatal("repeated export changed its bytes", err)
	}
	for name, original := range before {
		current, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !bytes.Equal(current, original) {
			t.Fatal("export modified installation configuration", name, err)
		}
	}
	for _, secret := range []string{loaded.Secrets.ProtocolKey, loaded.Secrets.PhoneCodeKey, loaded.Secrets.ProviderKey, loaded.Secrets.ManagementSecretSHA256, string(bytes.TrimSpace(before["management-secret"]))} {
		if secret == "" || bytes.Contains(first, []byte(secret)) {
			t.Fatal("export included private installation material")
		}
	}
	for _, invalid := range [][]string{
		{"config", "export-jwks"},
		append(slices.Clone(args), "extra"),
		append(slices.Clone(args), "--issuer", "https://other.example.invalid"),
		append(slices.Clone(args), "--allow-loopback-http"),
	} {
		stdout.Reset()
		stderr.Reset()
		if err := run(t.Context(), invalid, &stdout, &stderr); err == nil || stdout.Len() != 0 {
			t.Fatal("invalid export request succeeded or wrote a partial key set")
		}
	}
	if err := os.WriteFile(publicFile, retainedPEM, 0600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := run(t.Context(), args, &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatal("installation missing its active verification key was exported")
	}
}
