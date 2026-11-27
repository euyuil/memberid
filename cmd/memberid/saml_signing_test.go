package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhizhun-tech/memberid/internal/config"
)

func TestSAMLSigningOperatorCommands(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "installation")
	if err := config.Initialize(directory, "https://login.example.test", false); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{"saml-key.pem": {Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}, "saml.pem": {Type: "CERTIFICATE", Bytes: der}} {
		if err := config.WriteExclusive(filepath.Join(directory, name), pem.EncodeToMemory(block)); err != nil {
			t.Fatal(err)
		}
	}
	loaded.SAML = &config.SAML{Enabled: true, SigningKeyFile: "saml-key.pem", CertificateFile: "saml.pem"}
	data, _ := json.Marshal(loaded.Installation)
	if err := os.WriteFile(filepath.Join(directory, "memberid.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEMBERID_DATABASE_URL", "not-a-database-url")
	var stdout, stderr bytes.Buffer
	call := func(args ...string) error {
		stdout.Reset()
		stderr.Reset()
		return run(t.Context(), append([]string{"saml", "signing"}, args...), &stdout, &stderr)
	}
	if err := call("inspect", "--directory", directory); err != nil {
		t.Fatal(err)
	}
	var inspected config.SAMLSigningInspection
	if err := json.Unmarshal(stdout.Bytes(), &inspected); err != nil || inspected.Status != "expiring" || !inspected.Usable || inspected.KeyBits != 2048 {
		t.Fatal("inspection did not expose expiry status", err)
	}
	for _, private := range []string{"PRIVATE KEY", loaded.Secrets.ProtocolKey, loaded.Secrets.ProviderKey, loaded.Secrets.PhoneCodeKey, loaded.Secrets.ManagementSecretSHA256} {
		if strings.Contains(stdout.String()+stderr.String(), private) {
			t.Fatal("inspection exposed private material")
		}
	}
	if err := call("export-certificate", "--directory", directory); err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(stdout.Bytes())
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 || !bytes.Equal(block.Bytes, der) {
		t.Fatal("export contained more than the public certificate")
	}
	if err := call("activate", "--directory", directory, "--key-file", "saml-key.pem", "--certificate-file", "saml.pem", "--expected-sha256", inspected.SHA256, "--backup-file", "before.json"); err != nil {
		t.Fatal(err)
	}
	var activated struct {
		RestartRequired bool   `json:"restartRequired"`
		SHA256          string `json:"sha256"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &activated); err != nil || !activated.RestartRequired || activated.SHA256 != inspected.SHA256 {
		t.Fatal("activation omitted restart boundary", err)
	}
	for _, args := range [][]string{
		{"inspect"}, {"inspect", "--directory", directory, "extra"}, {"inspect", "--directory", directory, "--key-file", "saml-key.pem"},
		{"activate", "--directory", directory}, {"export-certificate", "--directory", directory, "--key-file", "../outside.pem", "--certificate-file", "saml.pem"},
		{"activate", "--directory", directory, "--key-file", "saml-key.pem", "--certificate-file", "saml.pem", "--expected-sha256", inspected.SHA256, "--backup-file", "../outside.json"},
	} {
		if err := call(args...); err == nil || stdout.Len() != 0 {
			t.Fatal("invalid command emitted successful output")
		}
	}
}
