//go:build integration

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/testdb"
)

func TestSAMLOnlyStartupAndOperatorCLI(t *testing.T) {
	database := testdb.Create(t)
	if err := identity.Initialize(t.Context(), database); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MEMBERID_DATABASE_URL", database)
	t.Setenv("MEMBERID_PHONE_ENABLED", "false")
	t.Setenv("MEMBERID_DINGTALK_ENABLED", "true")
	t.Setenv("MEMBERID_FEISHU_ENABLED", "false")
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
		if err := os.WriteFile(filepath.Join(directory, name), pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	loaded.Installation.SAML = &config.SAML{Enabled: true, SigningKeyFile: "saml-key.pem", CertificateFile: "saml.pem"}
	write := func(name string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("memberid.json", loaded.Installation)
	if _, closeStore, err := authenticationHandler(t.Context(), directory); err == nil {
		closeStore()
		t.Fatal("started SAML-only without an active SP")
	}
	store, err := identity.Open(t.Context(), database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	organization, err := store.CreateOrganization(t.Context(), identity.OperatorPrincipal(), "", "Example")
	if err != nil {
		t.Fatal(err)
	}
	sp := identity.SAMLServiceProvider{EntityID: "https://sp.example.test/metadata", OrganizationID: organization.ID, ACSURL: "https://sp.example.test/acs", Enabled: true, AllowUnsignedRequests: true}
	write("sp.json", sp)
	var created bytes.Buffer
	if err := run(t.Context(), []string{"saml", "sp", "apply", "--directory", directory, "--file", filepath.Join(directory, "sp.json")}, &created, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(created.Bytes(), &sp); err != nil {
		t.Fatal(err)
	}
	handler, closeStore, err := authenticationHandler(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer closeStore()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "https://login.example.test/saml/metadata", nil))
	if response.Code != 200 {
		t.Fatal("SAML-only metadata unavailable")
	}
	if err := run(t.Context(), []string{"saml", "sp", "disable", "--directory", directory, "--id", sp.ID, "--revision", "1"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := run(t.Context(), []string{"saml", "sp", "retire", "--directory", directory, "--id", sp.ID, "--revision", "1"}, io.Discard, io.Discard); err == nil {
		t.Fatal("CLI accepted stale revision")
	}
}
