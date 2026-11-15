package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSAMLSigningConfiguration(t *testing.T) {
	directory := t.TempDir()
	now := time.Now()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	settings := &SAML{Enabled: true, SigningKeyFile: "key.pem", CertificateFile: "cert.pem"}
	loaded, err := LoadSAMLSigning(directory, settings)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Validate(now.Add(2*time.Hour)) == nil || loaded.Validate(now.Add(-2*time.Hour)) == nil {
		t.Fatal("accepted an unusable certificate")
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Key = other
	if loaded.Validate(now) == nil {
		t.Fatal("accepted mismatched certificate")
	}
	for _, bad := range []*SAML{{Enabled: true}, {Enabled: true, SigningKeyFile: "../key.pem", CertificateFile: "cert.pem"}, {Enabled: true, SigningKeyFile: "key.pem", CertificateFile: "absent.pem"}} {
		if _, err := LoadSAMLSigning(directory, bad); err == nil {
			t.Fatal("accepted incomplete signing configuration")
		}
	}
	if material, err := LoadSAMLSigning(directory, &SAML{}); err != nil || material != nil {
		t.Fatal("disabled SAML required signing material")
	}
}
