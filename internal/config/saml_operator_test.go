package config

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
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
)

func signingFixture(t *testing.T) (string, *Loaded) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "installation")
	if err := Initialize(directory, "https://login.example.test", false); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	loaded.SAML = writeSigningFixture(t, directory, "original", nil, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour), x509.KeyUsageDigitalSignature)
	data, _ := json.Marshal(loaded.Installation)
	if err := os.WriteFile(filepath.Join(directory, "memberid.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err = Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	return directory, loaded
}

func writeSigningFixture(t *testing.T, directory, name string, key *rsa.PrivateKey, before, after time.Time, usage x509.KeyUsage) *SAML {
	t.Helper()
	var err error
	if key == nil {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: before, NotAfter: after, KeyUsage: usage}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	settings := &SAML{Enabled: true, SigningKeyFile: name + "-key.pem", CertificateFile: name + ".pem"}
	for file, block := range map[string]*pem.Block{settings.SigningKeyFile: {Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}, settings.CertificateFile: {Type: "CERTIFICATE", Bytes: der}} {
		if err := os.WriteFile(filepath.Join(directory, file), pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return settings
}

func TestSAMLSigningActivationAndRecovery(t *testing.T) {
	directory, original := signingFixture(t)
	next := writeSigningFixture(t, directory, "next", nil, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), x509.KeyUsageDigitalSignature)
	before := map[string][]byte{}
	entries, _ := os.ReadDir(directory)
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		before[entry.Name()] = data
	}
	current, err := InspectSAMLSigning(directory, "", "")
	if err != nil || current.Status != "valid" || !current.Usable {
		t.Fatal("current signing inspection", err)
	}
	preview, err := InspectSAMLSigning(directory, next.SigningKeyFile, next.CertificateFile)
	if err != nil || preview.SHA256 == current.SHA256 {
		t.Fatal("candidate inspection", err)
	}
	active, err := ActivateSAMLSigning(directory, next.SigningKeyFile, next.CertificateFile, current.SHA256, "before-rotation.json")
	if err != nil || active.SHA256 != preview.SHA256 {
		t.Fatal("activation", err)
	}
	backup, err := os.ReadFile(filepath.Join(directory, "before-rotation.json"))
	if err != nil || !bytes.Equal(backup, before["memberid.json"]) {
		t.Fatal("backup did not preserve original configuration", err)
	}
	loaded, err := Load(directory)
	if err != nil || loaded.SAMLSigning.Certificate.Equal(original.SAMLSigning.Certificate) {
		t.Fatal("new signer not loaded", err)
	}
	loaded.SAML = original.SAML
	if !reflect.DeepEqual(loaded.Installation, original.Installation) {
		t.Fatal("unrelated installation configuration changed")
	}
	for file, data := range before {
		if file == "memberid.json" {
			continue
		}
		actual, err := os.ReadFile(filepath.Join(directory, file))
		if err != nil || !bytes.Equal(actual, data) {
			t.Fatal("changed protected material", file, err)
		}
	}
	if runtime.GOOS != "windows" {
		for _, file := range []string{"memberid.json", "before-rotation.json"} {
			info, err := os.Stat(filepath.Join(directory, file))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("unprotected configuration", err)
			}
		}
	}
	restored, err := ActivateSAMLSigning(directory, original.SAML.SigningKeyFile, original.SAML.CertificateFile, active.SHA256, "before-recovery.json")
	if err != nil || restored.SHA256 != current.SHA256 {
		t.Fatal("rollback did not restore signing identity", err)
	}
	if leftovers, err := filepath.Glob(filepath.Join(directory, ".saml-signing*")); err != nil || len(leftovers) != 0 {
		t.Fatal("retained lock or temporary file", err)
	}
}

func TestSAMLSigningInspectionAndInvalidActivation(t *testing.T) {
	directory, original := signingFixture(t)
	current, _ := InspectSAMLSigning(directory, "", "")
	configuration, _ := os.ReadFile(filepath.Join(directory, "memberid.json"))
	now := time.Now()
	for _, mode := range []string{"expired", "future", "expiring", "key usage", "OIDC key", "mismatch", "bundle", "weak key", "stale", "existing backup", "locked"} {
		t.Run(mode, func(t *testing.T) {
			before, after, usage := now.Add(-time.Hour), now.Add(60*24*time.Hour), x509.KeyUsageDigitalSignature
			key := original.SAMLSigning.Key
			switch mode {
			case "expired":
				after = now.Add(-time.Minute)
			case "future":
				before = now.Add(time.Hour)
			case "expiring":
				after = now.Add(24 * time.Hour)
			case "key usage":
				usage = x509.KeyUsageKeyEncipherment
			case "OIDC key":
				key = original.SigningKey
			case "weak key":
				var err error
				key, err = rsa.GenerateKey(rand.Reader, 1024)
				if err != nil {
					t.Fatal(err)
				}
			}
			candidate := writeSigningFixture(t, directory, "candidate", key, before, after, usage)
			if mode == "mismatch" {
				candidate.SigningKeyFile = original.SigningKeyFile
			}
			if mode == "bundle" {
				data, _ := os.ReadFile(filepath.Join(directory, candidate.CertificateFile))
				if err := os.WriteFile(filepath.Join(directory, candidate.CertificateFile), append(data, data...), 0600); err != nil {
					t.Fatal(err)
				}
			}
			report, err := InspectSAMLSigning(directory, candidate.SigningKeyFile, candidate.CertificateFile)
			invalid := mode == "key usage" || mode == "OIDC key" || mode == "mismatch" || mode == "bundle" || mode == "weak key"
			if (err != nil) != invalid {
				t.Fatal("unexpected inspection result", err)
			}
			if invalid {
				if data, err := ExportSAMLSigningCertificate(directory, candidate.SigningKeyFile, candidate.CertificateFile); err == nil || len(data) != 0 {
					t.Fatal("exported invalid material")
				}
			}
			if mode == "expired" || mode == "future" || mode == "expiring" {
				want := mode
				if mode == "future" {
					want = "notYetValid"
				}
				if report.Status != want || report.Usable != (mode == "expiring") {
					t.Fatal("incorrect validity status", report.Status)
				}
				if mode == "expiring" {
					return
				}
			}
			expected := current.SHA256
			if mode == "stale" {
				expected = SecretHash("another signing certificate")
			}
			backup := "rejected-backup.json"
			if mode == "existing backup" {
				if err := WriteExclusive(filepath.Join(directory, backup), []byte("preserve")); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(filepath.Join(directory, backup))
			}
			if mode == "locked" {
				if err := WriteExclusive(filepath.Join(directory, ".saml-signing.lock"), []byte("another operator")); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(filepath.Join(directory, ".saml-signing.lock"))
			}
			if _, err := ActivateSAMLSigning(directory, candidate.SigningKeyFile, candidate.CertificateFile, expected, backup); err == nil {
				t.Fatal("unsafe activation succeeded")
			}
			actual, _ := os.ReadFile(filepath.Join(directory, "memberid.json"))
			if !bytes.Equal(actual, configuration) {
				t.Fatal("failed activation changed configuration")
			}
			if mode == "existing backup" {
				data, _ := os.ReadFile(filepath.Join(directory, backup))
				if string(data) != "preserve" {
					t.Fatal("replaced backup")
				}
			} else if _, err := os.Stat(filepath.Join(directory, backup)); !os.IsNotExist(err) {
				t.Fatal("failed preflight created backup", err)
			}
			if mode == "locked" {
				data, _ := os.ReadFile(filepath.Join(directory, ".saml-signing.lock"))
				if string(data) != "another operator" {
					t.Fatal("removed competing lock")
				}
			}
		})
	}
}

func TestExpiredSAMLSigningCanBeInspectedAndReplaced(t *testing.T) {
	directory, original := signingFixture(t)
	old := writeSigningFixture(t, directory, "original", original.SAMLSigning.Key, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), x509.KeyUsageDigitalSignature)
	if _, err := Load(directory); err == nil {
		t.Fatal("server accepted expired certificate")
	}
	current, err := InspectSAMLSigning(directory, "", "")
	if err != nil || current.Status != "expired" || current.Usable {
		t.Fatal("expired inspection", err)
	}
	public, err := ExportSAMLSigningCertificate(directory, "", "")
	block, rest := pem.Decode(public)
	if err != nil || block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("public export", err)
	}
	fresh := writeSigningFixture(t, directory, "fresh", nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), x509.KeyUsageDigitalSignature)
	if _, err := ActivateSAMLSigning(directory, fresh.SigningKeyFile, fresh.CertificateFile, current.SHA256, "expired-backup.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(directory); err != nil {
		t.Fatal("replacement failed", err)
	}
	if old.SigningKeyFile != original.SAML.SigningKeyFile {
		t.Fatal("fixture did not replace active expired certificate")
	}
}

func TestConcurrentSAMLActivationDoesNotOverwriteWinner(t *testing.T) {
	directory, _ := signingFixture(t)
	current, _ := InspectSAMLSigning(directory, "", "")
	candidate := writeSigningFixture(t, directory, "next", nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), x509.KeyUsageDigitalSignature)
	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for _, backup := range []string{"one.json", "two.json"} {
		group.Go(func() {
			<-start
			_, err := ActivateSAMLSigning(directory, candidate.SigningKeyFile, candidate.CertificateFile, current.SHA256, backup)
			results <- err
		})
	}
	close(start)
	group.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("expected one activation, got %d", succeeded)
	}
}
