package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// SAMLSigningInspection describes files on disk, not a running process's signer.
type SAMLSigningInspection struct {
	SHA256           string    `json:"sha256"`
	NotBefore        time.Time `json:"notBefore"`
	NotAfter         time.Time `json:"notAfter"`
	Status           string    `json:"status"`
	Usable           bool      `json:"usable"`
	ExpiresInSeconds int64     `json:"expiresInSeconds"`
	KeyBits          int       `json:"keyBits"`
	SigningKeyFile   string    `json:"signingKeyFile"`
	CertificateFile  string    `json:"certificateFile"`
}

func signingInspection(loaded *Loaded, now time.Time) SAMLSigningInspection {
	cert := loaded.SAMLSigning.Certificate
	digest := sha256.Sum256(cert.Raw)
	result := SAMLSigningInspection{
		SHA256: hex.EncodeToString(digest[:]), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		Status: "valid", Usable: true, ExpiresInSeconds: int64(cert.NotAfter.Sub(now).Seconds()),
		KeyBits:        loaded.SAMLSigning.Key.N.BitLen(),
		SigningKeyFile: loaded.SAML.SigningKeyFile, CertificateFile: loaded.SAML.CertificateFile,
	}
	switch {
	case now.Before(cert.NotBefore):
		result.Status, result.Usable = "notYetValid", false
	case !now.Before(cert.NotAfter):
		result.Status, result.Usable = "expired", false
	case cert.NotAfter.Sub(now) <= 30*24*time.Hour:
		result.Status = "expiring"
	}
	return result
}

func inspectSAMLSigning(directory, keyFile, certificateFile string) (*Loaded, error) {
	var candidate *SAML
	if keyFile != "" || certificateFile != "" {
		if keyFile == "" || certificateFile == "" {
			return nil, errors.New("candidate signing key and certificate files are both required")
		}
		candidate = &SAML{Enabled: true, SigningKeyFile: keyFile, CertificateFile: certificateFile}
	}
	loaded, err := load(directory, candidate, true)
	if err != nil {
		return nil, err
	}
	if loaded.SAMLSigning == nil {
		return nil, errors.New("SAML signing is not enabled")
	}
	return loaded, nil
}

func InspectSAMLSigning(directory, keyFile, certificateFile string) (SAMLSigningInspection, error) {
	loaded, err := inspectSAMLSigning(directory, keyFile, certificateFile)
	if err != nil {
		return SAMLSigningInspection{}, err
	}
	return signingInspection(loaded, time.Now()), nil
}

// ExportSAMLSigningCertificate emits only the validated public certificate.
// Expired and future certificates can be inspected/exported, never activated.
func ExportSAMLSigningCertificate(directory, keyFile, certificateFile string) ([]byte, error) {
	loaded, err := inspectSAMLSigning(directory, keyFile, certificateFile)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: loaded.SAMLSigning.Certificate.Raw}), nil
}

// ActivateSAMLSigning changes only the two SAML file references. The caller
// provisions immutable candidate files and coordinates SP trust and restarts.
func ActivateSAMLSigning(directory, keyFile, certificateFile, expectedSHA256, backupFile string) (SAMLSigningInspection, error) {
	var result SAMLSigningInspection
	if directory == "" || keyFile == "" || certificateFile == "" || !validHash(expectedSHA256) || backupFile == "" || !filepath.IsLocal(backupFile) {
		return result, errors.New("activation requires candidate files, the expected current SHA-256, and a new local backup file")
	}
	lockName := filepath.Join(directory, ".saml-signing.lock")
	lock, err := os.OpenFile(lockName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return result, errors.New("SAML signing configuration is locked or unavailable")
	}
	defer os.Remove(lockName)
	if err := lock.Close(); err != nil {
		return result, err
	}
	configurationFile := filepath.Join(directory, "memberid.json")
	original, err := readKeyFile(configurationFile)
	if err != nil {
		return result, err
	}
	current, err := inspectSAMLSigning(directory, "", "")
	if err != nil {
		return result, err
	}
	if signingInspection(current, time.Now()).SHA256 != expectedSHA256 {
		return result, errors.New("SAML signing certificate changed; inspect before retrying")
	}
	candidate, err := inspectSAMLSigning(directory, keyFile, certificateFile)
	if err != nil {
		return result, err
	}
	if err := candidate.SAMLSigning.Validate(time.Now()); err != nil {
		return result, err
	}
	data, err := json.MarshalIndent(candidate.Installation, "", "  ")
	if err != nil {
		return result, err
	}
	temporary, err := os.CreateTemp(directory, ".saml-signing-*.tmp")
	if err != nil {
		return result, err
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	if err := temporary.Chmod(0600); err != nil {
		return result, err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		return result, err
	}
	if err := temporary.Sync(); err != nil {
		return result, err
	}
	if err := temporary.Close(); err != nil {
		return result, err
	}
	latest, err := readKeyFile(configurationFile)
	if err != nil || !bytes.Equal(original, latest) {
		return result, errors.New("installation configuration changed; inspect before retrying")
	}
	// Keep a byte-for-byte recovery copy, refusing an existing backup. Neither
	// key file is modified or deleted, including when replacement fails.
	if err := WriteExclusive(filepath.Join(directory, backupFile), original); err != nil {
		return result, errors.New("cannot create the new SAML configuration backup")
	}
	if err := os.Rename(temporary.Name(), configurationFile); err != nil {
		return result, errors.New("cannot replace SAML configuration; inspect before retrying")
	}
	return signingInspection(candidate, time.Now()), nil
}
