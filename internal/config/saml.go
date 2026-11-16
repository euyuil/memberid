package config

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"path/filepath"
	"time"
)

// SAML keeps signing trust separate from TLS and OIDC signing material.
type SAML struct {
	Enabled         bool   `json:"enabled"`
	SigningKeyFile  string `json:"signingKeyFile"`
	CertificateFile string `json:"certificateFile"`
}

type SAMLSigning struct {
	Key         *rsa.PrivateKey
	Certificate *x509.Certificate
}

func (signing *SAMLSigning) Validate(now time.Time) error {
	if err := signing.validateKeyPair(); err != nil {
		return err
	}
	if now.Before(signing.Certificate.NotBefore) || !now.Before(signing.Certificate.NotAfter) {
		return errors.New("SAML signing certificate is not currently usable")
	}
	return nil
}

func (signing *SAMLSigning) validateKeyPair() error {
	if signing == nil || signing.Key == nil || signing.Certificate == nil {
		return errors.New("SAML signing key and certificate are required")
	}
	certificate := signing.Certificate
	public, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || signing.Key.N.BitLen() < 2048 || !signing.Key.PublicKey.Equal(public) || signing.Key.Validate() != nil {
		return errors.New("SAML requires a matching RSA key and certificate of at least 2048 bits")
	}
	if certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("SAML signing certificate does not permit digital signatures")
	}
	return nil
}

func LoadSAMLSigning(directory string, settings *SAML) (*SAMLSigning, error) {
	result, err := readSAMLSigning(directory, settings)
	if err != nil || result == nil {
		return result, err
	}
	return result, result.Validate(time.Now())
}

func readSAMLSigning(directory string, settings *SAML) (*SAMLSigning, error) {
	if settings == nil || !settings.Enabled {
		return nil, nil
	}
	for _, name := range []string{settings.SigningKeyFile, settings.CertificateFile} {
		if name == "" || !filepath.IsLocal(name) {
			return nil, errors.New("SAML signing files must be relative to the protected installation directory")
		}
	}
	key, err := ReadSigningKey(filepath.Join(directory, settings.SigningKeyFile))
	if err != nil {
		return nil, errors.New("cannot load SAML signing key")
	}
	data, err := readKeyFile(filepath.Join(directory, settings.CertificateFile))
	if err != nil || len(data) > MaximumFileSize {
		return nil, errors.New("cannot load SAML signing certificate")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("SAML requires exactly one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid SAML signing certificate")
	}
	result := &SAMLSigning{Key: key, Certificate: certificate}
	return result, result.validateKeyPair()
}
