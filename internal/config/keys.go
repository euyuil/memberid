package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
)

func RandomSecret() string {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func SecretHash(secret string) string {
	digest := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(digest[:])
}

func KeyID(key *rsa.PublicKey) string {
	encoded, _ := x509.MarshalPKIXPublicKey(key)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:16])
}

func readKeyFile(file string) ([]byte, error) {
	handle, err := os.Open(file)
	if err != nil {
		return nil, errors.New("key file unavailable")
	}
	defer handle.Close()
	data, err := io.ReadAll(io.LimitReader(handle, MaximumFileSize+1))
	if err != nil || len(data) > MaximumFileSize {
		return nil, errors.New("key file is unreadable or too large")
	}
	return data, nil
}

func ReadSigningKey(file string) (*rsa.PrivateKey, error) {
	data, err := readKeyFile(file)
	if err != nil {
		return nil, err
	}
	block, remaining := pem.Decode(data)
	if block == nil || len(remaining) != 0 || len(block.Headers) != 0 {
		return nil, errors.New("expected one unencrypted RSA private key")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid private key")
		}
		key, _ = parsed.(*rsa.PrivateKey)
	case "RSA PRIVATE KEY":
		key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if key == nil || key.N.BitLen() < 2048 || key.Validate() != nil {
		return nil, errors.New("signing key must be valid RSA with at least 2048 bits")
	}
	return key, nil
}

func ReadPublicKeys(file string) (map[string]*rsa.PublicKey, error) {
	data, err := readKeyFile(file)
	if err != nil {
		return nil, err
	}
	result := map[string]*rsa.PublicKey{}
	for len(data) != 0 {
		block, remaining := pem.Decode(data)
		if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 {
			return nil, errors.New("invalid public key bundle")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid public key")
		}
		key, ok := parsed.(*rsa.PublicKey)
		if !ok || key.N.BitLen() < 2048 || key.E < 3 {
			return nil, errors.New("public keys must use RSA with at least 2048 bits")
		}
		id := KeyID(key)
		if result[id] != nil {
			return nil, errors.New("repeated public key")
		}
		result[id] = key
		data = remaining
	}
	if len(result) == 0 {
		return nil, errors.New("public key bundle is empty")
	}
	return result, nil
}
