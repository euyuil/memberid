package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"time"
)

type Kind string

const (
	OrganizationKind Kind = "org"
	MemberKind       Kind = "mbr"
	FactorKind       Kind = "af"
	idAlphabet            = "0123456789bcdfghjkmnpqrstvwxz"
	idWidth               = 27
)

var ErrInvalid = errors.New("invalid identity input")

func NewID(kind Kind) (string, error) {
	if !knownKind(kind) {
		return "", ErrInvalid
	}
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	stamp := uint64(time.Now().UnixMilli())
	for index := 5; index >= 0; index-- {
		value[index] = byte(stamp)
		stamp >>= 8
	}
	value[6] = value[6]&0x0f | 0x70
	value[8] = value[8]&0x3f | 0x80
	number, base, remainder := new(big.Int).SetBytes(value[:]), big.NewInt(int64(len(idAlphabet))), new(big.Int)
	var suffix [idWidth]byte
	for index := len(suffix) - 1; index >= 0; index-- {
		number.QuoRem(number, base, remainder)
		suffix[index] = idAlphabet[remainder.Int64()]
	}
	return string(kind) + "_" + string(suffix[:]), nil
}

func ValidID(id string, kind Kind) bool {
	prefix, suffix, ok := strings.Cut(id, "_")
	if !ok || !knownKind(kind) || prefix != string(kind) || len(suffix) != idWidth {
		return false
	}
	number, base := new(big.Int), big.NewInt(int64(len(idAlphabet)))
	for index := range len(suffix) {
		digit := strings.IndexByte(idAlphabet, suffix[index])
		if digit < 0 {
			return false
		}
		number.Mul(number, base).Add(number, big.NewInt(int64(digit)))
	}
	if number.BitLen() > 128 {
		return false
	}
	var value [16]byte
	number.FillBytes(value[:])
	return value[6]>>4 == 7 && value[8]>>6 == 2
}

func knownKind(kind Kind) bool {
	return kind == OrganizationKind || kind == MemberKind || kind == FactorKind
}

// ValidUUID validates the canonical textual shape used by opaque binding and protocol identifiers.
func ValidUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil && len(decoded) == 16
}
