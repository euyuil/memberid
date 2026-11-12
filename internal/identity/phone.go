package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrPhoneChallenge      = errors.New("invalid or expired phone challenge")
	ErrRateLimited         = errors.New("phone verification rate limit reached")
	ErrDeliveryUnavailable = errors.New("phone delivery unavailable")
)

type SMSSender interface {
	Send(context.Context, string, string) error
}

// Verification is server-local evidence. It is neither a token nor Member authorization.
type Verification struct {
	Factor          Factor    `json:"factor"`
	AuthenticatedAt time.Time `json:"authenticatedAt"`
	Method          string    `json:"method"`
}

type PhoneChallenge struct {
	ID         string
	ExpiresAt  time.Time
	RetryAfter time.Duration
}

type PhoneVerifier struct {
	store  *Store
	key    []byte
	sender SMSSender
	now    func() time.Time
}

func NewPhoneVerifier(store *Store, key []byte, sender SMSSender) (*PhoneVerifier, error) {
	if store == nil || len(key) != 32 || sender == nil {
		return nil, ErrInvalid
	}
	return &PhoneVerifier{store: store, key: append([]byte(nil), key...), sender: sender, now: time.Now}, nil
}

func NormalizePhone(number string) (string, error) {
	value := strings.TrimPrefix(number, "+86")
	if len(value) != 11 || value[0] != '1' || value[1] < '3' || value[1] > '9' {
		return "", ErrInvalid
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return "", ErrInvalid
		}
	}
	return "+86" + value, nil
}

func (verifier *PhoneVerifier) codeMAC(id, phone, binding, code string) []byte {
	mac := hmac.New(sha256.New, verifier.key)
	_, _ = mac.Write([]byte(id + "\x00" + phone + "\x00" + binding + "\x00" + code))
	return mac.Sum(nil)
}

func (verifier *PhoneVerifier) Start(ctx context.Context, binding, number string) (PhoneChallenge, error) {
	phone, err := NormalizePhone(number)
	if err != nil || !validText(binding, 256) || len(binding) < 32 {
		return PhoneChallenge{}, ErrInvalid
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return PhoneChallenge{}, err
	}
	id := base64.RawURLEncoding.EncodeToString(entropy[:])
	value, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return PhoneChallenge{}, err
	}
	code := fmt.Sprintf("%06d", value.Int64())
	now := verifier.now().UTC()
	challenge := PhoneChallenge{ID: id, ExpiresAt: now.Add(5 * time.Minute), RetryAfter: time.Minute}
	bindingHash := sha256.Sum256([]byte(binding))
	err = pgx.BeginFunc(ctx, verifier.store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "phone:"+phone); err != nil {
			return err
		}
		var count int
		var recent bool
		if err := tx.QueryRow(ctx, "SELECT count(*),COALESCE(bool_or(created_at>$2::timestamptz-interval '60 seconds'),false) FROM phone_challenges WHERE phone_number=$1 AND created_at>$2::timestamptz-interval '1 hour'", phone, now).Scan(&count, &recent); err != nil {
			return err
		}
		if recent || count >= 6 {
			return ErrRateLimited
		}
		if _, err := tx.Exec(ctx, "UPDATE phone_challenges SET consumed_at=$2 WHERE phone_number=$1 AND consumed_at IS NULL", phone, now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO phone_challenges(id,phone_number,binding_hash,code_mac,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6)", id, phone, bindingHash[:], verifier.codeMAC(id, phone, binding, code), now, challenge.ExpiresAt)
		return err
	})
	if err != nil {
		return PhoneChallenge{}, err
	}
	if err := verifier.sender.Send(ctx, phone, code); err != nil {
		return PhoneChallenge{}, ErrDeliveryUnavailable
	}
	result, err := verifier.store.pool.Exec(ctx, "UPDATE phone_challenges SET ready=true WHERE id=$1 AND consumed_at IS NULL AND expires_at>$2", id, verifier.now())
	if err != nil {
		return PhoneChallenge{}, err
	}
	if result.RowsAffected() != 1 {
		return PhoneChallenge{}, ErrDeliveryUnavailable
	}
	return challenge, nil
}

func (verifier *PhoneVerifier) Verify(ctx context.Context, binding, id, code string) (Verification, error) {
	if len(id) != 43 || len(code) != 6 || !validText(binding, 256) || len(binding) < 32 {
		return Verification{}, ErrPhoneChallenge
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return Verification{}, ErrPhoneChallenge
		}
	}
	now := verifier.now().UTC()
	bindingHash := sha256.Sum256([]byte(binding))
	denied := false
	var verified Verification
	err := pgx.BeginFunc(ctx, verifier.store.pool, func(tx pgx.Tx) error {
		var phone string
		var expected []byte
		err := tx.QueryRow(ctx, "SELECT phone_number,code_mac FROM phone_challenges WHERE id=$1 AND binding_hash=$2 AND ready AND consumed_at IS NULL AND expires_at>$3 AND attempts<5 FOR UPDATE", id, bindingHash[:], now).Scan(&phone, &expected)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPhoneChallenge
		}
		if err != nil {
			return err
		}
		if !hmac.Equal(expected, verifier.codeMAC(id, phone, binding, code)) {
			denied = true
			_, err := tx.Exec(ctx, "UPDATE phone_challenges SET attempts=attempts+1 WHERE id=$1", id)
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE phone_challenges SET consumed_at=$2 WHERE id=$1", id, now); err != nil {
			return err
		}
		factor, err := ensureFactor(ctx, tx, "phone", "phone:e164", phone)
		if err != nil {
			return err
		}
		verified = Verification{Factor: factor, AuthenticatedAt: now.Truncate(time.Second), Method: "sms"}
		return nil
	})
	if denied {
		return Verification{}, ErrPhoneChallenge
	}
	if err != nil {
		return Verification{}, err
	}
	return verified, nil
}

func (store *Store) CleanupPhoneChallenges(ctx context.Context) error {
	_, err := store.pool.Exec(ctx, "DELETE FROM phone_challenges WHERE expires_at<clock_timestamp()-interval '1 hour'")
	return err
}
