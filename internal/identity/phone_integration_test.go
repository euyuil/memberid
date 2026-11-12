//go:build integration

package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingSender struct {
	mu      sync.Mutex
	codes   map[string]string
	calls   int
	failure error
}

func (sender *recordingSender) Send(_ context.Context, phone, code string) error {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	sender.codes[phone] = code
	sender.calls++
	return sender.failure
}
func (sender *recordingSender) code(phone string) string {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	return sender.codes[phone]
}

func phoneFixture(t *testing.T) (*PhoneVerifier, *recordingSender, string) {
	t.Helper()
	store := testStore(t)
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	sender := &recordingSender{codes: map[string]string{}}
	verifier, err := NewPhoneVerifier(store, key[:], sender)
	if err != nil {
		t.Fatal(err)
	}
	return verifier, sender, strings.Repeat("x", 43)
}

func TestPhoneVerificationIsBoundAndSingleUse(t *testing.T) {
	verifier, sender, binding := phoneFixture(t)
	challenge, err := verifier.Start(t.Context(), binding, "19900000001")
	if err != nil {
		t.Fatal(err)
	}
	code := sender.code("+8619900000001")
	if _, err := verifier.Verify(t.Context(), strings.Repeat("y", 43), challenge.ID, code); !errors.Is(err, ErrPhoneChallenge) {
		t.Fatal("accepted another browser transaction")
	}
	restarted, err := NewPhoneVerifier(verifier.store, verifier.key, sender)
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		verified Verification
		err      error
	}
	results := make(chan outcome, 12)
	for range 12 {
		go func() {
			value, err := restarted.Verify(t.Context(), binding, challenge.ID, code)
			results <- outcome{value, err}
		}()
	}
	successful := 0
	for range 12 {
		result := <-results
		if result.err == nil {
			successful++
			if result.verified.Factor.Type != "phone" || result.verified.Factor.Subject != "+8619900000001" || result.verified.Method != "sms" || result.verified.AuthenticatedAt.IsZero() {
				t.Fatal("wrong verification evidence")
			}
		} else if !errors.Is(result.err, ErrPhoneChallenge) {
			t.Fatal(result.err)
		}
	}
	if successful != 1 {
		t.Fatalf("successful replays=%d", successful)
	}
	var members, bindings int
	if err := verifier.store.pool.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM members),(SELECT count(*) FROM member_auth_factor_bindings)").Scan(&members, &bindings); err != nil || members != 0 || bindings != 0 {
		t.Fatal("phone verification inferred membership")
	}
}

func TestPhoneAttemptsExpiryAndReplacement(t *testing.T) {
	verifier, sender, binding := phoneFixture(t)
	now := time.Now().UTC()
	verifier.now = func() time.Time { return now }
	challenge, err := verifier.Start(t.Context(), binding, "19900000001")
	if err != nil {
		t.Fatal(err)
	}
	code := sender.code("+8619900000001")
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for range 5 {
		if _, err := verifier.Verify(t.Context(), binding, challenge.ID, wrong); !errors.Is(err, ErrPhoneChallenge) {
			t.Fatal("wrong code accepted")
		}
	}
	if _, err := verifier.Verify(t.Context(), binding, challenge.ID, code); !errors.Is(err, ErrPhoneChallenge) {
		t.Fatal("attempt limit was not persisted")
	}
	now = now.Add(61 * time.Second)
	next, err := verifier.Start(t.Context(), binding, "19900000001")
	if err != nil {
		t.Fatal(err)
	}
	nextCode := sender.code("+8619900000001")
	now = now.Add(61 * time.Second)
	latest, err := verifier.Start(t.Context(), binding, "19900000001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(t.Context(), binding, next.ID, nextCode); !errors.Is(err, ErrPhoneChallenge) {
		t.Fatal("superseded challenge accepted")
	}
	now = now.Add(5 * time.Minute)
	if _, err := verifier.Verify(t.Context(), binding, latest.ID, sender.code("+8619900000001")); !errors.Is(err, ErrPhoneChallenge) {
		t.Fatal("expired challenge accepted")
	}
}

func TestPhoneConcurrentRateLimitAndHourlyCap(t *testing.T) {
	verifier, sender, binding := phoneFixture(t)
	now := time.Now().UTC()
	verifier.now = func() time.Time { return now }
	failures := make(chan error, 10)
	for range 10 {
		go func() { _, err := verifier.Start(t.Context(), binding, "19900000001"); failures <- err }()
	}
	success := 0
	for range 10 {
		err := <-failures
		if err == nil {
			success++
		} else if !errors.Is(err, ErrRateLimited) {
			t.Fatal(err)
		}
	}
	if success != 1 || sender.calls != 1 {
		t.Fatal("concurrent requests bypassed send cooldown")
	}
	for range 5 {
		now = now.Add(61 * time.Second)
		if _, err := verifier.Start(t.Context(), binding, "19900000001"); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(61 * time.Second)
	if _, err := verifier.Start(t.Context(), binding, "19900000001"); !errors.Is(err, ErrRateLimited) {
		t.Fatal("hourly cap was bypassed")
	}
}

func TestFailedPhoneDeliveryCannotAuthenticate(t *testing.T) {
	verifier, sender, binding := phoneFixture(t)
	sender.failure = errors.New("private delivery failure")
	if _, err := verifier.Start(t.Context(), binding, "19900000001"); !errors.Is(err, ErrDeliveryUnavailable) {
		t.Fatal("delivery error was exposed or accepted")
	}
	var id string
	if err := verifier.store.pool.QueryRow(t.Context(), "SELECT id FROM phone_challenges").Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(t.Context(), binding, id, sender.code("+8619900000001")); !errors.Is(err, ErrPhoneChallenge) {
		t.Fatal("undelivered challenge accepted")
	}
	if _, err := verifier.Start(t.Context(), binding, "19900000001"); !errors.Is(err, ErrRateLimited) {
		t.Fatal("delivery failure removed cooldown")
	}
}
