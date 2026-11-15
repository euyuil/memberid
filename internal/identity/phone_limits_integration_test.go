//go:build integration

package identity

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestPhoneSendQuotasAcrossNumbersAndRestart(t *testing.T) {
	for _, dimension := range []string{"transaction", "browser", "source", "client", "installation"} {
		t.Run(dimension, func(t *testing.T) {
			verifier, sender, binding := phoneFixture(t)
			limits := PhoneSendLimits{}
			source := testPhoneSource()
			next := PhoneSendSource{BrowserID: strings.Repeat("c", 43), ClientID: "other-web", Address: netip.MustParseAddr("192.0.2.2")}
			nextBinding := strings.Repeat("y", 43)
			switch dimension {
			case "transaction":
				limits.Transaction, nextBinding = 1, binding
			case "browser":
				limits.Browser, next.BrowserID = 1, source.BrowserID
			case "source":
				limits.Source, next.Address = 1, source.Address
			case "client":
				limits.Client, next.ClientID = 1, source.ClientID
			case "installation":
				limits.Installation = 1
			}
			verifier.limits, _ = limits.WithDefaults()
			now := time.Now().UTC()
			verifier.now = func() time.Time { return now }
			if _, err := verifier.Start(t.Context(), binding, "19900000001", source); err != nil {
				t.Fatal(err)
			}
			restarted, err := NewPhoneVerifier(verifier.store, verifier.key, sender, limits)
			if err != nil {
				t.Fatal(err)
			}
			restarted.now = func() time.Time { return now }
			// Consuming a code and ordinary cleanup must not refund the send.
			if _, err := verifier.store.pool.Exec(t.Context(), "UPDATE phone_challenges SET consumed_at=$1", now); err != nil {
				t.Fatal(err)
			}
			if err := verifier.store.CleanupPhoneChallenges(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.Start(t.Context(), nextBinding, "19900000002", next); !errors.Is(err, ErrRateLimited) || sender.calls != 1 {
				t.Fatal("rotating other dimensions or restarting bypassed quota", err, sender.calls)
			}
			now = now.Add(time.Hour + time.Second)
			if _, err := restarted.Start(t.Context(), nextBinding, "19900000002", next); err != nil || sender.calls != 2 {
				t.Fatal("rolling window did not release quota", err)
			}
		})
	}
}

func TestPhoneSendInstallationBudgetIsAtomicAcrossVerifiers(t *testing.T) {
	first, sender, _ := phoneFixture(t)
	first.limits.Installation = 3
	second, err := NewPhoneVerifier(first.store, first.key, sender, first.limits)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 18)
	for i := range 18 {
		go func() {
			verifier := first
			if i%2 == 0 {
				verifier = second
			}
			source := PhoneSendSource{BrowserID: fmt.Sprintf("%043d", i), ClientID: fmt.Sprintf("web-%d", i), Address: netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})}
			_, err := verifier.Start(t.Context(), fmt.Sprintf("%043d", i), fmt.Sprintf("199%08d", i), source)
			results <- err
		}()
	}
	admitted := 0
	for range 18 {
		if err := <-results; err == nil {
			admitted++
		} else if !errors.Is(err, ErrRateLimited) {
			t.Fatal(err)
		}
	}
	if admitted != 3 || sender.calls != 3 {
		t.Fatal("concurrent requests exceeded budget", admitted, sender.calls)
	}
}

func TestPhoneSendFailureConsumesBudget(t *testing.T) {
	verifier, sender, binding := phoneFixture(t)
	verifier.limits.Installation = 1
	sender.failure = errors.New("uncertain delivery")
	if _, err := verifier.Start(t.Context(), binding, "19900000001", testPhoneSource()); !errors.Is(err, ErrDeliveryUnavailable) {
		t.Fatal(err)
	}
	sender.failure = nil
	if _, err := verifier.Start(t.Context(), binding, "19900000002", testPhoneSource()); !errors.Is(err, ErrRateLimited) || sender.calls != 1 {
		t.Fatal("failed delivery refunded budget", err)
	}
}

func TestPhoneSendDeniedRequestPreservesChallenge(t *testing.T) {
	verifier, sender, binding := phoneFixture(t)
	verifier.limits.Browser = 1
	now := time.Now().UTC()
	verifier.now = func() time.Time { return now }
	challenge, err := verifier.Start(t.Context(), binding, "19900000001", testPhoneSource())
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(61 * time.Second)
	if _, err := verifier.Start(t.Context(), binding, "19900000001", testPhoneSource()); !errors.Is(err, ErrRateLimited) {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(t.Context(), binding, challenge.ID, sender.code("+8619900000001")); err != nil {
		t.Fatal("denied send invalidated an existing challenge", err)
	}
}

func TestPhoneSendSourceNetworkNormalization(t *testing.T) {
	for _, addresses := range [][3]string{
		{"192.0.2.1", "::ffff:192.0.2.1", "192.0.2.2"},
		{"2001:db8:1:2::1", "2001:db8:1:2::ffff", "2001:db8:1:3::1"},
	} {
		t.Run(addresses[0], func(t *testing.T) {
			verifier, sender, binding := phoneFixture(t)
			verifier.limits.Source = 1
			for i, address := range addresses {
				source := testPhoneSource()
				source.Address = netip.MustParseAddr(address)
				_, err := verifier.Start(t.Context(), binding, fmt.Sprintf("199%08d", i), source)
				if i == 1 && !errors.Is(err, ErrRateLimited) || i != 1 && err != nil {
					t.Fatal("incorrect source quota", err)
				}
			}
			if sender.calls != 2 {
				t.Fatal("wrong send count", sender.calls)
			}
		})
	}
}

func TestPhoneSendAccountClientBucketAndInvalidSource(t *testing.T) {
	verifier, sender, binding := phoneFixture(t)
	verifier.limits.Client = 1
	source := testPhoneSource()
	source.ClientID = ""
	if _, err := verifier.Start(t.Context(), binding, "19900000001", source); err != nil {
		t.Fatal(err)
	}
	source.BrowserID = strings.Repeat("c", 43)
	if _, err := verifier.Start(t.Context(), binding, "19900000002", source); !errors.Is(err, ErrRateLimited) {
		t.Fatal("clientless account pages bypassed shared quota", err)
	}
	source.ClientID = "account"
	if _, err := verifier.Start(t.Context(), binding, "19900000002", source); err != nil {
		t.Fatal("clientless bucket collided with a registered client", err)
	}
	for _, invalid := range []PhoneSendSource{{}, {BrowserID: source.BrowserID}, {Address: source.Address}} {
		if _, err := verifier.Start(t.Context(), binding, "19900000003", invalid); !errors.Is(err, ErrInvalid) {
			t.Fatal("accepted incomplete quota context", err)
		}
	}
	if sender.calls != 2 {
		t.Fatal("invalid source reached sender", sender.calls)
	}
}
