//go:build integration

package oidcprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/identity"
)

func TestPhoneLoginSendReservation(t *testing.T) {
	for _, mode := range []string{"concurrent send", "cancel", "delivery failure"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			page, _ := f.loginPage("example-web", "openid")
			key, _ := base64.StdEncoding.DecodeString(f.service.configuration.Secrets.PhoneCodeKey)
			calls := 0
			verifier, err := identity.NewPhoneVerifier(f.store, key, accountPhoneSender(func(ctx context.Context, phone, code string) error {
				calls++
				switch mode {
				case "concurrent send":
					result := f.submit(page.body, "send", url.Values{"phone": {"19900000002"}})
					f.status(result, 200)
					if !strings.Contains(result.body, "Cancel the current verification") {
						t.Fatal("second send admitted")
					}
				case "cancel":
					f.status(f.submit(page.body, "cancel", nil), 200)
				case "delivery failure":
					return errors.New("private synthetic delivery failure")
				}
				return f.sender.Send(ctx, phone, code)
			}), identity.PhoneSendLimits{})
			if err != nil {
				t.Fatal(err)
			}
			f.service.phone = verifier
			result := f.submit(page.body, "send", url.Values{"phone": {"19900000001"}})
			if mode == "cancel" {
				f.status(result, 400)
			} else {
				f.status(result, 200)
			}
			if calls != 1 || strings.Contains(result.body, "private synthetic") {
				t.Fatal("unexpected delivery", calls)
			}
			if mode == "delivery failure" {
				f.status(f.submit(page.body, "send", url.Values{"phone": {"19900000002"}}), 200)
				if calls != 1 {
					t.Fatal("failed delivery was retried without cancellation")
				}
			}
			if mode != "concurrent send" {
				result = f.submit(page.body, "verify", url.Values{"code": {f.sender.latest()}})
				if result.header.Get("Set-Cookie") != "" {
					t.Fatal("canceled or failed send created session")
				}
			}
		})
	}
}

func TestPhoneLoginRollback(t *testing.T) {
	for _, table := range []string{"oidc_sessions", "oidc_authorization_requests"} {
		t.Run(table, func(t *testing.T) {
			f := newFixture(t)
			page, _ := f.loginPage("registration", "openid registration_identity")
			sent := f.submit(page.body, "send", url.Values{"phone": {"19900000003"}})
			f.status(sent, 200)
			// This constraint exists only in the fixture's isolated database.
			if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE "+table+" ADD CONSTRAINT fail_login CHECK (false) NOT VALID"); err != nil {
				t.Fatal(err)
			}
			result := f.submit(sent.body, "verify", url.Values{"code": {f.sender.latest()}})
			f.status(result, 400)
			if result.header.Get("Set-Cookie") != "" {
				t.Fatal("failed commit issued cookie")
			}
			var sessions, factors, consumed int
			if err := f.store.Database().QueryRow(t.Context(), "SELECT (SELECT count(*) FROM oidc_sessions),(SELECT count(*) FROM authentication_factors WHERE subject='+8619900000003'),(SELECT count(*) FROM phone_challenges WHERE consumed_at IS NOT NULL)").Scan(&sessions, &factors, &consumed); err != nil || sessions != 0 || factors != 0 || consumed != 0 {
				t.Fatal("partial login committed", sessions, factors, consumed, err)
			}
			if _, err := f.store.Database().Exec(t.Context(), "ALTER TABLE "+table+" DROP CONSTRAINT fail_login"); err != nil {
				t.Fatal(err)
			}
			result = f.submit(sent.body, "verify", url.Values{"code": {f.sender.latest()}})
			f.status(result, 200)
			if !strings.Contains(result.body, "Phone verified") || result.header.Get("Set-Cookie") == "" {
				t.Fatal("rolled-back challenge could not complete")
			}
		})
	}
}

func TestPhoneLoginCancellationWinsBeforeCommit(t *testing.T) {
	f := newFixture(t)
	page, _ := f.loginPage("example-web", "openid")
	sent := f.submit(page.body, "send", url.Values{"phone": {"19900000001"}})
	f.status(sent, 200)
	tx, err := f.store.Database().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), "SELECT id FROM phone_challenges FOR UPDATE"); err != nil {
		t.Fatal(err)
	}
	results := make(chan reply, 1)
	code := f.sender.latest()
	go func() { results <- f.submit(sent.body, "verify", url.Values{"code": {code}}) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		err := f.store.Database().QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT phone_number,code_mac%')").Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("verification did not reach the challenge lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.status(f.submit(sent.body, "cancel", nil), 200)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	result := <-results
	f.status(result, 400)
	if result.header.Get("Set-Cookie") != "" {
		t.Fatal("canceled login issued cookie")
	}
	var sessions, consumed int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT (SELECT count(*) FROM oidc_sessions),(SELECT count(*) FROM phone_challenges WHERE consumed_at IS NOT NULL)").Scan(&sessions, &consumed); err != nil || sessions != 0 || consumed != 0 {
		t.Fatal("canceled login committed", err)
	}
}

func TestPhoneLoginConcurrentVerification(t *testing.T) {
	f := newFixture(t)
	page, _ := f.loginPage("example-web", "openid")
	sent := f.submit(page.body, "send", url.Values{"phone": {"19900000001"}})
	f.status(sent, 200)
	code := f.sender.latest()
	var group sync.WaitGroup
	results := make(chan reply, 2)
	for range 2 {
		group.Go(func() { results <- f.submit(sent.body, "verify", url.Values{"code": {code}}) })
	}
	group.Wait()
	close(results)
	cookies := 0
	for result := range results {
		if result.header.Get("Set-Cookie") != "" {
			cookies++
		}
	}
	var sessions int
	if err := f.store.Database().QueryRow(t.Context(), "SELECT count(*) FROM oidc_sessions").Scan(&sessions); err != nil || sessions != 1 || cookies != 1 {
		t.Fatal("duplicate login sessions", sessions, cookies, err)
	}
}
