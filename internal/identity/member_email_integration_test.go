//go:build integration

package identity

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestMemberEmailAuthorityConflictsAndAudit(t *testing.T) {
	store := testStore(t)
	org, member := organizationAndMember(t, store)
	other, foreign := organizationAndMember(t, store)
	admin, factor := administratorMember(t, store, org.ID, 81)
	platform, platformFactor := administratorMember(t, store, store.SystemOrganizationID(), 82)
	principal := administratorActor(t, store, admin, factor).Principal()
	platformPrincipal := administratorActor(t, store, platform, platformFactor).Principal()
	service := NewManagementService(store, nil, nil, time.Hour)
	input := MemberEmailInput{Address: "Member@EXAMPLE.TEST"}
	for _, caller := range []Principal{{}, OperatorPrincipal(), InstallationManagerPrincipal(), ManagementPrincipal(member.ID, "unknown"), {kind: accountPrincipal}} {
		if _, err := service.PutMemberEmail(t.Context(), caller, org.ID, member.ID, input); !errors.Is(err, ErrForbidden) {
			t.Fatal("unadmitted email update", err)
		}
	}
	if _, err := service.PutMemberEmail(t.Context(), principal, other.ID, foreign.ID, input); !errors.Is(err, ErrForbidden) {
		t.Fatal("foreign email update", err)
	}
	if _, err := service.PutMemberEmail(t.Context(), principal, org.ID, foreign.ID, input); !errors.Is(err, ErrNotFound) {
		t.Fatal("forged ownership", err)
	}
	current, err := service.PutMemberEmail(t.Context(), principal, org.ID, member.ID, input)
	if err != nil || current.Address != "Member@example.test" || current.Revision != 1 || current.Source != "administrator" || current.MailboxVerified || current.UpdatedBy != admin.ID || current.UpdatedAt == nil {
		t.Fatal("missing provenance", current, err)
	}
	detail, err := service.Member(t.Context(), principal, org.ID, member.ID)
	if err != nil || detail.Email.Address != current.Address {
		t.Fatal("management email read", err)
	}
	if _, err := service.Member(t.Context(), principal, other.ID, foreign.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal("foreign read", err)
	}
	if _, err := service.PutMemberEmail(t.Context(), platformPrincipal, other.ID, foreign.ID, input); err != nil {
		t.Fatal("cross-organization matching contacts must remain possible", err)
	}
	input.Address = "member@example.test"
	if _, err := service.PutMemberEmail(t.Context(), principal, org.ID, admin.ID, input); !errors.Is(err, ErrMemberEmailTaken) {
		t.Fatal("ambiguous active email", err)
	}
	input.Address = "changed@example.test"
	if _, err := service.PutMemberEmail(t.Context(), principal, org.ID, member.ID, input); !errors.Is(err, ErrConflict) {
		t.Fatal("stale write", err)
	}
	input.Revision = current.Revision
	current, err = service.PutMemberEmail(t.Context(), principal, org.ID, member.ID, input)
	if err != nil || current.Revision != 2 {
		t.Fatal(current, err)
	}
	events, err := store.ManagementEvents(t.Context(), org.ID, member.ID, 0)
	if err != nil || len(events) != 2 || events[0].Actor != admin.ID || events[0].Action != "member.email.update" {
		t.Fatal("email audit", events, err)
	}
	var before map[string]any
	var after MemberEmail
	if json.Unmarshal(events[0].Previous, &before) != nil || json.Unmarshal(events[0].Changes, &after) != nil || before["address"] != "Member@example.test" || after.Address != current.Address || after.MailboxVerified {
		t.Fatal("audit lost change provenance")
	}
	if _, err := store.pool.Exec(t.Context(), "ALTER TABLE management_events ADD CONSTRAINT synthetic_email_audit_failure CHECK (action <> 'member.email.update') NOT VALID"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PutMemberEmail(t.Context(), principal, org.ID, member.ID, MemberEmailInput{Address: "lost@example.test", Revision: 2}); err == nil {
		t.Fatal("email committed without audit")
	}
	unchanged, err := store.MemberEmail(t.Context(), OperatorPrincipal(), org.ID, member.ID)
	if err != nil || unchanged.Address != current.Address || unchanged.Revision != 2 {
		t.Fatal("failed audit changed email", unchanged, err)
	}
	if _, err := store.pool.Exec(t.Context(), "ALTER TABLE management_events DROP CONSTRAINT synthetic_email_audit_failure"); err != nil {
		t.Fatal(err)
	}
	current, err = service.PutMemberEmail(t.Context(), principal, org.ID, member.ID, MemberEmailInput{Revision: 2})
	if err != nil || current.Address != "" || current.Revision != 3 {
		t.Fatal("clear lost version", current, err)
	}
	if _, err := service.PutMemberEmail(t.Context(), principal, org.ID, member.ID, MemberEmailInput{Address: "stale@example.test"}); !errors.Is(err, ErrConflict) {
		t.Fatal("clearing allowed stale create", err)
	}
	if _, err := store.pool.Exec(t.Context(), "UPDATE oidc_grants SET revoked_at=clock_timestamp() WHERE id=$1", admin.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PutMemberEmail(t.Context(), principal, org.ID, member.ID, MemberEmailInput{Address: "denied@example.test", Revision: 3}); !errors.Is(err, ErrForbidden) {
		t.Fatal("revoked administrator changed email", err)
	}
}

func TestMemberEmailConcurrentChangesAndIssuanceLock(t *testing.T) {
	store := testStore(t)
	org, member := organizationAndMember(t, store)
	var group sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for _, address := range []string{"one@example.test", "two@example.test"} {
		group.Go(func() {
			_, err := store.PutMemberEmail(t.Context(), OperatorPrincipal(), org.ID, member.ID, MemberEmailInput{Address: address})
			errorsSeen <- err
		})
	}
	group.Wait()
	close(errorsSeen)
	success := 0
	for err := range errorsSeen {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("concurrent writes lost revision protection", success)
	}
	tx, err := store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), "SELECT id FROM members WHERE id=$1 FOR SHARE", member.ID); err != nil {
		t.Fatal(err)
	}
	before, err := SAMLMemberEmail(t.Context(), tx, org.ID, member.ID)
	if err != nil {
		t.Fatal(err)
	}
	changed := make(chan error, 1)
	go func() {
		_, err := store.PutMemberEmail(t.Context(), OperatorPrincipal(), org.ID, member.ID, MemberEmailInput{Address: "after@example.test", Revision: 1})
		changed <- err
	}()
	// Wait until PostgreSQL confirms the updater is waiting on the Member lock.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := store.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT id FROM members%')").Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("email updater did not reach issuance lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	during, err := SAMLMemberEmail(t.Context(), tx, org.ID, member.ID)
	if err != nil || during != before {
		t.Fatal("email changed during issuance", err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-changed; err != nil {
		t.Fatal(err)
	}
	after, err := store.MemberEmail(t.Context(), OperatorPrincipal(), org.ID, member.ID)
	if err != nil || after.Address != "after@example.test" {
		t.Fatal("update did not complete after issuance", err)
	}
}
