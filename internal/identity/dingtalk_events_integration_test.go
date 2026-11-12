//go:build integration

package identity

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/dingtalk"
)

func directoryEvent(app DingTalkApplication, id, kind string, born int64) dingtalk.DirectoryEvent {
	return dingtalk.DirectoryEvent{ID: id, CorpID: app.CorpID, Type: kind, BornTime: born, UserIDs: []string{"example-employee"}}
}

func TestDirectoryEventsPersistBeforeSuccessAndPreserveBlocks(t *testing.T) {
	store, apps, directory, _, app, member := reconciliationFixture(t)
	if _, err := store.SetManualBlock(t.Context(), app.OrganizationID, member.ID, true); err != nil {
		t.Fatal(err)
	}
	event := directoryEvent(app, "leave", "user_leave_org", time.Now().UnixMilli())
	event.UserIDs = []string{"example-employee", "unadmitted-employee", "example-employee"}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if err := directory.acceptDirectoryEvent(t.Context(), app, event); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	var receipts int
	var revision int64
	var blocked bool
	if err := store.pool.QueryRow(t.Context(), "SELECT count(*) FROM dingtalk_events").Scan(&receipts); err != nil || receipts != 1 {
		t.Fatal("event receipt not idempotent", err)
	}
	if err := store.pool.QueryRow(t.Context(), "SELECT external_departure,eligibility_revision FROM members WHERE id=$1", member.ID).Scan(&blocked, &revision); err != nil || !blocked || revision != 2 {
		t.Fatal("departure was not atomic or was repeated", revision, err)
	}
	current, err := store.Member(t.Context(), app.OrganizationID, member.ID)
	if err != nil || len(current.BlockSources) != 2 {
		t.Fatal("event erased manual policy", err)
	}
	// A new worker sees the durable receipt and must not apply the leave again.
	restarted, _ := NewDingTalkDirectory(apps, directory.provider)
	event.UserIDs = []string{"unadmitted-employee", "example-employee"}
	if err := restarted.acceptDirectoryEvent(t.Context(), app, event); err != nil {
		t.Fatal(err)
	}
	event.UserIDs = append(event.UserIDs, "unknown-employee")
	if err := restarted.acceptDirectoryEvent(t.Context(), app, event); !errors.Is(err, ErrConflict) {
		t.Fatal("conflicting event ID accepted", err)
	}
	if _, err := directory.Observe(t.Context(), app.OrganizationID, member.ID, "phone"); !errors.Is(err, ErrIneligible) {
		t.Fatal("phone login ignored departure", err)
	}
	if _, err := directory.Observe(t.Context(), app.OrganizationID, member.ID, "dingtalk"); !errors.Is(err, ErrIneligible) {
		t.Fatal("DingTalk login ignored departure", err)
	}
}

func TestDirectoryEventOrderingAndVerifiedReturn(t *testing.T) {
	store, _, directory, _, app, member := reconciliationFixture(t)
	born := time.Now().Add(-time.Minute).UnixMilli()
	accept := func(id, kind string, at int64) {
		t.Helper()
		if err := directory.acceptDirectoryEvent(t.Context(), app, directoryEvent(app, id, kind, at)); err != nil {
			t.Fatal(err)
		}
	}
	departed := func(want bool) {
		t.Helper()
		var got bool
		if err := store.pool.QueryRow(t.Context(), "SELECT external_departure FROM members WHERE id=$1", member.ID).Scan(&got); err != nil || got != want {
			t.Fatal("incorrect departure evidence", got, want, err)
		}
	}
	accept("leave", "user_leave_org", born)
	departed(true)
	accept("return", "user_add_org", born+2)
	departed(true) // Positive events are not verified directory evidence.
	if _, err := directory.Reconcile(t.Context(), app.OrganizationID); err != nil {
		t.Fatal(err)
	}
	departed(false)
	accept("late-leave", "user_leave_org", born+1)
	accept("leave", "user_leave_org", born) // Replay after successful return.
	departed(false)
	accept("same-time-leave", "user_leave_org", born+2)
	departed(true)
	accept("same-time-add", "user_add_org", born+2)
	departed(true)
	accept("new-profile", "user_modify_org", born+3)
	departed(true)
	if _, err := directory.Reconcile(t.Context(), app.OrganizationID); err != nil {
		t.Fatal(err)
	}
	departed(false)
}

func TestDirectoryEventInvalidInputAndStaleConnectionRollback(t *testing.T) {
	for _, kind := range []string{"wrong corporation", "missing time", "future time", "empty users", "invalid user", "too many users", "unsupported type", "rotation", "disabled", "lifecycle cycle", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			store, apps, directory, _, app, member := reconciliationFixture(t)
			event := directoryEvent(app, "leave", "user_leave_org", time.Now().UnixMilli())
			switch kind {
			case "wrong corporation":
				event.CorpID = "another-corp"
			case "missing time":
				event.BornTime = 0
			case "future time":
				event.BornTime = time.Now().Add(time.Hour).UnixMilli()
			case "empty users":
				event.UserIDs = nil
			case "invalid user":
				event.UserIDs = []string{"\n"}
			case "too many users":
				event.UserIDs = make([]string, 1001)
			case "unsupported type":
				event.Type = "org_remove"
			case "rotation":
				if _, err := apps.Configure(t.Context(), app.OrganizationID, DingTalkApplicationInput{CorpID: app.CorpID, ClientID: app.ClientID, ClientSecret: "new-synthetic-secret", ExpectedRevision: app.Revision}); err != nil {
					t.Fatal(err)
				}
			case "disabled", "lifecycle cycle":
				disabled := "disabled"
				if _, err := store.UpdateOrganization(t.Context(), app.OrganizationID, OrganizationChange{Status: &disabled}); err != nil {
					t.Fatal(err)
				}
				if kind == "lifecycle cycle" {
					enabled := "enabled"
					if _, err := store.UpdateOrganization(t.Context(), app.OrganizationID, OrganizationChange{Status: &enabled}); err != nil {
						t.Fatal(err)
					}
				}
			case "revoked":
				if _, err := apps.recordAuthorization(t.Context(), app, app.organizationRevision, "revoked"); err != nil {
					t.Fatal(err)
				}
			}
			if err := directory.acceptDirectoryEvent(t.Context(), app, event); err == nil {
				t.Fatal("invalid or stale event accepted")
			}
			var count int
			var departed bool
			if err := store.pool.QueryRow(t.Context(), "SELECT count(*) FROM dingtalk_events").Scan(&count); err != nil || count != 0 {
				t.Fatal("failed event left receipt", err)
			}
			if err := store.pool.QueryRow(t.Context(), "SELECT external_departure FROM members WHERE id=$1", member.ID).Scan(&departed); err != nil || departed {
				t.Fatal("failed event changed member", err)
			}
		})
	}
}

func TestDirectoryEventsFenceInFlightChecksAndAdmissions(t *testing.T) {
	for _, kind := range []string{"reconcile", "observation", "login", "first admission"} {
		t.Run(kind, func(t *testing.T) {
			store, _, directory, verifier, app, member := reconciliationFixture(t)
			event := directoryEvent(app, "leave", "user_leave_org", time.Now().UnixMilli())
			leave := func() {
				t.Helper()
				if err := directory.acceptDirectoryEvent(t.Context(), app, event); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "reconcile":
				directory.provider = directoryDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
					leave()
					return dingtalk.Member{UnionID: "example-union", UserID: "example-employee"}, nil
				})
				result, err := directory.Reconcile(t.Context(), app.OrganizationID)
				if !errors.Is(err, ErrSynchronizationIncomplete) || result.Conflicts != 1 {
					t.Fatal("lookup overwrote departure", err)
				}
			case "observation":
				observed, err := directory.Observe(t.Context(), app.OrganizationID, member.ID, "phone")
				if err != nil {
					t.Fatal(err)
				}
				leave()
				if err := observed.Validate(t.Context(), store.pool); !errors.Is(err, ErrIneligible) {
					t.Fatal("observation survived departure", err)
				}
			case "login", "first admission":
				if kind == "first admission" {
					event.UserIDs = []string{"new-employee"}
				}
				verifier.provider = loginDingTalkFunc(func(context.Context, string, string, string, string) (dingtalk.Member, error) {
					leave()
					if kind == "first admission" {
						return dingtalk.Member{UnionID: "new-union", UserID: "new-employee"}, nil
					}
					return dingtalk.Member{UnionID: "example-union", UserID: "example-employee"}, nil
				})
				proof := verifiedLogin(t, verifier, app)
				if _, err := admitLogin(t.Context(), verifier, proof); !errors.Is(err, ErrConflict) {
					t.Fatal("stale admission survived departure", err)
				}
			}
		})
	}
}

func TestDirectoryEventsDoNotProvisionOrCrossBindings(t *testing.T) {
	store, apps, directory, verifier, app, member := reconciliationFixture(t)
	secondID, _ := NewID(OrganizationKind)
	second, err := store.CreateOrganization(t.Context(), secondID, "Another organization")
	if err != nil {
		t.Fatal(err)
	}
	secondApp, err := apps.Configure(t.Context(), second.ID, DingTalkApplicationInput{CorpID: "another-corp", ClientID: "another-client", ClientSecret: "synthetic-secret"})
	if err != nil {
		t.Fatal(err)
	}
	wrong := directoryEvent(secondApp, "leave", "user_leave_org", time.Now().UnixMilli())
	if err := directory.acceptDirectoryEvent(t.Context(), secondApp, wrong); err != nil {
		t.Fatal(err)
	}
	unknown := directoryEvent(app, "unknown", "user_add_org", time.Now().UnixMilli())
	unknown.UserIDs = []string{"unknown"}
	if err := directory.acceptDirectoryEvent(t.Context(), app, unknown); err != nil {
		t.Fatal(err)
	}
	proof := verifiedLogin(t, verifier, app)
	verified, err := admitLogin(t.Context(), verifier, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeBinding(t.Context(), app.OrganizationID, member.ID, verified.Factor.ID); err != nil {
		t.Fatal(err)
	}
	if err := directory.acceptDirectoryEvent(t.Context(), app, directoryEvent(app, "revoked-binding", "user_leave_org", time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	var count int
	var departed bool
	if err := store.pool.QueryRow(t.Context(), "SELECT count(*) FROM members").Scan(&count); err != nil || count != 2 {
		t.Fatal("event provisioned a member", err)
	}
	if err := store.pool.QueryRow(t.Context(), "SELECT external_departure FROM members WHERE id=$1", member.ID).Scan(&departed); err != nil || departed {
		t.Fatal("event crossed identity boundary", err)
	}
}

func TestDirectoryDepartureWaitsForIssuanceTransaction(t *testing.T) {
	store, _, directory, _, app, member := reconciliationFixture(t)
	observation, err := directory.Observe(t.Context(), app.OrganizationID, member.ID, "phone")
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := store.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback(context.Background())
	if err := observation.Validate(t.Context(), transaction); err != nil {
		t.Fatal(err)
	}
	// A deadline proves that acceptance cannot acknowledge a departure while an
	// earlier validated issuance transaction still holds its eligibility lock.
	bounded, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	event := directoryEvent(app, "ordered-leave", "user_leave_org", time.Now().UnixMilli())
	if err := directory.acceptDirectoryEvent(bounded, app, event); err == nil {
		t.Fatal("event bypassed active issuance transaction")
	}
	if err := transaction.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := directory.acceptDirectoryEvent(t.Context(), app, event); err != nil {
		t.Fatal("event failed after issuance completed", err)
	}
	if err := observation.Validate(t.Context(), store.pool); !errors.Is(err, ErrIneligible) {
		t.Fatal("subsequent issuance ignored departure", err)
	}
}
