//go:build integration

package identity

import (
	"errors"
	"testing"
)

func TestPasswordUsernameCaseSharesReservationAndAttemptLimit(t *testing.T) {
	store := testStore(t)
	ctx := t.Context()
	op := OperatorPrincipal()
	org, first := organizationAndMember(t, store)
	second, err := store.CreateMember(ctx, op, org.ID, "", "Second member")
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for id, name := range map[string]string{first.ID: "Casey", second.ID: "CASEY"} {
		go func() {
			_, err := store.SetMemberPassword(ctx, op, org.ID, id, name)
			results <- err
		}()
	}
	a, b := <-results, <-results
	if !(a == nil && errors.Is(b, ErrConflict) || b == nil && errors.Is(a, ErrConflict)) {
		t.Fatalf("concurrent case variants returned %v, %v", a, b)
	}
	for i := 0; i < 10; i++ {
		if err := store.VerifyPasswordAndApply(ctx, org.ID, "casey", "incorrect", nil); !errors.Is(err, ErrPasswordCredential) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	if err := store.VerifyPasswordAndApply(ctx, org.ID, "CaSeY", "incorrect", nil); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("mixed-case attempt after limit: %v", err)
	}
}
