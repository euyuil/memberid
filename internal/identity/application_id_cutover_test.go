package identity

import (
	"slices"
	"testing"
)

func TestApplicationManifest(t *testing.T) {
	keys := []applicationKey{{"oidc", "same"}, {"saml", "same"}}
	plan, err := matchApplicationIDs(keys, nil, true)
	if err != nil || len(plan) != 2 || !ValidID(plan[0].NewID, ApplicationKind) || !ValidID(plan[1].NewID, ApplicationKind) || plan[0].NewID == plan[1].NewID {
		t.Fatal("invalid plan", plan, err)
	}
	extended, err := matchApplicationIDs(append(keys, applicationKey{"saml", "another"}), plan, true)
	if err != nil || !slices.Equal(extended[:2], plan) {
		t.Fatal("reconciliation changed an existing assignment", extended, err)
	}
	for _, invalid := range [][]ApplicationIDAssignment{
		plan[:1], {plan[0], plan[0]}, extended,
		{plan[0], {"saml", "same", plan[0].NewID}},
		{plan[0], {"saml", "same", "invalid"}},
	} {
		if _, err := matchApplicationIDs(keys, invalid, false); err == nil {
			t.Fatal("accepted incomplete or ambiguous assignments", invalid)
		}
	}
	retry, err := matchApplicationIDs(keys, plan, false)
	if err != nil || !slices.Equal(retry, plan) {
		t.Fatal("retry changed plan", err)
	}
}
