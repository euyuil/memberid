//go:build integration

package management

import (
	"encoding/json"
	"testing"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

func TestEnrollmentManagementContract(t *testing.T) {
	f := newFixture(t)
	factor, err := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8619900000001")
	if err != nil {
		t.Fatal(err)
	}
	input := identity.OrganizationEnrollment{IdempotencyKey: "00000000-0000-4000-8000-000000000010", FactorID: factor.ID, BindingID: "00000000-0000-4000-8000-000000000001", Name: "Example organization"}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var first, second identity.EnrollmentReceipt
	f.call(t, "POST", "/v1/organization-enrollments", string(body), 200, &first)
	f.call(t, "POST", "/v1/organization-enrollments", string(body), 200, &second)
	if first != second || !identity.ValidID(first.OrganizationID, identity.OrganizationKind) || !identity.ValidID(first.MemberID, identity.MemberKind) {
		t.Fatal("HTTP enrollment replay changed the receipt")
	}
	f.call(t, "GET", "/v1/organizations/"+first.OrganizationID+"/enrollment", "", 200, &second)
	if second != first {
		t.Fatal("HTTP receipt lookup differs")
	}
	input.Name = "Conflicting name"
	body, err = json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	f.call(t, "POST", "/v1/organization-enrollments", string(body), 409, nil)
	for _, addition := range []string{`"organizationId":"` + first.OrganizationID + `"`, `"memberId":"` + first.MemberID + `"`, `"memberId":null`, `"organizationId":""`} {
		var failure map[string]string
		f.call(t, "POST", "/v1/organization-enrollments", string(body[:len(body)-1])+","+addition+"}", 400, &failure)
		if failure["error"] != "invalid_request" {
			t.Fatal(failure)
		}
	}
	input.IdempotencyKey = ""
	body, err = json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	f.call(t, "POST", "/v1/organization-enrollments", string(body), 400, nil)
}
