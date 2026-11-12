//go:build integration

package management

import (
	"encoding/json"
	"testing"

	"github.com/euyuil/memberid/internal/identity"
)

func TestEnrollmentManagementContract(t *testing.T) {
	f := newFixture(t)
	organizationID, err := identity.NewID(identity.OrganizationKind)
	if err != nil {
		t.Fatal(err)
	}
	memberID, err := identity.NewID(identity.MemberKind)
	if err != nil {
		t.Fatal(err)
	}
	factor, err := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", "+8619900000001")
	if err != nil {
		t.Fatal(err)
	}
	input := identity.OrganizationEnrollment{OrganizationID: organizationID, MemberID: memberID, FactorID: factor.ID, BindingID: "00000000-0000-4000-8000-000000000001", Name: "Example organization"}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var first, second identity.EnrollmentReceipt
	f.call(t, "POST", "/v1/organization-enrollments", string(body), 200, &first)
	f.call(t, "POST", "/v1/organization-enrollments", string(body), 200, &second)
	if first != second || first.OrganizationID != organizationID || first.MemberID != memberID {
		t.Fatal("HTTP enrollment replay changed the receipt")
	}
	f.call(t, "GET", "/v1/organizations/"+organizationID+"/enrollment", "", 200, &second)
	if second != first {
		t.Fatal("HTTP receipt lookup differs")
	}
	input.Name = "Conflicting name"
	body, err = json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	f.call(t, "POST", "/v1/organization-enrollments", string(body), 409, nil)
	input.OrganizationID, err = identity.NewID(identity.OrganizationKind)
	if err != nil {
		t.Fatal(err)
	}
	body, err = json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var failure map[string]string
	f.call(t, "POST", "/v1/organization-enrollments", string(body), 422, &failure)
	if failure["error"] != "member_id_conflict" {
		t.Fatal("collision category was lost")
	}
	f.call(t, "GET", "/v1/organizations/"+input.OrganizationID, "", 404, nil)
}
