//go:build integration

package management

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/identity"
)

func TestMemberEligibilityManagementContract(t *testing.T) {
	f := newFixture(t)
	organization, member := f.provision(t)
	other, outside := f.provision(t)
	factor, err := f.store.EnsureFactor(t.Context(), "phone", "phone:e164", "+12025550101")
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range []struct{ organizationID, memberID string }{{organization.ID, member.ID}, {other.ID, outside.ID}} {
		if _, err := f.store.BindFactor(t.Context(), identity.OperatorPrincipal(), pair.organizationID, pair.memberID, factor.ID); err != nil {
			t.Fatal(err)
		}
	}
	path := "/v1/organizations/" + organization.ID + "/member-eligibility"
	body := `{"memberIds":["` + outside.ID + `","` + member.ID + `"]}`
	var result struct {
		Members []string `json:"eligibleMemberIds"`
	}
	f.call(t, "POST", path, body, 200, &result)
	if !slices.Equal(result.Members, []string{member.ID}) {
		t.Fatal("unexpected eligible identities", result.Members)
	}
	f.call(t, "PATCH", "/v1/organizations/"+organization.ID+"/members/"+member.ID, `{"manualBlocked":true}`, 200, nil)
	f.call(t, "POST", path, body, 200, &result)
	if result.Members == nil || len(result.Members) != 0 {
		t.Fatal("ineligible result must be an empty array")
	}
	for _, body := range []string{`{}`, `{"memberIds":null}`, `{"memberIds":[]}`, `{"memberIds":[null]}`, `{"memberIds":["invalid"]}`, `{"memberIds":["` + member.ID + `","` + member.ID + `"]}`, `{"memberIds":[],"memberIds":["` + member.ID + `"]}`, `{"MemberIds":["` + member.ID + `"]}`, `{"memberIds":["` + member.ID + `"],"extra":true}`} {
		f.call(t, "POST", path, body, 400, nil)
	}
	many := []string{}
	for range 101 {
		id, err := identity.NewID(identity.MemberKind)
		if err != nil {
			t.Fatal(err)
		}
		many = append(many, id)
	}
	encoded, err := json.Marshal(map[string]any{"memberIds": many})
	if err != nil {
		t.Fatal(err)
	}
	f.call(t, "POST", path, string(encoded), 400, nil)
	f.call(t, "POST", path+"?limit=1", body, 400, nil)
	f.call(t, "POST", "/v1/organizations/invalid/member-eligibility", body, 400, nil)
	f.call(t, "GET", path, "", 405, nil)
	for _, origin := range []string{"", "https://client.example.invalid"} {
		request, err := http.NewRequest("POST", f.server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		want := 401
		if origin != "" {
			request.Header.Set("Authorization", "Bearer "+f.secret)
			request.Header.Set("Origin", origin)
			want = 403
		}
		response, err := f.server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("management boundary: %d, want %d", response.StatusCode, want)
		}
	}
}
