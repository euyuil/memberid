//go:build integration

package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/euyuil/memberid/internal/identity"
)

func TestMemberUpdateManagementContract(t *testing.T) {
	f := newFixture(t)
	organization, member := f.provision(t)
	path := "/v1/organizations/" + organization.ID + "/members/" + member.ID + "/updates/abcd0000-abcd-4abc-8abc-000000000001"
	// A UUID's casing is not part of the operation identity.
	request, err := http.NewRequest("PUT", f.server.URL+strings.TrimSuffix(path, "abcd0000-abcd-4abc-8abc-000000000001")+"ABCD0000-ABCD-4ABC-8ABC-000000000001", strings.NewReader(`{"manualBlocked":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+f.secret)
	request.Header.Set("Content-Type", "application/json")
	response, err := f.server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var first identity.MemberUpdateReceipt
	if response.StatusCode != 201 || response.Header.Get("Location") != path || response.Header.Get("Cache-Control") != "no-store" || json.NewDecoder(response.Body).Decode(&first) != nil {
		t.Fatal("missing created receipt or canonical location")
	}
	var repeated identity.MemberUpdateReceipt
	f.call(t, "PUT", path, `{"manualBlocked":true}`, 200, &repeated)
	if !reflect.DeepEqual(first, repeated) {
		t.Fatal("HTTP replay changed the receipt")
	}
	f.call(t, "GET", path, "", 200, &repeated)
	if !reflect.DeepEqual(first, repeated) {
		t.Fatal("HTTP receipt lookup changed")
	}
	f.call(t, "PUT", path, `{"manualBlocked":false}`, 409, nil)
	f.call(t, "GET", path+"?limit=1", "", 400, nil)
	for _, body := range []string{`{}`, `{"manualBlocked":null}`, `{"manualBlocked":true,"manualBlocked":false}`, `{"ManualBlocked":true}`, `{"manualBlocked":true,"actorMemberId":"untrusted"}`} {
		f.call(t, "PUT", path, body, 400, nil)
	}
	f.call(t, "PUT", strings.TrimSuffix(path, "abcd0000-abcd-4abc-8abc-000000000001")+"invalid", `{"manualBlocked":true}`, 400, nil)
	other, _ := f.provision(t)
	f.call(t, "GET", strings.Replace(path, organization.ID, other.ID, 1), "", 404, nil)
	var current identity.Member
	f.call(t, "GET", "/v1/organizations/"+organization.ID+"/members/"+member.ID, "", 200, &current)
	if current.Status != "blocked" {
		t.Fatal("rejected request modified the member")
	}
}

func TestMemberUpdateLostHTTPResponseDoesNotUndoLaterChange(t *testing.T) {
	f := newFixture(t)
	organization, member := f.provision(t)
	path := "/v1/organizations/" + organization.ID + "/members/" + member.ID + "/updates/00000000-0000-4000-8000-000000000002"
	original := f.server.Config.Handler
	var lose atomic.Bool
	lose.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == path && lose.CompareAndSwap(true, false) {
			saved := httptest.NewRecorder()
			original.ServeHTTP(saved, r)
			if saved.Code != 201 {
				t.Errorf("fixture did not commit before losing response: %d", saved.Code)
			}
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		original.ServeHTTP(w, r)
	}))
	defer server.Close()
	request, err := http.NewRequest("PUT", server.URL+path, strings.NewReader(`{"manualBlocked":true,"displayName":"Original update"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+f.secret)
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("fixture did not lose the HTTP response")
	}
	var first identity.MemberUpdateReceipt
	f.call(t, "GET", path, "", 200, &first)
	if first.Member.Status != "blocked" {
		t.Fatal("lost response was not a committed update")
	}
	memberPath := "/v1/organizations/" + organization.ID + "/members/" + member.ID
	f.call(t, "PATCH", memberPath, `{"manualBlocked":false,"displayName":"Later update"}`, 200, nil)
	var recovered identity.MemberUpdateReceipt
	f.call(t, "PUT", path, `{"displayName":"Original update","manualBlocked":true}`, 200, &recovered)
	if !reflect.DeepEqual(first, recovered) {
		t.Fatal("recovery changed the historical receipt")
	}
	var current identity.Member
	f.call(t, "GET", memberPath, "", 200, &current)
	if current.Status != "active" || current.DisplayName != "Later update" {
		t.Fatal("lost-response retry undid a later update")
	}
}

func TestMemberUpdateRequiresManagementCredential(t *testing.T) {
	f := newFixture(t)
	organization, member := f.provision(t)
	path := "/v1/organizations/" + organization.ID + "/members/" + member.ID + "/updates/00000000-0000-4000-8000-000000000003"
	request, err := http.NewRequest("PUT", f.server.URL+path, strings.NewReader(`{"manualBlocked":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := f.server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("anonymous update accepted")
	}
	f.call(t, "GET", path, "", 404, nil)
	current, err := f.store.Member(t.Context(), organization.ID, member.ID)
	if err != nil || current.Status != "active" {
		t.Fatal("anonymous update changed member", err)
	}
}
