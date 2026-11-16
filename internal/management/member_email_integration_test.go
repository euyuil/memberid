//go:build integration

package management

import (
	"testing"

	"github.com/euyuil/memberid/internal/identity"
)

func TestMemberEmailManagementHTTP(t *testing.T) {
	f := newFixture(t)
	org, member := f.provision(t)
	other, _ := f.provision(t)
	path := "/v1/organizations/" + org.ID + "/members/" + member.ID + "/email"
	var email identity.MemberEmail
	f.call(t, "GET", path, "", 200, &email)
	if email.Address != "" || email.Revision != 0 || email.MailboxVerified {
		t.Fatal(email)
	}
	for _, body := range []string{`{}`, `{"address":"a@example.test"}`, `{"revision":0}`, `{"address":null,"revision":0}`, `{"address":"a@example.test","revision":0,"source":"feishu"}`, `{"address":"a@example.test","revision":0,"mailboxVerified":true}`, `{"address":"a@example.test","revision":0,"actor":"forged"}`} {
		f.call(t, "PUT", path, body, 400, nil)
	}
	f.call(t, "PUT", path, `{"address":"a@example.test","revision":0}`, 200, &email)
	if email.Address != "a@example.test" || email.UpdatedBy != "installation-manager" || email.MailboxVerified {
		t.Fatal(email)
	}
	f.call(t, "PUT", path, `{"address":"b@example.test","revision":0}`, 409, nil)
	f.call(t, "GET", "/v1/organizations/"+other.ID+"/members/"+member.ID+"/email", "", 404, nil)
	f.call(t, "PUT", path, `{"address":"","revision":1}`, 200, &email)
	if email.Address != "" || email.Revision != 2 {
		t.Fatal(email)
	}
}
