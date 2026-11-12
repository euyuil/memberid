//go:build integration

package management

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
)

type applicationChecker struct{ fail bool }

func (checker *applicationChecker) CheckAuthorization(context.Context, string, string, string) error {
	if checker.fail {
		return errors.New("private provider details")
	}
	return nil
}

func TestDingTalkApplicationManagement(t *testing.T) {
	f := newFixture(t)
	organization, _ := f.provision(t)
	checker := new(applicationChecker)
	applications, err := identity.NewDingTalkApplications(f.store, []byte(strings.Repeat("k", 32)), checker)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(f.store, config.SecretHash(f.secret), applications)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	f.server = server
	path := "/v1/organizations/" + organization.ID + "/dingtalk-application"
	f.call(t, "GET", path, "", 404, nil)
	input := identity.DingTalkApplicationInput{CorpID: "example-corp", ClientID: "example-client", ClientSecret: rand.Text()}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	f.call(t, "PUT", path, string(body), 200, &result)
	if result["revision"] != float64(1) || result["organizationId"] != organization.ID || result["clientSecret"] != nil || result["secretCiphertext"] != nil {
		t.Fatal("invalid metadata or secret exposure")
	}
	f.call(t, "GET", path, "", 200, &result)
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), input.ClientSecret) {
		t.Fatal("secret exposed by inspection")
	}
	f.call(t, "PUT", path, string(body), 409, nil)
	input.ExpectedRevision = 1
	input.ClientSecret = rand.Text()
	body, err = json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	checker.fail = true
	var problem map[string]string
	f.call(t, "PUT", path, string(body), 503, &problem)
	if problem["error"] != "provider_unavailable" || len(problem) != 1 {
		t.Fatal("provider details exposed")
	}
	checker.fail = false
	f.call(t, "PUT", path, string(body), 200, &result)
	if result["revision"] != float64(2) {
		t.Fatal("rotation did not advance revision")
	}
	for _, body := range []string{`{"corpId":"example-corp","clientId":"example-client","clientSecret":"synthetic-secret"}`, `{"corpId":"example-corp","clientId":"example-client","clientSecret":"synthetic-secret","expectedRevision":null}`, `{"corpId":"example-corp","corpId":"different","clientId":"example-client","clientSecret":"synthetic-secret"}`, `{"CorpId":"example-corp"}`, `{"corpId":"../other","clientId":"example-client","clientSecret":"synthetic-secret"}`} {
		f.call(t, "PUT", path, body, 400, nil)
	}
	f.call(t, "PUT", path+"?clientSecret=synthetic", string(body), 400, nil)
}
