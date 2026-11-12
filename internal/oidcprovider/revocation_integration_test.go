//go:build integration

package oidcprovider

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/euyuil/memberid/internal/config"
)

func TestRevocationRejectsUnverifiedInputAndIgnoresTypeHints(t *testing.T) {
	f := newConfiguredFixture(t, true)
	tokens := f.refreshTokens()
	access := tokens["access_token"].(string)
	refresh := tokens["refresh_token"].(string)
	id := f.signedClaims(access)["jti"].(string)
	revoke := func(client, token, hint string) {
		t.Helper()
		basic := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(client+":"+f.secret))}
		f.status(f.call(browserClient(), "POST", "/oauth/revoke", url.Values{"token": {token}, "token_type_hint": {hint}}, basic), 200)
	}
	for _, form := range []url.Values{{}, {"token": {""}}} {
		basic := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("example-web:"+f.secret))}
		f.status(f.call(browserClient(), "POST", "/oauth/revoke", form, basic), 400)
	}
	// Random opaque credentials must not enter the library's unauthenticated legacy decoder.
	unknown := config.RandomSecret()
	if _, err := f.service.protocol.Crypto().Decrypt(unknown); err == nil {
		t.Fatal("accepted unauthenticated opaque ciphertext")
	}
	revoke("example-web", unknown, "refresh_token")
	revoke("example-web", id, "access_token")
	for _, plaintext := range []string{"\xff:" + f.member.ID, id + ":\xff", id + ":" + f.otherMember.ID} {
		malformed, err := f.service.protocol.Crypto().Encrypt(plaintext)
		if err != nil {
			t.Fatal(err)
		}
		revoke("example-web", malformed, "")
	}
	for _, hint := range []string{"", "refresh_token", "access_token", "unknown"} {
		revoke("second-web", refresh, hint)
	}
	f.status(f.userinfo(access), 200)
	response := f.refresh("example-web", refresh, "")
	f.status(response, 200)
	next := jsonObject(t, response)
	revoke("example-web", next["refresh_token"].(string), "access_token")
	f.invalidRefresh("example-web", next["refresh_token"].(string))
	f.status(f.userinfo(next["access_token"].(string)), 401)
}
