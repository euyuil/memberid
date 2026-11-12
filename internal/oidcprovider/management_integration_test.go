//go:build integration

package oidcprovider

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/management"
)

func TestOIDCAndManagementCredentialsAreSeparate(t *testing.T) {
	f := newFixture(t)
	tokens := f.tokens()
	managementSecret := config.RandomSecret()
	handler, err := management.New(f.store, config.SecretHash(managementSecret), nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	for _, credential := range []string{tokens["access_token"].(string), tokens["id_token"].(string), f.secret} {
		response := f.call(f.browser, http.MethodGet, server.URL+"/v1/organizations", nil, map[string]string{"Authorization": "Bearer " + credential})
		f.status(response, http.StatusUnauthorized)
	}
	f.status(f.call(f.browser, http.MethodGet, server.URL+"/v1/organizations", nil, map[string]string{"Authorization": "Bearer " + managementSecret}), http.StatusOK)
	f.status(f.call(f.browser, http.MethodGet, "/v1/organizations", nil, map[string]string{"Authorization": "Bearer " + managementSecret}), http.StatusNotFound)
	f.status(f.userinfo(managementSecret), http.StatusUnauthorized)
}
