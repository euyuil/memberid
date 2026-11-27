package console

import (
	"net/http"

	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/identity"
	"github.com/zhizhun-tech/memberid/internal/management"
)

type oidcApplicationResult struct {
	Application  identity.OIDCApplication `json:"application"`
	ClientSecret string                   `json:"clientSecret,omitempty"`
}

func (s *Service) registerOIDCApplicationRoutes(installation *config.Loaded) {
	const collection = "/api/oidc-applications"
	const scopedCollection = "/api/organizations/{organizationId}/oidc-applications"
	list := func(w http.ResponseWriter, r *http.Request) {
		value, err := s.management.OIDCApplications(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"))
		respond(w, struct {
			identity.OIDCApplicationDirectory
			Issuer            string `json:"issuer"`
			AllowLoopbackHTTP bool   `json:"allowLoopbackHttp"`
		}{value, installation.Issuer, installation.AllowLoopbackHTTP}, err)
	}
	create := func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			DisplayName            string   `json:"displayName"`
			OrganizationID         string   `json:"organizationId"`
			RedirectURIs           []string `json:"redirectUris"`
			PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris"`
			AccountReturnURIs      []string `json:"accountReturnUris"`
			EvidenceScope          string   `json:"evidenceScope"`
			EvidenceAudience       string   `json:"evidenceAudience"`
			Preauthorized          bool     `json:"preauthorized"`
			Refresh                bool     `json:"refresh"`
		}
		if !management.DecodeRequest(w, r, &input) {
			return
		}
		secret := config.RandomSecret()
		value, err := s.management.CreateOIDCApplication(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"),
			identity.OIDCApplication{
				DisplayName: input.DisplayName, OrganizationID: input.OrganizationID,
				RedirectURIs: input.RedirectURIs, PostLogoutRedirectURIs: input.PostLogoutRedirectURIs, Refresh: input.Refresh,
				AccountReturnURIs: input.AccountReturnURIs, Preauthorized: input.Preauthorized,
				EvidenceScope: input.EvidenceScope, EvidenceAudience: input.EvidenceAudience,
			}, config.SecretHash(secret), installation.AllowLoopbackHTTP)
		respond(w, oidcApplicationResult{value, secret}, err)
	}
	update := func(w http.ResponseWriter, r *http.Request) {
		var input identity.OIDCApplicationChange
		if !management.DecodeRequest(w, r, &input) {
			return
		}
		value, err := s.management.UpdateOIDCApplication(r.Context(), r.Context().Value(sessionKey{}).(session).principal(),
			r.PathValue("organizationId"), r.PathValue("clientId"), input, installation.AllowLoopbackHTTP)
		respond(w, oidcApplicationResult{Application: value}, err)
	}
	rotate := func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ExpectedRevision int64 `json:"expectedRevision"`
		}
		if !management.DecodeRequest(w, r, &input) {
			return
		}
		secret := config.RandomSecret()
		value, err := s.management.RotateOIDCApplicationSecret(r.Context(), r.Context().Value(sessionKey{}).(session).principal(),
			r.PathValue("organizationId"), r.PathValue("clientId"), input.ExpectedRevision, config.SecretHash(secret))
		respond(w, oidcApplicationResult{value, secret}, err)
	}
	for _, path := range []string{collection, scopedCollection} {
		item := path + "/{clientId}"
		s.routes.HandleFunc("GET "+path, list)
		s.routes.HandleFunc("POST "+path, create)
		s.routes.HandleFunc("PATCH "+item, update)
		s.routes.HandleFunc("POST "+item+"/rotate-secret", rotate)
	}
}
