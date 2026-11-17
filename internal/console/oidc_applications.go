package console

import (
	"net/http"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/management"
)

type oidcApplicationResult struct {
	Application  identity.OIDCApplication `json:"application"`
	ClientSecret string                   `json:"clientSecret,omitempty"`
}

func (s *Service) registerOIDCApplicationRoutes(installation *config.Loaded) {
	const collection = "/api/oidc-applications"
	const item = collection + "/{clientId}"
	s.routes.HandleFunc("GET "+collection, func(w http.ResponseWriter, r *http.Request) {
		value, err := s.management.OIDCApplications(r.Context(), r.Context().Value(sessionKey{}).(session).principal())
		respond(w, struct {
			identity.OIDCApplicationDirectory
			Issuer string `json:"issuer"`
		}{value, installation.Issuer}, err)
	})
	s.routes.HandleFunc("POST "+collection, func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ClientID               string   `json:"clientId"`
			DisplayName            string   `json:"displayName"`
			OrganizationID         string   `json:"organizationId"`
			RedirectURIs           []string `json:"redirectUris"`
			PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris"`
			AccountReturnURIs      []string `json:"accountReturnUris"`
			Preauthorized          bool     `json:"preauthorized"`
			Refresh                bool     `json:"refresh"`
		}
		if !management.DecodeRequest(w, r, &input) {
			return
		}
		secret := config.RandomSecret()
		value, err := s.management.CreateOIDCApplication(r.Context(), r.Context().Value(sessionKey{}).(session).principal(),
			identity.OIDCApplication{
				ClientID: input.ClientID, DisplayName: input.DisplayName, OrganizationID: input.OrganizationID,
				RedirectURIs: input.RedirectURIs, PostLogoutRedirectURIs: input.PostLogoutRedirectURIs, Refresh: input.Refresh,
				AccountReturnURIs: input.AccountReturnURIs, Preauthorized: input.Preauthorized,
			}, config.SecretHash(secret), installation.AllowLoopbackHTTP)
		respond(w, oidcApplicationResult{value, secret}, err)
	})
	s.routes.HandleFunc("PATCH "+item, func(w http.ResponseWriter, r *http.Request) {
		var input identity.OIDCApplicationChange
		if !management.DecodeRequest(w, r, &input) {
			return
		}
		value, err := s.management.UpdateOIDCApplication(r.Context(), r.Context().Value(sessionKey{}).(session).principal(),
			r.PathValue("clientId"), input, installation.AllowLoopbackHTTP)
		respond(w, oidcApplicationResult{Application: value}, err)
	})
	s.routes.HandleFunc("POST "+item+"/rotate-secret", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ExpectedRevision int64 `json:"expectedRevision"`
		}
		if !management.DecodeRequest(w, r, &input) {
			return
		}
		secret := config.RandomSecret()
		value, err := s.management.RotateOIDCApplicationSecret(r.Context(), r.Context().Value(sessionKey{}).(session).principal(),
			r.PathValue("clientId"), input.ExpectedRevision, config.SecretHash(secret))
		respond(w, oidcApplicationResult{value, secret}, err)
	})
}
