package console

import (
	"context"
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
			AllowOrganizationScope bool     `json:"allowOrganizationScope"`
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
				AllowOrganizationScope: input.AllowOrganizationScope,
				EvidenceScope:          input.EvidenceScope, EvidenceAudience: input.EvidenceAudience,
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
	const uses = "/api/organizations/{organizationId}/oidc-application-uses"
	readUses := func(w http.ResponseWriter, r *http.Request) {
		items, err := s.management.OIDCApplicationUses(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"), r.PathValue("clientId"))
		if r.PathValue("clientId") != "" && err == nil {
			respond(w, items[0], nil)
			return
		}
		respond(w, map[string]any{"items": items}, err)
	}
	s.routes.HandleFunc("GET "+uses, readUses)
	s.routes.HandleFunc("GET "+uses+"/{clientId}", readUses)
	s.routes.HandleFunc("PUT "+scopedCollection+"/{clientId}/publication", sharingHandler("clientId", s.management.SetOIDCPublication))
	s.routes.HandleFunc("PUT "+scopedCollection+"/{clientId}/enablement", sharingHandler("clientId", s.management.SetOIDCEnablement))
	for _, path := range []string{collection, scopedCollection} {
		item := path + "/{clientId}"
		s.routes.HandleFunc("GET "+path, list)
		s.routes.HandleFunc("POST "+path, create)
		s.routes.HandleFunc("PATCH "+item, update)
		s.routes.HandleFunc("POST "+item+"/rotate-secret", rotate)
	}
}

func sharingHandler(param string, set func(context.Context, identity.Principal, string, string, bool) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Enabled *bool `json:"enabled"`
		}
		if !management.DecodeRequest(w, r, &input) {
			return
		}
		if input.Enabled == nil {
			respond(w, nil, identity.ErrInvalid)
			return
		}
		err := set(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"), r.PathValue(param), *input.Enabled)
		respond(w, map[string]bool{"enabled": *input.Enabled}, err)
	}
}
