package console

import (
	"net/http"

	"github.com/zhizhun-tech/memberid/internal/management"
)

func (s *Service) registerSAMLRoutes() {
	const collection = "/api/organizations/{organizationId}/saml-service-providers"
	const item = collection + "/{serviceProviderId}"
	const uses = "/api/organizations/{organizationId}/saml-application-uses"
	readUses := func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("serviceProviderId")
		items, err := s.management.SAMLApplicationUses(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"), id)
		if id != "" && err == nil {
			respond(w, items[0], nil)
			return
		}
		respond(w, map[string]any{"items": items}, err)
	}
	s.routes.HandleFunc("GET "+uses, readUses)
	s.routes.HandleFunc("GET "+uses+"/{serviceProviderId}", readUses)
	s.routes.HandleFunc("PUT "+item+"/enablement", sharingHandler("serviceProviderId", s.management.SetSAMLEnablement))
	s.routes.HandleFunc("GET "+collection, func(w http.ResponseWriter, r *http.Request) {
		after, limit, ok := management.DecodePageRequest(w, r)
		if !ok {
			return
		}
		value, err := s.management.SAMLServiceProviders(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"), after, limit)
		respond(w, value, err)
	})
	s.routes.HandleFunc("GET "+item, func(w http.ResponseWriter, r *http.Request) {
		value, err := s.management.SAMLServiceProvider(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"), r.PathValue("serviceProviderId"))
		respond(w, value, err)
	})
	configure := func(w http.ResponseWriter, r *http.Request) {
		input, ok := management.DecodeSAMLRegistration(w, r)
		if !ok {
			return
		}
		value, err := s.management.PutSAMLServiceProvider(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), input.Registration(r.PathValue("organizationId")))
		respond(w, value, err)
	}
	s.routes.HandleFunc("POST "+collection, configure)
	s.routes.HandleFunc("PUT "+item, configure)
	s.routes.HandleFunc("POST "+item+"/retire", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Revision int64 `json:"revision"`
		}
		if !management.DecodeRequest(w, r, &input) {
			return
		}
		value, err := s.management.RetireSAMLServiceProvider(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"), r.PathValue("serviceProviderId"), input.Revision)
		respond(w, value, err)
	})
}
