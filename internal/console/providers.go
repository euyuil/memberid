package console

import (
	"net/http"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/management"
)

func (s *Service) registerProviderRoutes(installation *config.Loaded) {
	const path = "/api/organizations/{organizationId}/providers"
	s.routes.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
		items, err := s.management.Providers(r.Context(), r.Context().Value(sessionKey{}).(session).principal(), r.PathValue("organizationId"))
		respond(w, map[string]any{
			"items":            items,
			"feishuCallback":   installation.Issuer + "/login/feishu/callback",
			"dingTalkCallback": installation.Issuer + "/login/dingtalk/callback",
		}, err)
	})
	configure := func(w http.ResponseWriter, r *http.Request) {
		var input identity.ProviderInput
		if !management.DecodeRequest(w, r, &input) {
			return
		}
		v := r.Context().Value(sessionKey{}).(session)
		item, err := s.management.ConfigureProvider(r.Context(), v.principal(), r.PathValue("organizationId"), r.PathValue("kind"), r.PathValue("providerId"), input)
		respond(w, item, err)
	}
	s.routes.HandleFunc("POST "+path+"/{kind}", configure)
	s.routes.HandleFunc("PUT "+path+"/{kind}/{providerId}", configure)
}
