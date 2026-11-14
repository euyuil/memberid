package console

import (
	"encoding/base64"
	"net/http"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/management"
)

func (s *Service) registerProviderRoutes(installation *config.Loaded, dingTalkProvider identity.DingTalkAuthorizationChecker, feishuProvider identity.FeishuProvider) error {
	key, err := base64.StdEncoding.DecodeString(installation.Secrets.ProviderKey)
	if err != nil {
		return err
	}
	dingTalk, err := identity.NewDingTalkApplications(s.store, key, dingTalkProvider)
	if err != nil {
		return err
	}
	feishuApps, err := identity.NewFeishuApplications(s.store, key, feishuProvider)
	if err != nil {
		return err
	}
	const path = "/api/organizations/{organizationId}/providers"
	s.routes.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
		items, err := s.store.Providers(r.Context(), r.PathValue("organizationId"))
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
		actor := r.Context().Value(sessionKey{}).(session).actor
		item, err := identity.ConfigureProvider(r.Context(), actor, r.PathValue("organizationId"), r.PathValue("kind"), r.PathValue("providerId"), input, dingTalk, feishuApps)
		respond(w, item, err)
	}
	s.routes.HandleFunc("POST "+path+"/{kind}", configure)
	s.routes.HandleFunc("PUT "+path+"/{kind}/{providerId}", configure)
	return nil
}
