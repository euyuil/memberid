package management

import (
	"net/http"

	"github.com/euyuil/memberid/internal/identity"
)

func (h *Handler) dingTalkRoutes(applications *identity.DingTalkApplications) {
	h.routes.HandleFunc("GET /v1/organizations/{organizationId}/dingtalk-application", func(w http.ResponseWriter, r *http.Request) {
		app, err := applications.Inspect(r.Context(), r.PathValue("organizationId"))
		respond(w, http.StatusOK, app, err)
	})
	h.routes.HandleFunc("PUT /v1/organizations/{organizationId}/dingtalk-application", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			CorpID           string `json:"corpId"`
			ClientID         string `json:"clientId"`
			ClientSecret     string `json:"clientSecret"`
			ExpectedRevision *int64 `json:"expectedRevision"`
		}
		if !decode(w, r, &input) {
			return
		}
		if input.ExpectedRevision == nil {
			problem(w, http.StatusBadRequest, "invalid_request")
			return
		}
		app, err := applications.Configure(r.Context(), r.PathValue("organizationId"), identity.DingTalkApplicationInput{CorpID: input.CorpID, ClientID: input.ClientID, ClientSecret: input.ClientSecret, ExpectedRevision: *input.ExpectedRevision})
		respond(w, http.StatusOK, app, err)
	})
}
