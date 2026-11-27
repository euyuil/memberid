package management

import (
	"net/http"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

func (h *Handler) memberEmailRoutes() {
	const path = "/v1/organizations/{organizationId}/members/{memberId}/email"
	h.routes.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
		value, err := h.store.MemberEmail(r.Context(), identity.InstallationManagerPrincipal(), r.PathValue("organizationId"), r.PathValue("memberId"))
		respond(w, http.StatusOK, value, err)
	})
	h.routes.HandleFunc("PUT "+path, func(w http.ResponseWriter, r *http.Request) {
		input, ok := DecodeMemberEmail(w, r)
		if !ok {
			return
		}
		value, err := h.store.PutMemberEmail(r.Context(), identity.InstallationManagerPrincipal(), r.PathValue("organizationId"), r.PathValue("memberId"), input)
		respond(w, http.StatusOK, value, err)
	})
}

// Both fields are required: an omitted address must never clear the assertion.
func DecodeMemberEmail(w http.ResponseWriter, r *http.Request) (identity.MemberEmailInput, bool) {
	var input struct {
		Address  *string `json:"address"`
		Revision *int64  `json:"revision"`
	}
	if !DecodeRequest(w, r, &input) {
		return identity.MemberEmailInput{}, false
	}
	if input.Address == nil || input.Revision == nil {
		problem(w, http.StatusBadRequest, "invalid_request")
		return identity.MemberEmailInput{}, false
	}
	return identity.MemberEmailInput{Address: *input.Address, Revision: *input.Revision}, true
}
