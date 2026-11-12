package management

import "net/http"

func (h *Handler) memberEligibility(w http.ResponseWriter, r *http.Request) {
	var input struct {
		MemberIDs []string `json:"memberIds"`
	}
	if !decode(w, r, &input) {
		return
	}
	members, err := h.store.EligibleMemberIDs(r.Context(), r.PathValue("organizationId"), input.MemberIDs)
	respond(w, http.StatusOK, map[string]any{"eligibleMemberIds": members}, err)
}
