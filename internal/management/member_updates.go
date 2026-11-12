package management

import (
	"net/http"

	"github.com/euyuil/memberid/internal/identity"
)

const memberUpdateRoute = "/v1/organizations/{organizationId}/members/{memberId}/updates/{updateId}"

func (h *Handler) memberUpdate(w http.ResponseWriter, r *http.Request) {
	value, err := h.store.MemberUpdate(r.Context(), r.PathValue("organizationId"), r.PathValue("memberId"), r.PathValue("updateId"))
	respond(w, http.StatusOK, value, err)
}

func (h *Handler) putMemberUpdate(w http.ResponseWriter, r *http.Request) {
	var change identity.MemberChange
	if !decode(w, r, &change) {
		return
	}
	receipt, created, err := h.store.UpdateMemberOnce(r.Context(), r.PathValue("organizationId"), r.PathValue("memberId"), r.PathValue("updateId"), change)
	status := http.StatusOK
	if err == nil && created {
		status = http.StatusCreated
		w.Header().Set("Location", "/v1/organizations/"+receipt.OrganizationID+"/members/"+receipt.MemberID+"/updates/"+receipt.ID)
	}
	respond(w, status, receipt, err)
}
