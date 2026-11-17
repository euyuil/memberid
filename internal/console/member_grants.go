package console

import (
	"net/http"

	"github.com/euyuil/memberid/internal/management"
)

func (s *Service) memberGrants(w http.ResponseWriter, r *http.Request) {
	after, limit, ok := management.DecodePageRequest(w, r)
	if !ok {
		return
	}
	v := r.Context().Value(sessionKey{}).(session)
	page, err := s.management.MemberGrants(r.Context(), v.principal(), r.PathValue("organizationId"), r.PathValue("memberId"), after, limit)
	respond(w, page, err)
}
