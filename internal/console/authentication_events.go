package console

import (
	"net/http"
	"strconv"

	"github.com/zhizhun-tech/memberid/internal/identity"
)

func (s *Service) authenticationEvents(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limit := 50
	if query.Get("limit") != "" {
		value, err := strconv.Atoi(query.Get("limit"))
		if err != nil {
			problem(w, 400, "invalid_request")
			return
		}
		limit = value
	}
	principal := r.Context().Value(sessionKey{}).(session).principal()
	page, err := s.management.AuthenticationEvents(r.Context(), principal, r.PathValue("organizationId"), identity.AuthenticationEventFilter{
		Type: query.Get("type"), Outcome: query.Get("outcome"), Method: query.Get("method"),
		MemberID: query.Get("memberId"), ClientID: query.Get("clientId"), GrantID: query.Get("grantId"),
		RequestID: query.Get("requestId"), InteractionID: query.Get("interactionId"),
		From: query.Get("from"), To: query.Get("to"), After: query.Get("after"), Limit: limit,
	})
	respond(w, page, err)
}

func (s *Service) authenticationEvent(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(sessionKey{}).(session).principal()
	event, err := s.management.AuthenticationEvent(r.Context(), principal, r.PathValue("organizationId"), r.PathValue("eventId"))
	respond(w, event, err)
}
