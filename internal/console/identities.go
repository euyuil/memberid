package console

import (
	"net/http"

	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/consolestate"
	"github.com/zhizhun-tech/memberid/internal/management"
	"golang.org/x/oauth2"
)

func (s *Service) identities(w http.ResponseWriter, r *http.Request) {
	v := r.Context().Value(sessionKey{}).(session)
	page, err := s.management.ConsoleIdentities(r.Context(), v.principal(), r.URL.Query().Get("after"), 50)
	respond(w, page, err)
}

func (s *Service) switchIdentity(w http.ResponseWriter, r *http.Request) {
	v := r.Context().Value(sessionKey{}).(session)
	var input struct {
		MemberID string `json:"memberId"`
		ReturnTo string `json:"returnTo"`
	}
	if !management.DecodeRequest(w, r, &input) {
		return
	}
	if !validReturnTo(input.ReturnTo) {
		problem(w, 400, "invalid_request")
		return
	}
	if err := s.management.CheckConsoleIdentity(r.Context(), v.principal(), input.MemberID, ""); err != nil {
		respond(w, nil, err)
		return
	}
	login := consolestate.Login{ReturnTo: input.ReturnTo, SwitchMemberID: input.MemberID, SourceSessionHash: config.SecretHash(v.secret)}
	address, err := s.beginLogin(w, r, login, oauth2.SetAuthURLParam("login_hint", input.MemberID), oauth2.SetAuthURLParam("prompt", "none"))
	if err != nil {
		problem(w, 503, "login_unavailable")
		return
	}
	respond(w, map[string]string{"authorizationUrl": address}, nil)
}
