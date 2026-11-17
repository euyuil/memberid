package console

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/euyuil/memberid/internal/consolestate"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/management"
	"golang.org/x/oauth2"
)

// The caller cannot choose another Member or an arbitrary return destination.
// Linking remains the authentication service's verified self-service flow.
func (s *Service) beginAccountLink(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !management.DecodeRequest(w, r, &input) {
		return
	}
	v := r.Context().Value(sessionKey{}).(session)
	actor, err := s.management.Actor(r.Context(), v.memberID, v.grantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	returnTo := "/organizations/" + actor.OrganizationID + "/members/" + actor.MemberID + "?accountLink=1"
	address, err := s.beginLogin(w, r, consolestate.Login{ReturnTo: returnTo}, oauth2.SetAuthURLParam("login_hint", actor.MemberID), oauth2.SetAuthURLParam("prompt", "login"))
	if err != nil {
		problem(w, 503, "login_unavailable")
		return
	}
	respond(w, map[string]string{"authorizationUrl": address}, nil)
}

func accountLinkMember(returnTo string) string {
	u, err := url.Parse(returnTo)
	if err != nil || !validReturnTo(returnTo) || u.Query().Get("accountLink") != "1" || len(u.Query()) != 1 || len(u.Query()["accountLink"]) != 1 {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "organizations" || parts[2] != "members" || !identity.ValidID(parts[1], identity.OrganizationKind) || !identity.ValidID(parts[3], identity.MemberKind) {
		return ""
	}
	return parts[3]
}
