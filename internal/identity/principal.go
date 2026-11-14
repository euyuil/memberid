package identity

type principalKind uint8

const (
	memberPrincipal principalKind = iota + 1
	installationManagerPrincipal
	operatorPrincipal
	accountPrincipal
)

// Principal identifies a server-authenticated caller, not a role or permission
// snapshot. Its zero value grants no access. It is never decoded from HTTP input.
type Principal struct {
	kind                           principalKind
	memberID, grantID              string
	sessionID, factorID, bindingID string
}

// Principal retains the authenticated identity reference. Authorization resolves
// current membership, grant, session, and assignments from server-side state.
func (actor ManagementActor) Principal() Principal {
	if !ValidID(actor.MemberID, MemberKind) || actor.GrantID == "" {
		return Principal{}
	}
	return Principal{kind: memberPrincipal, memberID: actor.MemberID, grantID: actor.GrantID}
}

// AccountPrincipal retains references from an authenticated SSO session and its
// selected Member binding. Construction is not authentication: account handlers
// verify the cookie/request and authorization resolves current stored evidence.
// Account context never inherits the Member's administrator permissions.
func AccountPrincipal(sessionID, memberID, factorID, bindingID string) Principal {
	if sessionID == "" || !ValidID(memberID, MemberKind) || !ValidID(factorID, FactorKind) || !ValidUUID(bindingID) {
		return Principal{}
	}
	return Principal{kind: accountPrincipal, memberID: memberID, sessionID: sessionID, factorID: factorID, bindingID: bindingID}
}

// InstallationManagerPrincipal is used only after the private listener validates
// its installation credential. It does not represent an end-user Member.
func InstallationManagerPrincipal() Principal {
	return Principal{kind: installationManagerPrincipal}
}

// OperatorPrincipal marks trusted in-process operator commands and provisioning.
// HTTP callers cannot select this identity through a request field or token claim.
func OperatorPrincipal() Principal {
	return Principal{kind: operatorPrincipal}
}

func (principal Principal) installation() bool {
	return principal.kind == installationManagerPrincipal || principal.kind == operatorPrincipal
}

func (principal Principal) auditID() (string, error) {
	switch principal.kind {
	case memberPrincipal:
		if ValidID(principal.memberID, MemberKind) && principal.grantID != "" {
			return principal.memberID, nil
		}
	case installationManagerPrincipal:
		return "installation-manager", nil
	case operatorPrincipal:
		return "installation-operator", nil
	}
	return "", ErrForbidden
}
