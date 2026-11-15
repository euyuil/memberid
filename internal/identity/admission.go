package identity

// MemberAdmission is the result of a Member admission/link transaction. It is
// provisional until the caller commits. Only Verification is stored in SSO;
// the Member references are contextual results, not shared-session authority.
type MemberAdmission struct {
	Verification
	OrganizationID, MemberID, BindingID string
}
