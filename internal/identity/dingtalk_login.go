package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/euyuil/memberid/internal/dingtalk"
	"github.com/jackc/pgx/v5"
)

type DingTalkLoginProvider interface {
	Login(context.Context, string, string, string, string) (dingtalk.Member, error)
}

// DingTalkLoginContext binds an attempt to current policy revisions; it is not authentication evidence.
type DingTalkLoginContext struct {
	OrganizationID        string `json:"organizationId"`
	ApplicationRevision   int64  `json:"applicationRevision"`
	AuthorizationRevision int64  `json:"authorizationRevision"`
	OrganizationRevision  int64  `json:"organizationRevision"`
}

func (app DingTalkApplication) LoginContext() DingTalkLoginContext {
	return DingTalkLoginContext{app.OrganizationID, app.Revision, app.AuthorizationRevision, app.organizationRevision}
}

type DingTalkVerifier struct {
	applications *DingTalkApplications
	provider     DingTalkLoginProvider
	now          func() time.Time
}

// DingTalkLoginProof can only be produced after a successful provider exchange.
// It is local evidence, cannot be serialized into a login credential, and expires after five minutes.
type DingTalkLoginProof struct {
	verifier        *DingTalkVerifier
	application     DingTalkApplication
	member          dingtalk.Member
	authenticatedAt time.Time
}

func NewDingTalkVerifier(applications *DingTalkApplications, provider DingTalkLoginProvider) (*DingTalkVerifier, error) {
	if applications == nil || provider == nil {
		return nil, ErrInvalid
	}
	return &DingTalkVerifier{applications, provider, time.Now}, nil
}

func (verifier *DingTalkVerifier) Application(ctx context.Context, organizationID string) (DingTalkApplication, error) {
	organization, err := verifier.applications.store.Organization(ctx, organizationID)
	if err != nil {
		return DingTalkApplication{}, err
	}
	if organization.Status != "enabled" {
		return DingTalkApplication{}, ErrIneligible
	}
	app, err := verifier.applications.Inspect(ctx, organizationID)
	if err != nil {
		return DingTalkApplication{}, err
	}
	if app.AuthorizationStatus != "active" {
		return DingTalkApplication{}, ErrIneligible
	}
	app.organizationRevision = organization.lifecycleRevision
	return app, nil
}

func (verifier *DingTalkVerifier) Verify(ctx context.Context, login DingTalkLoginContext, code string) (DingTalkLoginProof, error) {
	app, err := verifier.applications.Load(ctx, login.OrganizationID)
	if err != nil {
		return DingTalkLoginProof{}, err
	}
	if app.Revision != login.ApplicationRevision || app.AuthorizationRevision != login.AuthorizationRevision {
		return DingTalkLoginProof{}, ErrConflict
	}
	organization, err := verifier.applications.store.Organization(ctx, login.OrganizationID)
	if err != nil {
		return DingTalkLoginProof{}, err
	}
	if organization.Status != "enabled" || organization.lifecycleRevision != login.OrganizationRevision || app.AuthorizationStatus != "active" {
		return DingTalkLoginProof{}, ErrIneligible
	}
	timeout, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	member, err := verifier.provider.Login(timeout, app.CorpID, app.ClientID, app.Secret, code)
	if errors.Is(err, dingtalk.ErrAuthorizationDenied) {
		if _, recordErr := verifier.applications.recordAuthorization(ctx, app.DingTalkApplication, organization.lifecycleRevision, "revoked"); recordErr != nil {
			return DingTalkLoginProof{}, recordErr
		}
		return DingTalkLoginProof{}, ErrIneligible
	}
	if err != nil || !validText(member.UnionID, 512) || !validText(member.UserID, 512) {
		return DingTalkLoginProof{}, ErrProviderUnavailable
	}
	app.organizationRevision = organization.lifecycleRevision
	return DingTalkLoginProof{verifier, app.DingTalkApplication, member, verifier.now().UTC().Truncate(time.Second)}, nil
}

// Admit participates in the caller's authentication transaction, so Member admission and session creation commit together.
// Caller cancellation or a superseded authorization request must roll this transaction back.
func (verifier *DingTalkVerifier) Admit(ctx context.Context, tx pgx.Tx, proof DingTalkLoginProof) (Verification, error) {
	return verifier.admit(ctx, tx, proof, nil)
}

type dingTalkLinkTarget struct{ memberID, factorID, bindingID string }

// Link attaches freshly verified DingTalk evidence to an existing eligible Member.
// The caller must authenticate the source session and commit this operation with
// its single-use account transaction. It never merges or replaces identities.
func (verifier *DingTalkVerifier) Link(ctx context.Context, tx pgx.Tx, proof DingTalkLoginProof, memberID, sourceFactorID, sourceBindingID string) (Verification, error) {
	if !ValidID(memberID, MemberKind) || !ValidID(sourceFactorID, FactorKind) || !ValidUUID(sourceBindingID) {
		return Verification{}, ErrInvalid
	}
	return verifier.admit(ctx, tx, proof, &dingTalkLinkTarget{memberID, sourceFactorID, sourceBindingID})
}

func (verifier *DingTalkVerifier) admit(ctx context.Context, tx pgx.Tx, proof DingTalkLoginProof, target *dingTalkLinkTarget) (Verification, error) {
	if proof.verifier != verifier || proof.authenticatedAt.IsZero() || proof.authenticatedAt.After(verifier.now()) || !proof.authenticatedAt.Add(5*time.Minute).After(verifier.now()) {
		return Verification{}, ErrIneligible
	}
	app := proof.application
	organization, err := readOrganization(tx.QueryRow(ctx, "SELECT "+organizationColumns+" FROM organizations WHERE id=$1 FOR UPDATE", app.OrganizationID))
	if err != nil {
		return Verification{}, err
	}
	if organization.Status != "enabled" || organization.lifecycleRevision != app.organizationRevision {
		return Verification{}, ErrIneligible
	}
	current, _, err := readApplication(tx.QueryRow(ctx, "SELECT "+applicationColumns+" FROM dingtalk_applications WHERE organization_id=$1 FOR UPDATE", app.OrganizationID))
	if err != nil {
		return Verification{}, err
	}
	if current.Revision != app.Revision || current.AuthorizationRevision != app.AuthorizationRevision || current.directoryRevision != app.directoryRevision || current.AuthorizationStatus != "active" || current.Namespace != app.Namespace || current.CorpID != app.CorpID || current.ClientID != app.ClientID {
		return Verification{}, ErrConflict
	}
	rows, err := tx.Query(ctx, "SELECT member_id,union_id FROM dingtalk_identities WHERE organization_id=$1 AND (union_id=$2 OR external_member_id=$3) FOR UPDATE", app.OrganizationID, proof.member.UnionID, proof.member.UserID)
	if err != nil {
		return Verification{}, err
	}
	var memberID, unionID string
	count := 0
	for rows.Next() {
		count++
		if err = rows.Scan(&memberID, &unionID); err != nil {
			break
		}
	}
	rows.Close()
	if err != nil {
		return Verification{}, err
	}
	if rows.Err() != nil {
		return Verification{}, rows.Err()
	}
	if count > 1 || count == 1 && unionID != proof.member.UnionID {
		return Verification{}, ErrConflict
	}
	if target != nil {
		if memberID != "" && memberID != target.memberID {
			return Verification{}, ErrConflict
		}
		// Lock the source factor before target factor/binding/member locks. Operator
		// factor updates and binding revocation cannot race a successful link.
		var id string
		if err := tx.QueryRow(ctx, "SELECT id FROM authentication_factors WHERE id=$1 AND status='active' FOR SHARE", target.factorID).Scan(&id); err != nil {
			return Verification{}, ErrIneligible
		}
		if err := tx.QueryRow(ctx, "SELECT id::text FROM member_auth_factor_bindings WHERE id=$1 AND member_id=$2 AND organization_id=$3 AND authentication_factor_id=$4 AND status='active' FOR SHARE", target.bindingID, target.memberID, app.OrganizationID, target.factorID).Scan(&id); err != nil {
			return Verification{}, ErrIneligible
		}
	}
	factor, err := ensureFactor(ctx, tx, "dingtalk", app.Namespace, proof.member.UnionID)
	if err != nil {
		return Verification{}, err
	}
	bound, err := readBinding(tx.QueryRow(ctx, "SELECT "+bindingColumns+" FROM member_auth_factor_bindings WHERE organization_id=$1 AND authentication_factor_id=$2 FOR UPDATE", app.OrganizationID, factor.ID))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Verification{}, err
	}
	if err == nil {
		if bound.Status != "active" || memberID != "" && memberID != bound.MemberID {
			return Verification{}, ErrConflict
		}
		memberID = bound.MemberID
	}
	if target != nil {
		if memberID != "" && memberID != target.memberID {
			return Verification{}, ErrConflict
		}
		memberID = target.memberID
	}
	if memberID == "" {
		memberID, err = NewID(MemberKind)
		if err != nil {
			return Verification{}, err
		}
		name := proof.member.DisplayName
		if !validText(name, 128) {
			name = "Member"
		}
		if _, err := tx.Exec(ctx, "INSERT INTO members(id,organization_id,display_name) VALUES($1,$2,$3)", memberID, app.OrganizationID, name); err != nil {
			return Verification{}, storageError(err)
		}
	} else {
		member, err := readMember(tx.QueryRow(ctx, "SELECT "+memberColumns+" FROM members WHERE id=$1 AND organization_id=$2 FOR UPDATE", memberID, app.OrganizationID))
		if err != nil {
			return Verification{}, err
		}
		if target != nil {
			bindingID, err := MemberEvidence(ctx, tx, target.factorID, memberID, app.OrganizationID)
			if err != nil || bindingID != target.bindingID {
				return Verification{}, ErrIneligible
			}
		}
		for _, source := range member.BlockSources {
			if source == "manual" {
				return Verification{}, ErrIneligible
			}
		}
		if _, err := tx.Exec(ctx, "UPDATE members SET external_departure=false,eligibility_revision=eligibility_revision+1,updated_at=CASE WHEN external_departure THEN clock_timestamp() ELSE updated_at END WHERE id=$1", memberID); err != nil {
			return Verification{}, err
		}
	}
	if _, err := tx.Exec(ctx, "INSERT INTO member_auth_factor_bindings(member_id,organization_id,authentication_factor_id,factor_type) VALUES($1,$2,$3,'dingtalk') ON CONFLICT DO NOTHING", memberID, app.OrganizationID, factor.ID); err != nil {
		return Verification{}, storageError(err)
	}
	bound, err = readBinding(tx.QueryRow(ctx, "SELECT "+bindingColumns+" FROM member_auth_factor_bindings WHERE member_id=$1 AND factor_type='dingtalk'", memberID))
	if err != nil {
		return Verification{}, err
	}
	if bound.OrganizationID != app.OrganizationID || bound.FactorID != factor.ID || bound.Status != "active" {
		return Verification{}, ErrConflict
	}
	var departments []byte
	if proof.member.DepartmentIDs != nil {
		departments, err = json.Marshal(proof.member.DepartmentIDs)
		if err != nil {
			return Verification{}, err
		}
	}
	if count == 0 {
		_, err = tx.Exec(ctx, "INSERT INTO dingtalk_identities(member_id,organization_id,union_id,external_member_id,department_ids,verified_at) VALUES($1,$2,$3,$4,$5,$6)", memberID, app.OrganizationID, proof.member.UnionID, proof.member.UserID, departments, proof.authenticatedAt)
	} else {
		_, err = tx.Exec(ctx, "UPDATE dingtalk_identities SET external_member_id=$2,department_ids=COALESCE($3::jsonb,department_ids),verified_at=$4 WHERE member_id=$1", memberID, proof.member.UserID, departments, proof.authenticatedAt)
	}
	if err != nil {
		return Verification{}, storageError(err)
	}
	return Verification{Factor: factor, AuthenticatedAt: proof.authenticatedAt, Method: "dingtalk"}, nil
}
