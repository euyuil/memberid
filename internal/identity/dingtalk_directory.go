package identity

import (
	"context"
	"errors"
	"time"

	"github.com/euyuil/memberid/internal/dingtalk"
	"github.com/jackc/pgx/v5"
)

type DingTalkDirectoryProvider interface {
	VerifyMember(context.Context, string, string, string, string) (dingtalk.Member, error)
}

type DingTalkDirectory struct {
	applications *DingTalkApplications
	provider     DingTalkDirectoryProvider
	now          func() time.Time
}

func NewDingTalkDirectory(applications *DingTalkApplications, provider DingTalkDirectoryProvider) (*DingTalkDirectory, error) {
	if applications == nil || provider == nil {
		return nil, ErrInvalid
	}
	return &DingTalkDirectory{applications, provider, time.Now}, nil
}

type directorySnapshot struct {
	organizationRevision, memberRevision, applicationRevision, authorizationRevision                        int64
	authorizationStatus, namespace, bindingID, factorID, factorNamespace, factorStatus, unionID, employeeID string
	manualBlocked, externalDeparture                                                                        bool
}

func readDirectorySnapshot(ctx context.Context, database queryer, organizationID, memberID string) (directorySnapshot, error) {
	var value directorySnapshot
	err := database.QueryRow(ctx, `SELECT o.lifecycle_revision,m.eligibility_revision,
 COALESCE(a.revision,0),COALESCE(a.authorization_revision,0),COALESCE(a.authorization_status,''),COALESCE(a.namespace,''),
 COALESCE(b.id::text,''),COALESCE(f.id,''),COALESCE(f.namespace,''),COALESCE(f.status,''),COALESCE(i.union_id,''),COALESCE(i.external_member_id,''),m.manual_block,m.external_departure
 FROM members m JOIN organizations o ON o.id=m.organization_id
 LEFT JOIN dingtalk_applications a ON a.organization_id=o.id
 LEFT JOIN member_auth_factor_bindings b ON b.member_id=m.id AND b.factor_type='dingtalk' AND b.status='active'
 LEFT JOIN authentication_factors f ON f.id=b.authentication_factor_id
 LEFT JOIN dingtalk_identities i ON i.member_id=m.id AND i.organization_id=o.id
 WHERE m.id=$1 AND o.id=$2 AND o.status='enabled'`, memberID, organizationID).Scan(
		&value.organizationRevision, &value.memberRevision, &value.applicationRevision, &value.authorizationRevision, &value.authorizationStatus, &value.namespace,
		&value.bindingID, &value.factorID, &value.factorNamespace, &value.factorStatus, &value.unionID, &value.employeeID, &value.manualBlocked, &value.externalDeparture)
	if errors.Is(err, pgx.ErrNoRows) {
		return value, ErrIneligible
	}
	if err == nil && value.authorizationStatus == "revoked" {
		return value, ErrIneligible
	}
	return value, err
}

// DingTalkDirectoryObservation is short-lived local evidence, not a serializable credential.
// Validate must run in the transaction that issues the tokens it protects.
type DingTalkDirectoryObservation struct {
	directory                *DingTalkDirectory
	organizationID, memberID string
	snapshot                 directorySnapshot
	observedAt               time.Time
}

// Observe performs provider I/O before the token transaction. Unknown provider failures allow
// an otherwise eligible phone identity to continue; definitive contradictions never do.
func (directory *DingTalkDirectory) Observe(ctx context.Context, organizationID, memberID, factorType string) (*DingTalkDirectoryObservation, error) {
	if !ValidID(organizationID, OrganizationKind) || !ValidID(memberID, MemberKind) || !validFactorType(factorType) {
		return nil, ErrInvalid
	}
	snapshot, err := readDirectorySnapshot(ctx, directory.applications.store.pool, organizationID, memberID)
	if err != nil {
		return nil, err
	}
	if snapshot.manualBlocked || snapshot.externalDeparture {
		return nil, ErrIneligible
	}
	observation := &DingTalkDirectoryObservation{directory, organizationID, memberID, snapshot, directory.now()}
	if snapshot.bindingID == "" || snapshot.unionID == "" && snapshot.employeeID == "" {
		if factorType == "dingtalk" {
			return nil, ErrIneligible
		}
		return observation, nil
	}
	if snapshot.authorizationStatus != "active" || snapshot.namespace != snapshot.factorNamespace || snapshot.unionID == "" || snapshot.employeeID == "" {
		return nil, ErrIneligible
	}
	app, err := directory.applications.Load(ctx, organizationID)
	if errors.Is(err, ErrProviderConfiguration) && factorType == "phone" {
		return observation, nil
	}
	if err != nil {
		return nil, err
	}
	if app.Revision != snapshot.applicationRevision || app.AuthorizationRevision != snapshot.authorizationRevision || app.Namespace != snapshot.namespace {
		return nil, ErrConflict
	}
	timeout, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	member, err := directory.provider.VerifyMember(timeout, app.CorpID, app.ClientID, app.Secret, snapshot.unionID)
	if errors.Is(err, dingtalk.ErrAuthorizationDenied) {
		if _, err := directory.applications.recordAuthorization(ctx, app.DingTalkApplication, snapshot.organizationRevision, "revoked"); err != nil {
			return nil, err
		}
		return nil, ErrIneligible
	}
	if errors.Is(err, dingtalk.ErrNotMember) || errors.Is(err, dingtalk.ErrIdentityConflict) {
		return nil, ErrIneligible
	}
	if err != nil {
		if factorType == "phone" {
			return observation, nil
		}
		return nil, ErrProviderUnavailable
	}
	if member.UnionID != snapshot.unionID || member.UserID != snapshot.employeeID {
		return nil, ErrConflict
	}
	observation.observedAt = directory.now()
	return observation, nil
}

func (observation *DingTalkDirectoryObservation) Validate(ctx context.Context, database queryer) error {
	if observation == nil || observation.directory == nil || observation.observedAt.After(observation.directory.now()) || !observation.observedAt.Add(time.Minute).After(observation.directory.now()) {
		return ErrIneligible
	}
	// Event acceptance takes the same organization's exclusive lock. Keep this
	// shared lock until the caller commits token issuance, so departure and
	// issuance have a definite order even after snapshot validation.
	var organizationID string
	if err := database.QueryRow(ctx, "SELECT id FROM organizations WHERE id=$1 FOR SHARE", observation.organizationID).Scan(&organizationID); err != nil {
		return storageError(err)
	}
	current, err := readDirectorySnapshot(ctx, database, observation.organizationID, observation.memberID)
	if err != nil {
		return err
	}
	if current.manualBlocked || current.externalDeparture {
		return ErrIneligible
	}
	if current != observation.snapshot {
		return ErrConflict
	}
	return nil
}
