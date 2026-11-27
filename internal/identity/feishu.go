package identity

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zhizhun-tech/memberid/internal/feishu"
)

type FeishuProvider interface {
	CheckAuthorization(context.Context, string, string) error
	Membership(context.Context, string, string, string) (bool, error)
	Login(context.Context, string, string, string, string, string) (feishu.Profile, error)
}

type FeishuApplications struct {
	store    *Store
	cipher   cipher.AEAD
	provider FeishuProvider
}

func NewFeishuApplications(store *Store, key []byte, provider FeishuProvider) (*FeishuApplications, error) {
	if store == nil || provider == nil {
		return nil, ErrInvalid
	}
	encrypted, err := providerCipher(key)
	if err != nil {
		return nil, err
	}
	return &FeishuApplications{store, encrypted, provider}, nil
}

type feishuApplication struct {
	Provider
	organizationID        string
	authorizationRevision int64
	ciphertext            []byte
}

const feishuColumns = "namespace,display_name,tenant_key,client_id,enabled,authorization_status,revision,created_at,organization_id,authorization_revision,secret_ciphertext"

func readFeishu(row pgx.Row) (feishuApplication, error) {
	app := feishuApplication{Provider: Provider{Type: "feishu"}}
	err := row.Scan(&app.ID, &app.DisplayName, &app.TenantID, &app.ClientID, &app.Enabled, &app.AuthorizationStatus, &app.Revision, &app.CreatedAt, &app.organizationID, &app.authorizationRevision, &app.ciphertext)
	app.CreatedAt = app.CreatedAt.UTC()
	return app, storageError(err)
}

func feishuAAD(app feishuApplication) []byte {
	data, _ := json.Marshal([]string{"MemberID Feishu credential v1", app.organizationID, app.ID, app.TenantID, app.ClientID, strconv.FormatInt(app.Revision, 10)})
	return data
}

func (apps *FeishuApplications) secret(app feishuApplication) (string, error) {
	secret, err := apps.cipher.Open(nil, nil, app.ciphertext, feishuAAD(app))
	if err != nil {
		return "", ErrProviderConfiguration
	}
	return string(secret), nil
}

func (apps *FeishuApplications) lookup(ctx context.Context, db queryer, organizationID, namespace string) (feishuApplication, error) {
	return readFeishu(db.QueryRow(ctx, "SELECT "+feishuColumns+" FROM feishu_applications WHERE organization_id=$1 AND namespace=$2", organizationID, namespace))
}

func (apps *FeishuApplications) configure(ctx context.Context, principal Principal, organizationID, namespace string, input ProviderInput) (Provider, error) {
	if principal.kind != memberPrincipal {
		return Provider{}, ErrForbidden
	}
	if !validProviderInput(organizationID, namespace, input, true) || organizationID == SystemOrganizationID ||
		!feishu.ValidApplication(input.TenantID, input.ClientID) || input.ClientSecret != "" && !feishu.ValidSecret(input.ClientSecret) {
		return Provider{}, ErrInvalid
	}
	organization, err := apps.store.Organization(ctx, organizationID)
	if err != nil {
		return Provider{}, err
	}
	if organization.Status != "enabled" {
		return Provider{}, ErrIneligible
	}
	current := feishuApplication{organizationID: organizationID}
	if namespace != "" {
		current, err = apps.lookup(ctx, apps.store.pool, organizationID, namespace)
		if err != nil {
			return Provider{}, err
		}
		if current.Revision != input.ExpectedRevision || current.ClientID != input.ClientID || current.TenantID != input.TenantID {
			return Provider{}, ErrConflict
		}
	} else if input.ExpectedRevision != 0 || input.ClientSecret == "" {
		return Provider{}, ErrInvalid
	} else {
		current.Provider = Provider{ID: rand.Text(), Type: "feishu", TenantID: input.TenantID, ClientID: input.ClientID}
	}

	candidate := current
	candidate.DisplayName, candidate.Enabled = input.DisplayName, *input.Enabled
	candidate.Revision++
	secret := input.ClientSecret
	checked := secret != ""
	if checked {
		if err := apps.provider.CheckAuthorization(ctx, candidate.ClientID, secret); err != nil {
			return Provider{}, ErrProviderUnavailable
		}
	} else {
		secret, err = apps.secret(current)
		if err != nil {
			return Provider{}, err
		}
	}
	encrypted := apps.cipher.Seal(nil, nil, []byte(secret), feishuAAD(candidate))
	credentialsUpdated := false
	if namespace != "" && checked {
		previousSecret, err := apps.secret(current)
		if err != nil {
			return Provider{}, err
		}
		credentialsUpdated = previousSecret != secret
	}
	var result feishuApplication
	err = pgx.BeginFunc(ctx, apps.store.pool, func(tx pgx.Tx) error {
		before, err := lockProviderManagement(ctx, tx, principal, organization, current.Enabled && !candidate.Enabled, providerWriteRequirements(organizationID, "feishu", namespace, input.Enabled != nil)...)
		if err != nil {
			return err
		}
		if namespace == "" {
			result, err = readFeishu(tx.QueryRow(ctx, `INSERT INTO feishu_applications
 (organization_id,namespace,display_name,enabled,tenant_key,client_id,revision,secret_ciphertext)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+feishuColumns, organizationID, candidate.ID, candidate.DisplayName, candidate.Enabled, candidate.TenantID, candidate.ClientID, candidate.Revision, encrypted))
		} else {
			result, err = readFeishu(tx.QueryRow(ctx, `UPDATE feishu_applications SET display_name=$3,enabled=$4,revision=$5,secret_ciphertext=$6,
 authorization_status=CASE WHEN $7 THEN 'active' ELSE authorization_status END,
 authorization_revision=authorization_revision+CASE WHEN $7 THEN 1 ELSE 0 END,updated_at=clock_timestamp()
 WHERE organization_id=$1 AND namespace=$2 AND revision=$8 AND authorization_revision=$9 RETURNING `+feishuColumns,
				organizationID, namespace, candidate.DisplayName, candidate.Enabled, candidate.Revision, encrypted, checked, current.Revision, current.authorizationRevision))
			if errors.Is(err, ErrNotFound) {
				return ErrConflict
			}
		}
		if err != nil {
			return err
		}
		return finishProviderManagement(ctx, tx, principal, organizationID, current.Provider, result.Provider, credentialsUpdated, before)
	})
	return result.Provider, err
}

type FeishuLoginContext struct {
	OrganizationID        string `json:"organizationId"`
	ProviderID            string `json:"providerId"`
	Revision              int64  `json:"revision"`
	AuthorizationRevision int64  `json:"authorizationRevision"`
	OrganizationRevision  int64  `json:"organizationRevision"`
}

func (apps *FeishuApplications) LoginSource(ctx context.Context, organizationID, namespace string) (Provider, FeishuLoginContext, error) {
	organization, err := apps.store.Organization(ctx, organizationID)
	if err != nil {
		return Provider{}, FeishuLoginContext{}, err
	}
	app, err := apps.lookup(ctx, apps.store.pool, organizationID, namespace)
	if err != nil {
		return Provider{}, FeishuLoginContext{}, err
	}
	if organization.Status != "enabled" || !app.Enabled || app.AuthorizationStatus != "active" {
		return Provider{}, FeishuLoginContext{}, ErrIneligible
	}
	return app.Provider, FeishuLoginContext{organizationID, namespace, app.Revision, app.authorizationRevision, organization.lifecycleRevision}, nil
}

type FeishuProof struct {
	applications         *FeishuApplications
	login                FeishuLoginContext
	profile              feishu.Profile
	authenticatedAt      time.Time
	membership           *feishuMembershipSnapshot
	membershipVerifiedAt time.Time
}

func (apps *FeishuApplications) Verify(ctx context.Context, login FeishuLoginContext, callback, code, verifier string) (FeishuProof, error) {
	organization, err := apps.store.Organization(ctx, login.OrganizationID)
	if err != nil {
		return FeishuProof{}, err
	}
	if organization.Status != "enabled" || organization.lifecycleRevision != login.OrganizationRevision {
		return FeishuProof{}, ErrIneligible
	}
	app, err := apps.lookup(ctx, apps.store.pool, login.OrganizationID, login.ProviderID)
	if err != nil {
		return FeishuProof{}, err
	}
	if !app.Enabled || app.AuthorizationStatus != "active" || app.Revision != login.Revision || app.authorizationRevision != login.AuthorizationRevision {
		return FeishuProof{}, ErrConflict
	}
	secret, err := apps.secret(app)
	if err != nil {
		return FeishuProof{}, err
	}
	timeout, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	profile, err := apps.provider.Login(timeout, app.ClientID, secret, callback, code, verifier)
	if errors.Is(err, feishu.ErrAuthorizationDenied) {
		// The browser's code does not attest to the expected tenant. Confirm
		// application-level denial with the self-built application's credentials.
		apps.checkAuthorization(ctx, app, secret, login.OrganizationRevision)
	}
	if err != nil {
		if errors.Is(err, feishu.ErrAuthorizationDenied) {
			return FeishuProof{}, ErrIneligible
		}
		return FeishuProof{}, ErrProviderUnavailable
	}
	if profile.TenantKey != app.TenantID || !validText(profile.OpenID, 256) {
		return FeishuProof{}, ErrIneligible
	}
	proof := FeishuProof{applications: apps, login: login, profile: profile, authenticatedAt: time.Now().UTC()}
	var bindingID string
	err = apps.store.pool.QueryRow(ctx, `SELECT b.id::text FROM member_auth_factor_bindings b JOIN authentication_factors f ON f.id=b.authentication_factor_id
 WHERE b.organization_id=$1 AND f.type='feishu' AND f.namespace=$2 AND f.subject=$3`, login.OrganizationID, login.ProviderID, profile.OpenID).Scan(&bindingID)
	if errors.Is(err, pgx.ErrNoRows) {
		return proof, nil
	}
	if err != nil {
		return FeishuProof{}, err
	}
	snapshot, err := readFeishuMembership(ctx, apps.store.pool, bindingID, false)
	if err != nil {
		return FeishuProof{}, err
	}
	snapshot, departed, err := apps.observeMembership(ctx, snapshot)
	if err != nil {
		return FeishuProof{}, ErrProviderUnavailable
	}
	if departed {
		return FeishuProof{}, ErrIneligible
	}
	proof.membership = &snapshot
	proof.membershipVerifiedAt = time.Now().UTC()
	return proof, nil
}

// Check observed application credentials without holding a database lock.
func (apps *FeishuApplications) checkAuthorization(ctx context.Context, app feishuApplication, secret string, lifecycle int64) error {
	status := "active"
	timeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := apps.provider.CheckAuthorization(timeout, app.ClientID, secret)
	if errors.Is(err, feishu.ErrAuthorizationDenied) {
		status = "revoked"
	} else if err != nil {
		return ErrProviderUnavailable
	}
	if status == app.AuthorizationStatus {
		return nil
	}
	return pgx.BeginFunc(ctx, apps.store.pool, func(tx pgx.Tx) error {
		org, err := readOrganization(tx.QueryRow(ctx, "SELECT "+organizationColumns+" FROM organizations WHERE id=$1 FOR UPDATE", app.organizationID))
		if err != nil {
			return err
		}
		if org.Status != "enabled" || org.lifecycleRevision != lifecycle {
			return ErrConflict
		}
		tag, err := tx.Exec(ctx, `UPDATE feishu_applications SET authorization_status=$3,
 authorization_revision=authorization_revision+1,updated_at=clock_timestamp()
 WHERE organization_id=$1 AND namespace=$2 AND enabled AND revision=$4 AND authorization_revision=$5`, org.ID, app.ID, status, app.Revision, app.authorizationRevision)
		if err == nil && tag.RowsAffected() != 1 {
			return ErrConflict
		}
		return err
	})
}

func (apps *FeishuApplications) CheckApplications(ctx context.Context) error {
	rows, err := apps.store.pool.Query(ctx, `SELECT a.organization_id,a.namespace,o.lifecycle_revision
 FROM feishu_applications a JOIN organizations o ON o.id=a.organization_id
 WHERE a.enabled AND o.status='enabled' ORDER BY a.namespace`)
	if err != nil {
		return err
	}
	type source struct {
		OrganizationID, Namespace string
		Lifecycle                 int64
	}
	sources, err := pgx.CollectRows(rows, pgx.RowToStructByPos[source])
	if err != nil {
		return err
	}
	var failure error
	for _, source := range sources {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		app, err := apps.lookup(ctx, apps.store.pool, source.OrganizationID, source.Namespace)
		if err == nil && app.Enabled {
			var secret string
			secret, err = apps.secret(app)
			if err == nil {
				err = apps.checkAuthorization(ctx, app, secret, source.Lifecycle)
			}
		}
		if err != nil {
			failure = ErrProviderUnavailable
		}
	}
	return failure
}

// Link uses the caller's locked, single-use account transaction. It cannot
// replace an occupied application slot, restore revocation, or transfer identity.
func (apps *FeishuApplications) Link(ctx context.Context, tx pgx.Tx, principal Principal, proof FeishuProof, memberID string) (MemberAdmission, error) {
	if principal.kind != accountPrincipal {
		return MemberAdmission{}, ErrForbidden
	}
	if !ValidID(memberID, MemberKind) {
		return MemberAdmission{}, ErrInvalid
	}
	if err := authorizeAll(ctx, tx, principal, bindingsResource.require(actionCreate, proof.login.OrganizationID, memberID)); err != nil {
		return MemberAdmission{}, err
	}
	return apps.admit(ctx, tx, proof, &principal, memberID)
}

func (apps *FeishuApplications) Admit(ctx context.Context, tx pgx.Tx, proof FeishuProof) (MemberAdmission, error) {
	return apps.admit(ctx, tx, proof, nil, "")
}

func (apps *FeishuApplications) admit(ctx context.Context, tx pgx.Tx, proof FeishuProof, source *Principal, targetID string) (MemberAdmission, error) {
	login := proof.login
	if proof.applications != apps || proof.authenticatedAt.IsZero() || proof.authenticatedAt.After(time.Now()) || !proof.authenticatedAt.Add(5*time.Minute).After(time.Now()) || login.OrganizationID == SystemOrganizationID {
		return MemberAdmission{}, ErrIneligible
	}
	org, err := readOrganization(tx.QueryRow(ctx, "SELECT "+organizationColumns+" FROM organizations WHERE id=$1 FOR UPDATE", login.OrganizationID))
	if err != nil {
		return MemberAdmission{}, err
	}
	app, err := apps.lookup(ctx, tx, org.ID, login.ProviderID)
	if err != nil {
		return MemberAdmission{}, err
	}
	if org.Status != "enabled" || org.lifecycleRevision != login.OrganizationRevision || !app.Enabled || app.AuthorizationStatus != "active" || app.Revision != login.Revision || app.authorizationRevision != login.AuthorizationRevision {
		return MemberAdmission{}, ErrIneligible
	}
	if source != nil {
		var id string
		if err := tx.QueryRow(ctx, "SELECT id FROM authentication_factors WHERE id=$1 AND status='active' FOR SHARE", source.factorID).Scan(&id); err != nil {
			return MemberAdmission{}, linkEligibilityError(err)
		}
		if err := tx.QueryRow(ctx, "SELECT id::text FROM member_auth_factor_bindings WHERE id=$1 AND member_id=$2 AND organization_id=$3 AND authentication_factor_id=$4 AND status='active' FOR SHARE", source.bindingID, targetID, org.ID, source.factorID).Scan(&id); err != nil {
			return MemberAdmission{}, linkEligibilityError(err)
		}
		if err := tx.QueryRow(ctx, "SELECT id FROM members WHERE id=$1 AND organization_id=$2 AND NOT manual_block AND NOT external_departure FOR UPDATE", targetID, org.ID).Scan(&id); err != nil {
			return MemberAdmission{}, linkEligibilityError(err)
		}
		binding, err := MemberEvidence(ctx, tx, source.factorID, targetID, org.ID)
		if err != nil {
			return MemberAdmission{}, linkEligibilityError(err)
		}
		if binding != source.bindingID {
			return MemberAdmission{}, ErrIneligible
		}
	}
	factor, err := ensureFactor(ctx, tx, "feishu", app.ID, proof.profile.OpenID)
	if err != nil {
		return MemberAdmission{}, err
	}
	binding, err := readBinding(tx.QueryRow(ctx, "SELECT "+bindingColumns+" FROM member_auth_factor_bindings WHERE organization_id=$1 AND authentication_factor_id=$2 FOR UPDATE", org.ID, factor.ID))
	if source != nil && err == nil {
		return MemberAdmission{}, ErrConflict
	}
	if errors.Is(err, ErrNotFound) {
		id := targetID
		if source == nil {
			id, err = NewID(MemberKind)
			if err != nil {
				return MemberAdmission{}, err
			}
			name := proof.profile.Name
			if !validText(name, 128) {
				name = "Member"
			}
			if _, err := tx.Exec(ctx, "INSERT INTO members(id,organization_id,display_name) VALUES($1,$2,$3)", id, org.ID, name); err != nil {
				return MemberAdmission{}, storageError(err)
			}
		}
		binding, err = readBinding(tx.QueryRow(ctx, `INSERT INTO member_auth_factor_bindings(member_id,organization_id,authentication_factor_id,factor_type,provider_namespace)
 VALUES($1,$2,$3,'feishu',$4) RETURNING `+bindingColumns, id, org.ID, factor.ID, app.ID))
		if err != nil {
			return MemberAdmission{}, storageError(err)
		}
	} else {
		if err != nil {
			return MemberAdmission{}, err
		}
		if proof.membership == nil || !proof.membershipVerifiedAt.Add(time.Minute).After(time.Now()) {
			return MemberAdmission{}, ErrConflict
		}
		current, err := readFeishuMembership(ctx, tx, binding.ID, true)
		if err != nil {
			return MemberAdmission{}, err
		}
		if current != *proof.membership {
			return MemberAdmission{}, ErrConflict
		}
		if _, err := MemberEvidence(ctx, tx, factor.ID, binding.MemberID, org.ID); err != nil {
			return MemberAdmission{}, err
		}
	}
	if _, err := tx.Exec(ctx, "INSERT INTO feishu_memberships(binding_id) VALUES($1) ON CONFLICT DO NOTHING", binding.ID); err != nil {
		return MemberAdmission{}, err
	}
	return MemberAdmission{Verification: Verification{Factor: factor, AuthenticatedAt: proof.authenticatedAt, Method: "feishu"}, OrganizationID: org.ID, MemberID: binding.MemberID, BindingID: binding.ID}, nil
}
