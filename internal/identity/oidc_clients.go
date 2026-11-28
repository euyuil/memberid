package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zhizhun-tech/memberid/internal/authorization"
)

type OIDCClientRegistration struct {
	Client              OIDCClient `json:"-"`
	DisplayName         string
	OwnerOrganizationID string
	Enabled             bool
	Published           bool
	System              bool
	Revision            int64
}

// OIDCApplication contains only registration information safe to show to an
// administrator. Credential verifiers are never part of this projection.
type OIDCApplication struct {
	ClientID               string   `json:"clientId"`
	DisplayName            string   `json:"displayName"`
	OwnerOrganizationID    string   `json:"ownerOrganizationId"`
	OrganizationID         string   `json:"organizationId,omitempty"`
	RedirectURIs           []string `json:"redirectUris"`
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris,omitempty"`
	AccountReturnURIs      []string `json:"accountReturnUris"`
	Preauthorized          bool     `json:"preauthorized"`
	SubjectKind            string   `json:"subjectKind"`
	EvidenceScope          string   `json:"evidenceScope,omitempty"`
	EvidenceAudience       string   `json:"evidenceAudience,omitempty"`
	Refresh                bool     `json:"refresh"`
	Enabled                bool     `json:"enabled"`
	Published              bool     `json:"published"`
	System                 bool     `json:"system"`
	Revision               int64    `json:"revision"`
}

func (registration OIDCClientRegistration) Application() OIDCApplication {
	client := registration.Client
	return OIDCApplication{
		ClientID: client.ID, DisplayName: registration.DisplayName, OrganizationID: client.OrganizationID,
		OwnerOrganizationID: registration.OwnerOrganizationID,
		RedirectURIs:        client.RedirectURIs, PostLogoutRedirectURIs: client.PostLogoutRedirectURIs, Refresh: client.Refresh,
		AccountReturnURIs: client.AccountReturnURIs, Preauthorized: client.Preauthorized,
		SubjectKind: client.SubjectKind, EvidenceScope: client.EvidenceScope, EvidenceAudience: client.EvidenceAudience,
		Published: registration.Published, Enabled: registration.Enabled, System: registration.System, Revision: registration.Revision,
	}
}

const oidcClientInsertColumns = "display_name,enabled,system,revision,registration,owner_organization_id"

const oidcClientColumns = oidcClientInsertColumns + ",published"

func scanOIDCClient(row pgx.Row) (OIDCClientRegistration, error) {
	var registration OIDCClientRegistration
	err := row.Scan(&registration.DisplayName, &registration.Enabled, &registration.System, &registration.Revision, &registration.Client, &registration.OwnerOrganizationID, &registration.Published)
	return registration, storageError(err)
}

func (store *Store) OIDCClient(ctx context.Context, id string) (OIDCClientRegistration, error) {
	return ReadOIDCClient(ctx, store.pool, id)
}

func ReadOIDCClient(ctx context.Context, db queryer, id string) (OIDCClientRegistration, error) {
	return scanOIDCClient(db.QueryRow(ctx, "SELECT "+oidcClientColumns+" FROM oidc_clients WHERE client_id=$1", id))
}

func LockOIDCClient(ctx context.Context, tx pgx.Tx, id string) (OIDCClientRegistration, error) {
	return scanOIDCClient(tx.QueryRow(ctx, "SELECT "+oidcClientColumns+" FROM oidc_clients WHERE client_id=$1 FOR SHARE", id))
}

type OIDCClientCapabilities struct {
	ActiveClients  int
	Refresh        bool
	EvidenceScopes []string
}

func (store *Store) OIDCClientCapabilities(ctx context.Context) (OIDCClientCapabilities, error) {
	var capabilities OIDCClientCapabilities
	err := store.pool.QueryRow(ctx, `SELECT count(*),COALESCE(bool_or(registration->>'refresh'='true'),false),
 COALESCE(array_agg(DISTINCT registration->>'evidenceScope' ORDER BY registration->>'evidenceScope')
 FILTER (WHERE registration->>'evidenceScope' IS NOT NULL),'{}')
 FROM oidc_clients WHERE enabled`).Scan(&capabilities.ActiveClients, &capabilities.Refresh, &capabilities.EvidenceScopes)
	return capabilities, err
}

func insertOIDCClient(ctx context.Context, tx pgx.Tx, registration OIDCClientRegistration) error {
	_, err := tx.Exec(ctx, "INSERT INTO oidc_clients(client_id,"+oidcClientInsertColumns+") VALUES($1,$2,$3,$4,$5,$6,$7)",
		registration.Client.ID, registration.DisplayName, registration.Enabled, registration.System, registration.Revision, registration.Client, registration.OwnerOrganizationID)
	return storageError(err)
}

type OIDCApplicationDirectory struct {
	Items         []OIDCApplication `json:"items"`
	Organizations []Organization    `json:"organizations"`
}

func (service *ManagementService) OIDCApplications(ctx context.Context, principal Principal, ownerID string) (OIDCApplicationDirectory, error) {
	store := service.store
	requirement := oidcClientsResource.require(actionList)
	if ownerID != "" {
		requirement = organizationOIDCClientsResource.require(actionList, ownerID)
	}
	if err := store.authorizeManagementRead(ctx, principal, requirement); err != nil {
		return OIDCApplicationDirectory{}, err
	}
	directory := OIDCApplicationDirectory{Items: []OIDCApplication{}, Organizations: []Organization{}}
	rows, err := store.pool.Query(ctx, "SELECT "+oidcClientColumns+" FROM oidc_clients WHERE ($1::text = '' OR owner_organization_id=$1) ORDER BY client_id", ownerID)
	if err != nil {
		return directory, err
	}
	clients, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (OIDCClientRegistration, error) {
		return scanOIDCClient(row)
	})
	if err != nil {
		return directory, err
	}
	for _, client := range clients {
		directory.Items = append(directory.Items, client.Application())
	}
	for after := ""; ; {
		page, err := service.Organizations(ctx, principal, after, 100)
		if err != nil {
			return directory, err
		}
		directory.Organizations = append(directory.Organizations, page.Items...)
		if page.NextAfter == "" {
			return directory, nil
		}
		after = page.NextAfter
	}
}

func (service *ManagementService) CreateOIDCApplication(ctx context.Context, principal Principal, ownerID string, application OIDCApplication, secretHash string, loopback bool) (OIDCApplication, error) {
	requirements := []authorization.Requirement{oidcClientsResource.require(actionCreate)}
	if ownerID == "" {
		ownerID = service.store.systemOrganizationID
	} else {
		requirements[0] = organizationOIDCClientsResource.require(actionCreate, ownerID)
		if application.OrganizationID != "" && application.OrganizationID != ownerID {
			return OIDCApplication{}, ErrForbidden
		}
		if application.EvidenceScope != "" || application.EvidenceAudience != "" || application.Preauthorized {
			requirements = append(requirements, oidcClientsResource.require(actionCreate))
		}
		application.OrganizationID = ownerID
	}
	registration := OIDCClientRegistration{
		DisplayName:         application.DisplayName,
		OwnerOrganizationID: ownerID,
		Client: OIDCClient{
			ID: application.ClientID, SecretSHA256: secretHash, SubjectKind: "member",
			OrganizationID: application.OrganizationID, RedirectURIs: application.RedirectURIs,
			PostLogoutRedirectURIs: application.PostLogoutRedirectURIs, Refresh: application.Refresh,
			AccountReturnURIs: application.AccountReturnURIs, Preauthorized: application.Preauthorized,
			EvidenceScope: application.EvidenceScope, EvidenceAudience: application.EvidenceAudience,
		},
	}
	return service.store.createOIDCClient(ctx, principal, registration, loopback, requirements...)
}

func (store *Store) CreateOIDCClient(ctx context.Context, principal Principal, registration OIDCClientRegistration, loopback bool) (OIDCApplication, error) {
	return store.createOIDCClient(ctx, principal, registration, loopback, oidcClientsResource.require(actionCreate))
}

func (store *Store) createOIDCClient(ctx context.Context, principal Principal, registration OIDCClientRegistration, loopback bool, requirements ...authorization.Requirement) (OIDCApplication, error) {
	if registration.Client.ID != "" {
		return OIDCApplication{}, ErrInvalid
	}
	id, err := NewID(ApplicationKind)
	if err != nil {
		return OIDCApplication{}, err
	}
	registration.Client.ID = id
	if registration.DisplayName == "" && principal.kind == operatorPrincipal {
		registration.DisplayName = id
	}
	if !validText(registration.DisplayName, 128) || ValidateOIDCClients([]OIDCClient{registration.Client}, loopback) != nil {
		return OIDCApplication{}, ErrInvalid
	}
	if registration.System && (principal.kind != operatorPrincipal || registration.OwnerOrganizationID != store.systemOrganizationID || registration.Client.SubjectKind != "member" || registration.Client.OrganizationID != "") {
		return OIDCApplication{}, ErrForbidden
	}
	registration.Enabled, registration.Revision = true, 1
	application := registration.Application()
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		if err := authorizeAll(ctx, tx, principal, requirements...); err != nil {
			return err
		}
		if err := requireOIDCOrganization(ctx, tx, registration.Client.OrganizationID); err != nil {
			return err
		}
		if err := insertOIDCClient(ctx, tx, registration); err != nil {
			return err
		}
		return managementEvent(ctx, tx, principal, registration.OwnerOrganizationID, "", "oidc.application.create", application, nil)
	})
	if err != nil {
		return OIDCApplication{}, err
	}
	return application, nil
}

type OIDCApplicationChange struct {
	ExpectedRevision       int64     `json:"expectedRevision"`
	DisplayName            string    `json:"displayName"`
	OrganizationID         string    `json:"organizationId"`
	RedirectURIs           []string  `json:"redirectUris"`
	PostLogoutRedirectURIs []string  `json:"postLogoutRedirectUris"`
	AccountReturnURIs      *[]string `json:"accountReturnUris"`
	EvidenceScope          *string   `json:"evidenceScope"`
	EvidenceAudience       *string   `json:"evidenceAudience"`
	Preauthorized          *bool     `json:"preauthorized"`
	Refresh                bool      `json:"refresh"`
	Enabled                *bool     `json:"enabled"`
}

func (service *ManagementService) UpdateOIDCApplication(ctx context.Context, principal Principal, ownerID, id string, change OIDCApplicationChange, loopback bool) (OIDCApplication, error) {
	action := actionUpdate
	if change.Enabled != nil {
		if change.DisplayName != "" || change.OrganizationID != "" || change.RedirectURIs != nil || change.PostLogoutRedirectURIs != nil || change.AccountReturnURIs != nil || change.Preauthorized != nil || change.EvidenceScope != nil || change.EvidenceAudience != nil || change.Refresh {
			return OIDCApplication{}, ErrInvalid
		}
		action = actionStatusUpdate
	}
	if change.ExpectedRevision < 1 || (change.EvidenceScope == nil) != (change.EvidenceAudience == nil) {
		return OIDCApplication{}, ErrInvalid
	}
	return service.store.changeOIDCClient(ctx, principal, ownerID, id, change.ExpectedRevision, action, func(registration *OIDCClientRegistration) (bool, error) {
		if change.Enabled != nil {
			registration.Enabled = *change.Enabled
			return !registration.Enabled, nil
		}
		if !validText(change.DisplayName, 128) {
			return false, ErrInvalid
		}
		if ownerID != "" {
			if change.OrganizationID != "" && change.OrganizationID != ownerID || change.EvidenceScope != nil || change.Preauthorized != nil {
				return false, ErrForbidden
			}
			change.OrganizationID = ownerID
		}
		client := &registration.Client
		if change.EvidenceScope != nil {
			if client.SubjectKind != "member" {
				return false, ErrForbidden
			}
			client.EvidenceScope, client.EvidenceAudience = *change.EvidenceScope, *change.EvidenceAudience
		}
		revoke := client.OrganizationID != change.OrganizationID || client.Refresh && !change.Refresh
		registration.DisplayName = change.DisplayName
		client.RedirectURIs, client.PostLogoutRedirectURIs = change.RedirectURIs, change.PostLogoutRedirectURIs
		client.OrganizationID, client.Refresh = change.OrganizationID, change.Refresh
		if change.AccountReturnURIs != nil {
			client.AccountReturnURIs = *change.AccountReturnURIs
		}
		if change.Preauthorized != nil {
			client.Preauthorized = *change.Preauthorized
		}
		if ValidateOIDCClients([]OIDCClient{*client}, loopback) != nil {
			return false, ErrInvalid
		}
		return revoke, nil
	})
}

func (service *ManagementService) RotateOIDCApplicationSecret(ctx context.Context, principal Principal, ownerID, id string, revision int64, secretHash string) (OIDCApplication, error) {
	if revision < 1 {
		return OIDCApplication{}, ErrInvalid
	}
	return service.store.RotateOIDCClientSecret(ctx, principal, ownerID, id, revision, secretHash)
}

func (store *Store) RotateOIDCClientSecret(ctx context.Context, principal Principal, ownerID, id string, revision int64, secretHash string) (OIDCApplication, error) {
	if !validOIDCSecretHash(secretHash) {
		return OIDCApplication{}, ErrInvalid
	}
	return store.changeOIDCClient(ctx, principal, ownerID, id, revision, "credential.rotate", func(registration *OIDCClientRegistration) (bool, error) {
		registration.Client.SecretSHA256 = secretHash
		return false, nil
	})
}

func (store *Store) changeOIDCClient(ctx context.Context, principal Principal, ownerID, id string, revision int64, action string, change func(*OIDCClientRegistration) (bool, error)) (OIDCApplication, error) {
	if !validOIDCClientID(id) || revision < 1 && principal.kind != operatorPrincipal {
		return OIDCApplication{}, ErrInvalid
	}
	var result OIDCApplication
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := managementLock(ctx, tx); err != nil {
			return err
		}
		requirement := oidcClientResource.require(action, id)
		if ownerID != "" {
			requirement = organizationOIDCClientResource.require(action, ownerID, id)
		}
		if err := authorizeAll(ctx, tx, principal, requirement); err != nil {
			return err
		}
		registration, err := scanOIDCClient(tx.QueryRow(ctx, "SELECT "+oidcClientColumns+" FROM oidc_clients WHERE client_id=$1 FOR UPDATE", id))
		if err != nil {
			return err
		}
		if ownerID != "" {
			if registration.OwnerOrganizationID != ownerID {
				return ErrNotFound
			}
			if registration.Client.SubjectKind != "member" || registration.Client.OrganizationID != ownerID {
				return ErrForbidden
			}
		}
		if registration.System && !(principal.kind == operatorPrincipal && action == "credential.rotate") {
			return ErrForbidden
		}
		if revision != 0 && registration.Revision != revision {
			return ErrConflict
		}
		previous := registration.Application()
		revoke, err := change(&registration)
		if err != nil {
			return err
		}
		if registration.Client.OrganizationID != previous.OrganizationID {
			if registration.Published {
				return ErrConflict
			}
			if err := requireOIDCOrganization(ctx, tx, registration.Client.OrganizationID); err != nil {
				return err
			}
		}
		registration.Revision++
		if _, err := tx.Exec(ctx, "UPDATE oidc_clients SET display_name=$2,enabled=$3,revision=$4,registration=$5 WHERE client_id=$1",
			id, registration.DisplayName, registration.Enabled, registration.Revision, registration.Client); err != nil {
			return storageError(err)
		}
		var removedScopes []string
		if previous.EvidenceScope != "" && (previous.EvidenceScope != registration.Client.EvidenceScope || previous.EvidenceAudience != registration.Client.EvidenceAudience) {
			removedScopes = append(removedScopes, previous.EvidenceScope)
		}
		if revoke || len(removedScopes) > 0 {
			if _, err := tx.Exec(ctx, `UPDATE oidc_grants SET revoked_at=$2 WHERE client_id=$1 AND revoked_at IS NULL
 AND ($3 OR (data->'scopes') ?| $4::text[])`, id, time.Now().UTC(), revoke, removedScopes); err != nil {
				return err
			}
		}
		result = registration.Application()
		before, err := json.Marshal(previous)
		if err != nil {
			return err
		}
		var values map[string]any
		if err := json.Unmarshal(before, &values); err != nil {
			return err
		}
		return managementEvent(ctx, tx, principal, registration.OwnerOrganizationID, "", "oidc.application."+action, result, values)
	})
	if err != nil {
		return OIDCApplication{}, err
	}
	return result, nil
}

func requireOIDCOrganization(ctx context.Context, tx pgx.Tx, id string) error {
	if id == "" {
		return nil
	}
	var exists bool
	err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)", id).Scan(&exists)
	if err == nil && !exists {
		return ErrInvalid
	}
	return err
}

func importOIDCClients(ctx context.Context, tx pgx.Tx, registrations []OIDCClientRegistration) error {
	for _, registration := range registrations {
		if !validText(registration.DisplayName, 128) || !validOIDCClientID(registration.Client.ID) || !validOIDCSecretHash(registration.Client.SecretSHA256) {
			return errors.New("invalid legacy OIDC client registration")
		}
		registration.Enabled, registration.Revision = true, 1
		registration.OwnerOrganizationID = "org_system" // Imported before the schema 38 rekey.
		if err := insertOIDCClient(ctx, tx, registration); err != nil {
			return err
		}
	}
	return nil
}
