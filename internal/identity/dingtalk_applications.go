package identity

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/euyuil/memberid/internal/dingtalk"
	"github.com/jackc/pgx/v5"
)

var ErrProviderUnavailable = errors.New("provider verification unavailable")
var ErrProviderConfiguration = errors.New("provider credentials could not be opened")

type DingTalkApplication struct {
	AuthorizationStatus     string    `json:"authorizationStatus"`
	AuthorizationRevision   int64     `json:"authorizationRevision"`
	AuthorizationVerifiedAt time.Time `json:"authorizationVerifiedAt"`
	directoryRevision       int64
	organizationRevision    int64
	DisplayName             string    `json:"displayName"`
	Enabled                 bool      `json:"enabled"`
	OrganizationID          string    `json:"organizationId"`
	Namespace               string    `json:"namespace"`
	CorpID                  string    `json:"corpId"`
	ClientID                string    `json:"clientId"`
	Revision                int64     `json:"revision"`
	CreatedAt               time.Time `json:"createdAt"`
	UpdatedAt               time.Time `json:"updatedAt"`
}

type DingTalkApplicationInput struct {
	CorpID           string `json:"corpId"`
	ClientID         string `json:"clientId"`
	ClientSecret     string `json:"clientSecret"`
	ExpectedRevision int64  `json:"expectedRevision"`
}

type DingTalkCredentials struct {
	DingTalkApplication
	Secret string `json:"-"`
}

type DingTalkAuthorizationChecker interface {
	CheckAuthorization(context.Context, string, string, string) error
}

type DingTalkApplications struct {
	store   *Store
	cipher  cipher.AEAD
	checker DingTalkAuthorizationChecker
}

func NewDingTalkApplications(store *Store, key []byte, checker DingTalkAuthorizationChecker) (*DingTalkApplications, error) {
	if store == nil || len(key) != 32 || checker == nil {
		return nil, ErrInvalid
	}
	encrypted, err := providerCipher(key)
	if err != nil {
		return nil, err
	}
	return &DingTalkApplications{store, encrypted, checker}, nil
}

func providerCipher(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

const applicationColumns = "organization_id,namespace,corp_id,client_id,revision,created_at,updated_at,secret_ciphertext,authorization_status,authorization_revision,authorization_verified_at,directory_revision,display_name,enabled"

func readApplication(row pgx.Row) (DingTalkApplication, []byte, error) {
	var app DingTalkApplication
	var encrypted []byte
	err := row.Scan(&app.OrganizationID, &app.Namespace, &app.CorpID, &app.ClientID, &app.Revision, &app.CreatedAt, &app.UpdatedAt, &encrypted, &app.AuthorizationStatus, &app.AuthorizationRevision, &app.AuthorizationVerifiedAt, &app.directoryRevision, &app.DisplayName, &app.Enabled)
	app.CreatedAt, app.UpdatedAt = app.CreatedAt.UTC(), app.UpdatedAt.UTC()
	app.AuthorizationVerifiedAt = app.AuthorizationVerifiedAt.UTC()
	return app, encrypted, storageError(err)
}

// dingTalkNamespace resolves the organization-only operator interface when it has one match.
func dingTalkNamespace(ctx context.Context, db queryer, organizationID, namespace string) (string, error) {
	if !ValidID(organizationID, OrganizationKind) || namespace != "" && !validText(namespace, 128) {
		return "", ErrInvalid
	}
	if namespace != "" {
		return namespace, nil
	}
	var found *string
	var count int
	err := db.QueryRow(ctx, "SELECT min(namespace), count(*) FROM dingtalk_applications WHERE organization_id=$1", organizationID).Scan(&found, &count)
	if err != nil {
		return "", err
	}
	if count > 1 {
		return "", ErrConflict
	}
	if found == nil {
		return "", ErrNotFound
	}
	return *found, nil
}

func (applications *DingTalkApplications) Inspect(ctx context.Context, organizationID string) (DingTalkApplication, error) {
	return applications.InspectSource(ctx, organizationID, "")
}

func (applications *DingTalkApplications) InspectSource(ctx context.Context, organizationID, namespace string) (DingTalkApplication, error) {
	namespace, err := dingTalkNamespace(ctx, applications.store.pool, organizationID, namespace)
	if err != nil {
		return DingTalkApplication{}, err
	}
	app, _, err := readApplication(applications.store.pool.QueryRow(ctx, "SELECT "+applicationColumns+" FROM dingtalk_applications WHERE organization_id=$1 AND namespace=$2", organizationID, namespace))
	return app, err
}

func applicationAAD(app DingTalkApplication) []byte {
	data, _ := json.Marshal([]string{"MemberID DingTalk credential v1", app.OrganizationID, app.Namespace, app.CorpID, app.ClientID, strconv.FormatInt(app.Revision, 10)})
	return data
}

// Load supplies credentials only to trusted, in-process provider operations.
func (applications *DingTalkApplications) Load(ctx context.Context, organizationID string) (DingTalkCredentials, error) {
	return applications.loadSource(ctx, organizationID, "")
}

func (applications *DingTalkApplications) loadSource(ctx context.Context, organizationID, namespace string) (DingTalkCredentials, error) {
	namespace, err := dingTalkNamespace(ctx, applications.store.pool, organizationID, namespace)
	if err != nil {
		return DingTalkCredentials{}, err
	}
	app, encrypted, err := readApplication(applications.store.pool.QueryRow(ctx, "SELECT "+applicationColumns+" FROM dingtalk_applications WHERE organization_id=$1 AND namespace=$2", organizationID, namespace))
	if err != nil {
		return DingTalkCredentials{}, err
	}
	secret, err := applications.cipher.Open(nil, nil, encrypted, applicationAAD(app))
	if err != nil {
		return DingTalkCredentials{}, ErrProviderConfiguration
	}
	return DingTalkCredentials{app, string(secret)}, nil
}

func (applications *DingTalkApplications) Configure(ctx context.Context, principal Principal, organizationID string, input DingTalkApplicationInput) (DingTalkApplication, error) {
	if !principal.installation() {
		return DingTalkApplication{}, ErrForbidden
	}
	return applications.ConfigureSource(ctx, principal, organizationID, "", input)
}

func (applications *DingTalkApplications) ConfigureSource(ctx context.Context, principal Principal, organizationID, namespace string, input DingTalkApplicationInput) (DingTalkApplication, error) {
	if !principal.installation() {
		return DingTalkApplication{}, ErrForbidden
	}
	if !dingtalk.ValidCredentials(input.CorpID, input.ClientID, input.ClientSecret) {
		return DingTalkApplication{}, ErrInvalid
	}
	return applications.configure(ctx, principal, organizationID, namespace, ProviderInput{
		TenantID: input.CorpID, ClientID: input.ClientID, ClientSecret: input.ClientSecret, ExpectedRevision: input.ExpectedRevision,
	})
}

func (applications *DingTalkApplications) configure(ctx context.Context, principal Principal, organizationID, namespace string, input ProviderInput) (DingTalkApplication, error) {
	if principal.kind != memberPrincipal && !principal.installation() {
		return DingTalkApplication{}, ErrForbidden
	}
	console := principal.kind == memberPrincipal
	if !validProviderInput(organizationID, namespace, input, console) || input.ClientSecret != "" && !dingtalk.ValidCredentials(input.TenantID, input.ClientID, input.ClientSecret) {
		return DingTalkApplication{}, ErrInvalid
	}
	organization, err := applications.store.Organization(ctx, organizationID)
	if err != nil {
		return DingTalkApplication{}, err
	}
	if organization.Status != "enabled" {
		return DingTalkApplication{}, ErrIneligible
	}
	var current DingTalkApplication
	var encrypted []byte
	if namespace != "" || !console {
		current, err = applications.InspectSource(ctx, organizationID, namespace)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return DingTalkApplication{}, err
		}
	}
	exists := current.Namespace != ""
	if exists && (current.Revision != input.ExpectedRevision || current.CorpID != input.TenantID || current.ClientID != input.ClientID) ||
		!exists && (input.ExpectedRevision != 0 || namespace != "" || input.ClientSecret == "") {
		return DingTalkApplication{}, ErrConflict
	}
	candidate := current
	if !exists {
		candidate = DingTalkApplication{OrganizationID: organizationID, Namespace: rand.Text(), CorpID: input.TenantID, ClientID: input.ClientID, DisplayName: "DingTalk", Enabled: true}
	}
	if console {
		candidate.DisplayName, candidate.Enabled = input.DisplayName, *input.Enabled
	}
	checked := input.ClientSecret != ""
	secretChanged := checked
	if checked {
		if err := applications.checker.CheckAuthorization(ctx, input.TenantID, input.ClientID, input.ClientSecret); err != nil {
			return DingTalkApplication{}, ErrProviderUnavailable
		}
		if exists {
			credentials, err := applications.loadSource(ctx, organizationID, current.Namespace)
			if err != nil {
				return DingTalkApplication{}, err
			}
			secretChanged = subtle.ConstantTimeCompare([]byte(credentials.Secret), []byte(input.ClientSecret)) != 1
		}
	}
	// A revision change also rebinds the encrypted secret to the new revision.
	changed := secretChanged || candidate.DisplayName != current.DisplayName || candidate.Enabled != current.Enabled
	if changed {
		secret := input.ClientSecret
		if !checked {
			credentials, err := applications.loadSource(ctx, organizationID, current.Namespace)
			if err != nil {
				return DingTalkApplication{}, err
			}
			secret = credentials.Secret
		}
		candidate.Revision++
		encrypted = applications.cipher.Seal(nil, nil, []byte(secret), applicationAAD(candidate))
	}
	var result DingTalkApplication
	err = pgx.BeginFunc(ctx, applications.store.pool, func(tx pgx.Tx) error {
		before, err := lockProviderManagement(ctx, tx, principal, organization, exists && current.Enabled && !candidate.Enabled, providerWriteRequirements(organizationID, "dingtalk", current.Namespace, input.Enabled != nil)...)
		if err != nil {
			return err
		}
		if exists {
			locked, _, err := readApplication(tx.QueryRow(ctx, "SELECT "+applicationColumns+" FROM dingtalk_applications WHERE organization_id=$1 AND namespace=$2 FOR UPDATE", organizationID, current.Namespace))
			if err != nil {
				return err
			}
			if locked.Revision != current.Revision || locked.AuthorizationRevision != current.AuthorizationRevision {
				return ErrConflict
			}
			if !changed && (!checked || locked.AuthorizationStatus == "active") {
				result = locked
				return nil
			}
			result, _, err = readApplication(tx.QueryRow(ctx, `UPDATE dingtalk_applications
 SET secret_ciphertext=COALESCE($3,secret_ciphertext),revision=$4,display_name=$5,enabled=$6,
 authorization_status=CASE WHEN $7 THEN 'active' ELSE authorization_status END,
 authorization_revision=authorization_revision+CASE WHEN $7 THEN 1 ELSE 0 END,
 authorization_verified_at=CASE WHEN $7 THEN clock_timestamp() ELSE authorization_verified_at END,updated_at=clock_timestamp()
 WHERE organization_id=$1 AND namespace=$2 RETURNING `+applicationColumns, organizationID, current.Namespace, encrypted, candidate.Revision, candidate.DisplayName, candidate.Enabled, checked))
		} else {
			if !console {
				_, err := dingTalkNamespace(ctx, tx, organizationID, "")
				if err == nil {
					return ErrConflict
				}
				if !errors.Is(err, ErrNotFound) {
					return err
				}
			}
			result, _, err = readApplication(tx.QueryRow(ctx, `INSERT INTO dingtalk_applications
 (organization_id,namespace,corp_id,client_id,revision,secret_ciphertext,display_name,enabled)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+applicationColumns, organizationID, candidate.Namespace, input.TenantID, input.ClientID, candidate.Revision, encrypted, candidate.DisplayName, candidate.Enabled))
		}
		if err != nil {
			return err
		}
		return finishProviderManagement(ctx, tx, principal, "dingtalk", result.OrganizationID, result.Namespace, result.DisplayName, result.Enabled, before)
	})
	return result, err
}
