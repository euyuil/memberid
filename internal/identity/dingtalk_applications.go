package identity

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"math"
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
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encrypted, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return &DingTalkApplications{store, encrypted, checker}, nil
}

const applicationColumns = "organization_id,namespace,corp_id,client_id,revision,created_at,updated_at,secret_ciphertext,authorization_status,authorization_revision,authorization_verified_at,directory_revision"

func readApplication(row pgx.Row) (DingTalkApplication, []byte, error) {
	var app DingTalkApplication
	var encrypted []byte
	err := row.Scan(&app.OrganizationID, &app.Namespace, &app.CorpID, &app.ClientID, &app.Revision, &app.CreatedAt, &app.UpdatedAt, &encrypted, &app.AuthorizationStatus, &app.AuthorizationRevision, &app.AuthorizationVerifiedAt, &app.directoryRevision)
	app.CreatedAt, app.UpdatedAt = app.CreatedAt.UTC(), app.UpdatedAt.UTC()
	app.AuthorizationVerifiedAt = app.AuthorizationVerifiedAt.UTC()
	return app, encrypted, storageError(err)
}

func (applications *DingTalkApplications) Inspect(ctx context.Context, organizationID string) (DingTalkApplication, error) {
	if !ValidID(organizationID, OrganizationKind) {
		return DingTalkApplication{}, ErrInvalid
	}
	app, _, err := readApplication(applications.store.pool.QueryRow(ctx, "SELECT "+applicationColumns+" FROM dingtalk_applications WHERE organization_id=$1", organizationID))
	return app, err
}

func applicationAAD(app DingTalkApplication) []byte {
	data, _ := json.Marshal([]string{"MemberID DingTalk credential v1", app.OrganizationID, app.Namespace, app.CorpID, app.ClientID, strconv.FormatInt(app.Revision, 10)})
	return data
}

// Load supplies credentials only to trusted, in-process provider operations.
func (applications *DingTalkApplications) Load(ctx context.Context, organizationID string) (DingTalkCredentials, error) {
	if !ValidID(organizationID, OrganizationKind) {
		return DingTalkCredentials{}, ErrInvalid
	}
	app, encrypted, err := readApplication(applications.store.pool.QueryRow(ctx, "SELECT "+applicationColumns+" FROM dingtalk_applications WHERE organization_id=$1", organizationID))
	if err != nil {
		return DingTalkCredentials{}, err
	}
	secret, err := applications.cipher.Open(nil, nil, encrypted, applicationAAD(app))
	if err != nil {
		return DingTalkCredentials{}, ErrProviderConfiguration
	}
	return DingTalkCredentials{app, string(secret)}, nil
}

// Configure verifies provider authorization before entering the write transaction.
// The revision is checked again under the organization lock so slow provider I/O cannot overwrite a newer decision.
func (applications *DingTalkApplications) Configure(ctx context.Context, organizationID string, input DingTalkApplicationInput) (DingTalkApplication, error) {
	if !ValidID(organizationID, OrganizationKind) || !dingtalk.ValidCredentials(input.CorpID, input.ClientID, input.ClientSecret) || input.ExpectedRevision < 0 || input.ExpectedRevision == math.MaxInt64 {
		return DingTalkApplication{}, ErrInvalid
	}
	organization, err := applications.store.Organization(ctx, organizationID)
	if err != nil {
		return DingTalkApplication{}, err
	}
	if organization.Status != "enabled" {
		return DingTalkApplication{}, ErrIneligible
	}
	current, err := applications.Load(ctx, organizationID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return DingTalkApplication{}, err
	}
	exists := err == nil
	if exists && (current.Revision != input.ExpectedRevision || current.CorpID != input.CorpID || current.ClientID != input.ClientID) || !exists && input.ExpectedRevision != 0 {
		return DingTalkApplication{}, ErrConflict
	}
	if err := applications.checker.CheckAuthorization(ctx, input.CorpID, input.ClientID, input.ClientSecret); err != nil {
		return DingTalkApplication{}, ErrProviderUnavailable
	}
	candidate := current.DingTalkApplication
	if !exists {
		candidate = DingTalkApplication{OrganizationID: organizationID, Namespace: rand.Text(), CorpID: input.CorpID, ClientID: input.ClientID}
	}
	candidate.Revision++
	encrypted := applications.cipher.Seal(nil, nil, []byte(input.ClientSecret), applicationAAD(candidate))
	var result DingTalkApplication
	lifecycle := organization.lifecycleRevision
	err = pgx.BeginFunc(ctx, applications.store.pool, func(tx pgx.Tx) error {
		organization, err := readOrganization(tx.QueryRow(ctx, "SELECT "+organizationColumns+" FROM organizations WHERE id=$1 FOR UPDATE", organizationID))
		if err != nil {
			return err
		}
		if organization.Status != "enabled" || organization.lifecycleRevision != lifecycle {
			return ErrIneligible
		}
		locked, _, err := readApplication(tx.QueryRow(ctx, "SELECT "+applicationColumns+" FROM dingtalk_applications WHERE organization_id=$1 FOR UPDATE", organizationID))
		if exists {
			if err != nil {
				return err
			}
			if locked.Revision != current.Revision || locked.Namespace != current.Namespace || locked.AuthorizationRevision != current.AuthorizationRevision {
				return ErrConflict
			}
			if subtle.ConstantTimeCompare([]byte(current.Secret), []byte(input.ClientSecret)) == 1 {
				if locked.AuthorizationStatus == "active" {
					result = locked
					return nil
				}
				result, _, err = readApplication(tx.QueryRow(ctx, "UPDATE dingtalk_applications SET authorization_status='active',authorization_revision=authorization_revision+1,authorization_verified_at=clock_timestamp(),updated_at=clock_timestamp() WHERE organization_id=$1 RETURNING "+applicationColumns, organizationID))
				return err
			}
			result, _, err = readApplication(tx.QueryRow(ctx, "UPDATE dingtalk_applications SET secret_ciphertext=$2,revision=$3,authorization_status='active',authorization_revision=authorization_revision+1,authorization_verified_at=clock_timestamp(),updated_at=clock_timestamp() WHERE organization_id=$1 RETURNING "+applicationColumns, organizationID, encrypted, candidate.Revision))
			return err
		}
		if err == nil {
			return ErrConflict
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		result, _, err = readApplication(tx.QueryRow(ctx, "INSERT INTO dingtalk_applications(organization_id,namespace,corp_id,client_id,revision,secret_ciphertext) VALUES($1,$2,$3,$4,$5,$6) RETURNING "+applicationColumns, organizationID, candidate.Namespace, input.CorpID, input.ClientID, candidate.Revision, encrypted))
		return err
	})
	return result, err
}
