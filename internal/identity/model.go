package identity

import (
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrNotFound         = errors.New("identity record not found")
	ErrConflict         = errors.New("identity binding or identifier conflict")
	ErrIneligible       = errors.New("identity is not eligible")
	ErrSchemaRequired   = errors.New("initialize an empty MemberID database first")
	ErrDatabaseNotEmpty = errors.New("database contains existing objects; initialization refused")
)

type Organization struct {
	lifecycleRevision int64
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

type Member struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	DisplayName    string    `json:"displayName"`
	Status         string    `json:"status"`
	BlockSources   []string  `json:"blockSources"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type Factor struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Namespace string    `json:"namespace"`
	Subject   string    `json:"subject"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Binding struct {
	ID             string     `json:"id"`
	MemberID       string     `json:"memberId"`
	OrganizationID string     `json:"organizationId"`
	FactorID       string     `json:"authenticationFactorId"`
	FactorType     string     `json:"factorType"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"createdAt"`
	RevokedAt      *time.Time `json:"revokedAt"`
}

func validText(value string, maximum int) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) != "" &&
		utf8.RuneCountInString(value) <= maximum &&
		strings.IndexFunc(value, unicode.IsControl) == -1
}

func validFactorType(kind string) bool { return kind == "phone" || kind == "dingtalk" }
