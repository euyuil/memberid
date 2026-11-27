package identity

import (
	"context"
	_ "embed"
	"errors"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/0038_installation_guards.sql
var installationIdentitySchema string

func reserveInstallationIdentities(ctx context.Context, tx pgx.Tx, org, member string) error {
	if _, err := tx.Exec(ctx, "INSERT INTO organization_login_slugs(slug,organization_id) VALUES('system',$1)", org); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "INSERT INTO installation_identities(slug,root_member_id) VALUES('system',$1)", member)
	return err
}

// Stage fresh IDs and reauthenticate organization-bound provider ciphertext while the
// old rows are still present. The surrounding maintenance transaction owns all writes.
func stageInstallationIDs(ctx context.Context, tx pgx.Tx, key []byte) (string, string, error) {
	var conflict, missing bool
	err := tx.QueryRow(ctx, `SELECT
        EXISTS(SELECT 1 FROM authentication_factors f WHERE f.type='password' AND f.namespace='org_system' AND f.subject='root'
            AND NOT EXISTS(SELECT 1 FROM member_auth_factor_bindings b WHERE b.authentication_factor_id=f.id AND b.member_id='mbr_root' AND b.organization_id='org_system')),
        EXISTS(SELECT 1 FROM members WHERE id='mbr_root') AND NOT EXISTS (
            SELECT 1 FROM member_auth_factor_bindings b JOIN authentication_factors f ON f.id=b.authentication_factor_id
            WHERE b.member_id='mbr_root' AND b.organization_id='org_system' AND f.type='password' AND f.namespace='org_system')`).Scan(&conflict, &missing)
	if err != nil {
		return "", "", err
	}
	if conflict {
		return "", "", errors.New("the system username root is held by another identity; reconcile it on the source installation before upgrading")
	}
	if missing {
		return "", "", errors.New("legacy root has no matching password binding; reconcile the source installation before upgrading")
	}
	org, err := NewID(OrganizationKind)
	if err != nil {
		return "", "", err
	}
	member, err := NewID(MemberKind)
	if err != nil {
		return "", "", err
	}
	rows, err := tx.Query(ctx, "SELECT namespace FROM dingtalk_applications WHERE organization_id='org_system' ORDER BY namespace")
	if err != nil {
		return "", "", err
	}
	namespaces, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", "", err
	}
	for _, namespace := range namespaces {
		app, encrypted, err := readApplication(tx.QueryRow(ctx, "SELECT "+applicationColumns+" FROM dingtalk_applications WHERE namespace=$1", namespace))
		if err != nil {
			return "", "", err
		}
		cipher, err := providerCipher(key)
		if err != nil {
			return "", "", ErrProviderConfiguration
		}
		secret, err := cipher.Open(nil, nil, encrypted, applicationAAD(app))
		if err != nil {
			return "", "", ErrProviderConfiguration
		}
		app.OrganizationID = org
		encrypted = cipher.Seal(nil, nil, secret, applicationAAD(app))
		clear(secret)
		if _, err := tx.Exec(ctx, "UPDATE dingtalk_applications SET secret_ciphertext=$1 WHERE namespace=$2", encrypted, namespace); err != nil {
			return "", "", err
		}
	}
	_, err = tx.Exec(ctx, "SELECT set_config('memberid.system_id',$1,true),set_config('memberid.root_id',$2,true)", org, member)
	return org, member, err
}
