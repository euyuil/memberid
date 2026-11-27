package identity

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"
)

type ApplicationIDAssignment struct {
	Protocol string `json:"protocol"`
	OldID    string `json:"oldId"`
	NewID    string `json:"newId"`
}

type applicationKey struct{ Protocol, OldID string }

func applicationInventory(ctx context.Context, tx pgx.Tx, version int, legacy []OIDCClientRegistration) ([]applicationKey, error) {
	query := "SELECT 'saml' AS protocol, id AS old_id FROM saml_service_providers"
	if version >= 29 {
		query += " UNION ALL SELECT 'oidc', client_id FROM oidc_clients"
	}
	rows, err := tx.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	keys, err := pgx.CollectRows(rows, pgx.RowToStructByPos[applicationKey])
	if err != nil {
		return nil, err
	}
	for _, reg := range legacy {
		keys = append(keys, applicationKey{"oidc", reg.Client.ID})
	}
	slices.SortFunc(keys, func(a, b applicationKey) int {
		if c := cmp.Compare(a.Protocol, b.Protocol); c != 0 {
			return c
		}
		return cmp.Compare(a.OldID, b.OldID)
	})
	return keys, nil
}

// PlanApplicationIDs takes a read-only snapshot. Extending an existing manifest
// retains each assignment so that staged consumer configurations remain valid.
func PlanApplicationIDs(ctx context.Context, databaseURL string, loadLegacy func() ([]OIDCClientRegistration, error), previous []ApplicationIDAssignment) ([]ApplicationIDAssignment, error) {
	c, err := maintenanceConnection(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	defer c.Close(context.Background())
	var plan []ApplicationIDAssignment
	err = pgx.BeginTxFunc(ctx, c, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		version, err := databasePlan(ctx, tx)
		if err != nil {
			return err
		}
		if !version.Supported || version.CurrentVersion >= 32 {
			return errors.New("application ID planning requires a supported pre-cutover schema")
		}
		var legacy []OIDCClientRegistration
		if version.CurrentVersion < 29 {
			legacy, err = loadLegacy()
			if err != nil {
				return err
			}
		}
		keys, err := applicationInventory(ctx, tx, version.CurrentVersion, legacy)
		if err != nil {
			return err
		}
		plan, err = matchApplicationIDs(keys, previous, true)
		return err
	})
	return plan, err
}

func matchApplicationIDs(keys []applicationKey, manifest []ApplicationIDAssignment, generate bool) ([]ApplicationIDAssignment, error) {
	assignments := make(map[applicationKey]string, len(keys))
	reserved := make(map[string]bool, len(keys)+len(manifest))
	for _, key := range keys {
		if _, exists := assignments[key]; exists {
			return nil, fmt.Errorf("duplicate %s inventory ID %q", key.Protocol, key.OldID)
		}
		assignments[key] = ""
		reserved[key.OldID] = true
	}
	for _, row := range manifest {
		key := applicationKey{row.Protocol, row.OldID}
		id, exists := assignments[key]
		if !exists || id != "" || reserved[row.NewID] || !ValidID(row.NewID, ApplicationKind) {
			return nil, fmt.Errorf("unknown, duplicate or invalid assignment for %s %q", row.Protocol, row.OldID)
		}
		assignments[key] = row.NewID
		reserved[row.NewID] = true
	}
	result := make([]ApplicationIDAssignment, 0, len(keys))
	for _, key := range keys {
		id := assignments[key]
		if id == "" {
			if !generate {
				return nil, fmt.Errorf("missing application ID for %s %q", key.Protocol, key.OldID)
			}
			var err error
			for {
				id, err = NewID(ApplicationKind)
				if err != nil {
					return nil, err
				}
				if !reserved[id] {
					break
				}
			}
		}
		reserved[id] = true
		result = append(result, ApplicationIDAssignment{key.Protocol, key.OldID, id})
	}
	return result, nil
}

func stageApplicationIDs(ctx context.Context, tx pgx.Tx, manifest []ApplicationIDAssignment) error {
	keys, err := applicationInventory(ctx, tx, 31, nil)
	if err != nil {
		return err
	}
	assignments, err := matchApplicationIDs(keys, manifest, false)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "CREATE TEMP TABLE application_id_cutover(protocol text, old_id text, new_id text) ON COMMIT DROP"); err != nil {
		return err
	}
	_, err = tx.CopyFrom(ctx, pgx.Identifier{"application_id_cutover"}, []string{"protocol", "old_id", "new_id"}, pgx.CopyFromSlice(len(assignments), func(i int) ([]any, error) {
		row := assignments[i]
		return []any{row.Protocol, row.OldID, row.NewID}, nil
	}))
	return err
}
