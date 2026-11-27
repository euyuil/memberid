package identity

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const SchemaVersion = 36

// The two-int key space is separate from existing bigint initialization,
// administration and worker locks. MID identifies this maintenance namespace.
const databaseMaintenanceNamespace int32 = 0x4d4944
const databaseMaintenanceLock int32 = 1

var ErrDatabaseBusy = errors.New("database maintenance requires all other database clients to be stopped")
var ErrUpgradeUnsupported = errors.New("unsupported database upgrade; first supported baseline is schema 26")

//go:embed migrations/0027_upgrade_history.sql
var upgrade27 string

//go:embed migrations/0028_feishu_memberships.sql
var upgrade28 string

//go:embed migrations/0029_oidc_clients.sql
var upgrade29 string

//go:embed migrations/0030_organization_login_slugs.sql
var upgrade30 string

//go:embed migrations/0031_oidc_client_owners.sql
var upgrade31 string

//go:embed migrations/0032_generated_application_ids.sql
var upgrade32 string

//go:embed migrations/0033_oidc_publication.sql
var upgrade33 string

//go:embed migrations/0034_oidc_organization_scope.sql
var upgrade34 string

//go:embed migrations/0035_shared_saml.sql
var upgrade35 string

//go:embed migrations/0036_provider_login_names.sql
var upgrade36 string

type DatabasePlan struct {
	CurrentVersion  int  `json:"currentVersion"`
	TargetVersion   int  `json:"targetVersion"`
	Supported       bool `json:"supported"`
	UpgradeRequired bool `json:"upgradeRequired"`
}

type UpgradeBackup struct {
	ID     string `json:"backupId"`
	SHA256 string `json:"backupSha256"`
}

type UpgradePreparation struct {
	Backup         UpgradeBackup
	OIDCClients    []OIDCClientRegistration
	ApplicationIDs []ApplicationIDAssignment
}

type UpgradeResult struct {
	DatabasePlan
	Upgraded bool `json:"upgraded"`
	UpgradeBackup
}

func maintenanceConnection(ctx context.Context, databaseURL string) (*pgx.Conn, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, ErrDatabaseConfiguration
	}
	c, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, ErrDatabaseConfiguration
	}
	c.RuntimeParams["search_path"] = "public"
	c.RuntimeParams["application_name"] = "memberid-database-upgrade"
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = 5 * time.Second
	}
	return pgx.ConnectConfig(ctx, c)
}

func databasePlan(ctx context.Context, db queryer) (DatabasePlan, error) {
	plan := DatabasePlan{TargetVersion: SchemaVersion}
	var count int
	if err := db.QueryRow(ctx, "SELECT count(*),coalesce(min(version),0) FROM memberid_schema").Scan(&count, &plan.CurrentVersion); err != nil {
		return plan, err
	}
	if count != 1 {
		return plan, ErrSchemaRequired
	}
	plan.Supported = plan.CurrentVersion >= 26 && plan.CurrentVersion <= SchemaVersion
	plan.UpgradeRequired = plan.CurrentVersion != SchemaVersion
	return plan, nil
}

// InspectDatabase reads the version without initializing or modifying the database.
func InspectDatabase(ctx context.Context, databaseURL string) (DatabasePlan, error) {
	c, err := maintenanceConnection(ctx, databaseURL)
	if err != nil {
		return DatabasePlan{}, err
	}
	defer c.Close(context.Background())
	var locked bool
	if err := c.QueryRow(ctx, "SELECT pg_try_advisory_lock_shared($1,$2)", databaseMaintenanceNamespace, databaseMaintenanceLock).Scan(&locked); err != nil {
		return DatabasePlan{}, err
	}
	if !locked {
		return DatabasePlan{}, ErrDatabaseBusy
	}
	return databasePlan(ctx, c)
}

func requireStoppedClients(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SELECT pg_stat_clear_snapshot()"); err != nil {
		return err
	}
	var busy bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND pid<>pg_backend_pid() AND (backend_type='client backend' OR backend_type IS NULL))`).Scan(&busy); err != nil {
		return err
	}
	if busy {
		return ErrDatabaseBusy
	}
	return nil
}

// UpgradeDatabase holds write-excluding table locks while the caller creates a
// consistent database/configuration backup. No SQL changes commit without it.
// The callback must fail if the protected files change while being copied.
func UpgradeDatabase(ctx context.Context, databaseURL string, prepare func(context.Context, string, int) (UpgradePreparation, error)) (UpgradeResult, error) {
	var result UpgradeResult
	c, err := maintenanceConnection(ctx, databaseURL)
	if err != nil {
		return result, err
	}
	defer c.Close(context.Background())
	err = pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
		var locked bool
		if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1,$2)", databaseMaintenanceNamespace, databaseMaintenanceLock).Scan(&locked); err != nil {
			return err
		}
		if !locked {
			return ErrDatabaseBusy
		}
		plan, err := databasePlan(ctx, tx)
		if err != nil {
			return err
		}
		result.DatabasePlan = plan
		if !plan.Supported {
			return ErrUpgradeUnsupported
		}
		if !plan.UpgradeRequired {
			return nil
		}
		if prepare == nil {
			return errors.New("a consistent recovery backup is required")
		}
		var serverVersion int
		if err := tx.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&serverVersion); err != nil {
			return err
		}
		if serverVersion < 180000 || serverVersion >= 190000 {
			return errors.New("database upgrade requires PostgreSQL 18")
		}
		if err := requireStoppedClients(ctx, tx); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
		if err != nil {
			return err
		}
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for _, name := range names {
			if _, err := tx.Exec(ctx, "LOCK TABLE "+pgx.Identifier{"public", name}.Sanitize()+" IN SHARE MODE NOWAIT"); err != nil {
				return err
			}
		}
		var snapshot string
		if err := tx.QueryRow(ctx, "SELECT pg_export_snapshot()").Scan(&snapshot); err != nil {
			return err
		}
		prepared, err := prepare(ctx, snapshot, plan.CurrentVersion)
		if err != nil {
			return err
		}
		receipt := prepared.Backup
		digest, err := hex.DecodeString(receipt.SHA256)
		if err != nil || len(digest) != 32 || receipt.ID == "" {
			return errors.New("invalid recovery backup receipt")
		}
		// Block schema-26 startup's version read before the final client check.
		// A late old process sees the new version only after commit and refuses startup.
		if _, err := tx.Exec(ctx, "LOCK TABLE memberid_schema IN ACCESS EXCLUSIVE MODE NOWAIT"); err != nil {
			return err
		}
		if err := requireStoppedClients(ctx, tx); err != nil {
			return err
		}
		for _, migration := range []struct {
			from, to int
			sql      string
		}{{26, 27, upgrade27}, {27, 28, upgrade28}, {28, 29, upgrade29}, {29, 30, upgrade30}, {30, 31, upgrade31}, {31, 32, upgrade32}, {32, 33, upgrade33}, {33, 34, upgrade34}, {34, 35, upgrade35}, {35, 36, upgrade36}} {
			if migration.from < plan.CurrentVersion {
				continue
			}
			if migration.to == 32 {
				if plan.CurrentVersion < 29 {
					if err := importOIDCClients(ctx, tx, prepared.OIDCClients); err != nil {
						return err
					}
				}
				if err := stageApplicationIDs(ctx, tx, prepared.ApplicationIDs); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, migration.sql); err != nil {
				return err
			}
			migrationHash := sha256.Sum256([]byte(migration.sql))
			if _, err := tx.Exec(ctx, "INSERT INTO database_upgrades(from_version,to_version,migration_sha256,backup_id,backup_sha256) VALUES($1,$2,$3,$4,$5)", migration.from, migration.to, hex.EncodeToString(migrationHash[:]), receipt.ID, receipt.SHA256); err != nil {
				return err
			}
		}
		result.Upgraded, result.UpgradeBackup = true, receipt
		result.CurrentVersion, result.UpgradeRequired = SchemaVersion, false
		return nil
	})
	if err != nil {
		return UpgradeResult{}, err
	}
	return result, nil
}
