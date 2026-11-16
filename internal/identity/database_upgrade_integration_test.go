//go:build integration

package identity

import (
	"context"
	_ "embed"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/euyuil/memberid/internal/testdb"
	"github.com/jackc/pgx/v5"
)

// Frozen from a7c3ebed19d4cfb7196108f80c6360fc9449f882, before migrations.
//
//go:embed testdata/schema26.sql
var schema26 string

func TestMaintenanceDoesNotBlockNormalAdministration(t *testing.T) {
	dsn := testdb.Create(t)
	if err := Initialize(t.Context(), dsn); err != nil {
		t.Fatal(err)
	}
	first, err := Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, err := first.CreateOrganization(ctx, OperatorPrincipal(), "", "Synthetic organization"); err != nil {
		t.Fatal("maintenance lock interfered with an ordinary management operation", err)
	}
}

func TestInitializationRefusesServingDatabasePromptly(t *testing.T) {
	dsn := testdb.Create(t)
	if err := Initialize(t.Context(), dsn); err != nil {
		t.Fatal(err)
	}
	store, err := Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := Initialize(ctx, dsn); !errors.Is(err, ErrDatabaseNotEmpty) {
		t.Fatal("initialization waited on a serving store or changed data", err)
	}
}

func baselineDatabase(t *testing.T) string {
	t.Helper()
	dsn := testdb.Create(t)
	c, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	if _, err = c.Exec(t.Context(), schema26); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Exec(t.Context(), "UPDATE organizations SET name='retained organization' WHERE id='org_system'"); err != nil {
		t.Fatal(err)
	}
	return dsn
}

func syntheticBackup(context.Context, string) (UpgradeBackup, error) {
	return UpgradeBackup{ID: "synthetic-backup", SHA256: strings.Repeat("a", 64)}, nil
}

func assertBaseline(t *testing.T, dsn string) {
	t.Helper()
	c, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	var version int
	var name string
	var journal *string
	if err = c.QueryRow(t.Context(), "SELECT version,name,to_regclass('public.database_upgrades')::text FROM memberid_schema,organizations WHERE id='org_system'").Scan(&version, &name, &journal); err != nil || version != 26 || name != "retained organization" || journal != nil {
		t.Fatal("baseline changed", version, name, journal, err)
	}
}

func TestDatabaseUpgradeAtomicFailureAndRetry(t *testing.T) {
	dsn := baselineDatabase(t)
	if _, err := Open(t.Context(), dsn); !errors.Is(err, ErrSchemaRequired) {
		t.Fatal("startup accepted old schema", err)
	}
	plan, err := InspectDatabase(t.Context(), dsn)
	if err != nil || !plan.Supported || plan.CurrentVersion != 26 || !plan.UpgradeRequired {
		t.Fatal(plan, err)
	}
	if _, err := UpgradeDatabase(t.Context(), dsn, func(context.Context, string) (UpgradeBackup, error) {
		return UpgradeBackup{}, errors.New("synthetic failed backup")
	}); err == nil {
		t.Fatal("accepted failed backup")
	}
	assertBaseline(t, dsn)
	c, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Exec(t.Context(), `CREATE FUNCTION fail_upgrade() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic migration failure'; END $$; CREATE EVENT TRIGGER fail_upgrade ON ddl_command_end WHEN TAG IN ('ALTER TABLE') EXECUTE FUNCTION fail_upgrade();`)
	if err != nil {
		t.Fatal(err)
	}
	c.Close(context.Background())
	if _, err := UpgradeDatabase(t.Context(), dsn, syntheticBackup); err == nil {
		t.Fatal("injected migration failure succeeded")
	}
	assertBaseline(t, dsn)
	c, err = pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Exec(t.Context(), "DROP EVENT TRIGGER fail_upgrade; DROP FUNCTION fail_upgrade()"); err != nil {
		t.Fatal(err)
	}
	c.Close(context.Background())
	result, err := UpgradeDatabase(t.Context(), dsn, syntheticBackup)
	if err != nil || !result.Upgraded || result.CurrentVersion != 27 {
		t.Fatal(result, err)
	}
	result, err = UpgradeDatabase(t.Context(), dsn, func(context.Context, string) (UpgradeBackup, error) {
		t.Error("repeat created another backup")
		return UpgradeBackup{}, nil
	})
	if err != nil || result.Upgraded || result.UpgradeRequired {
		t.Fatal(result, err)
	}
	store, err := Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var count int
	var name string
	if err := store.pool.QueryRow(t.Context(), "SELECT count(*) FROM database_upgrades WHERE from_version=26 AND to_version=27 AND backup_id='synthetic-backup'").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if err := store.pool.QueryRow(t.Context(), "SELECT name FROM organizations WHERE id='org_system'").Scan(&name); err != nil || name != "retained organization" {
		t.Fatal(name, err)
	}
	freshDSN := testdb.Create(t)
	if err := Initialize(t.Context(), freshDSN); err != nil {
		t.Fatal(err)
	}
	fresh, err := Open(t.Context(), freshDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	for _, query := range []string{
		`SELECT table_name||'.'||column_name||':'||udt_name||':'||is_nullable||':'||coalesce(column_default,'') FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,column_name`,
		`SELECT conrelid::regclass::text||':'||conname||':'||pg_get_constraintdef(oid) FROM pg_constraint WHERE connamespace='public'::regnamespace ORDER BY conrelid::regclass::text,conname`,
		`SELECT indexname||':'||indexdef FROM pg_indexes WHERE schemaname='public' ORDER BY indexname`,
	} {
		left, err := store.pool.Query(t.Context(), query)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := pgx.CollectRows(left, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		right, err := fresh.pool.Query(t.Context(), query)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := pgx.CollectRows(right, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatal("upgraded and freshly initialized schemas differ", actual, expected)
		}
	}
}

func TestDatabaseUpgradeMaintenanceAndConcurrentAttempts(t *testing.T) {
	dsn := baselineDatabase(t)
	legacy, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UpgradeDatabase(t.Context(), dsn, syntheticBackup); !errors.Is(err, ErrDatabaseBusy) {
		t.Fatal("legacy client did not block upgrade", err)
	}
	legacy.Close(context.Background())
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := UpgradeDatabase(t.Context(), dsn, func(ctx context.Context, _ string) (UpgradeBackup, error) {
			close(entered)
			<-release
			return syntheticBackup(ctx, "")
		})
		done <- err
	}()
	<-entered
	if _, err := UpgradeDatabase(t.Context(), dsn, syntheticBackup); !errors.Is(err, ErrDatabaseBusy) {
		t.Error("concurrent upgrade admitted", err)
	}
	if s, err := Open(t.Context(), dsn); !errors.Is(err, ErrDatabaseBusy) {
		if s != nil {
			s.Close()
		}
		t.Error("server opened during maintenance", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseUpgradeUnsupportedAndCancellation(t *testing.T) {
	for _, version := range []int{25, 28} {
		dsn := testdb.Create(t)
		c, err := pgx.Connect(t.Context(), dsn)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = c.Exec(t.Context(), "CREATE TABLE memberid_schema(version integer)"); err != nil {
			t.Fatal(err)
		}
		if _, err = c.Exec(t.Context(), "INSERT INTO memberid_schema VALUES($1)", version); err != nil {
			t.Fatal(err)
		}
		c.Close(context.Background())
		if _, err := UpgradeDatabase(t.Context(), dsn, func(context.Context, string) (UpgradeBackup, error) {
			t.Error("unsupported version backed up")
			return UpgradeBackup{}, nil
		}); !errors.Is(err, ErrUpgradeUnsupported) {
			t.Fatal(err)
		}
		plan, err := InspectDatabase(t.Context(), dsn)
		if err != nil || plan.Supported || plan.CurrentVersion != version {
			t.Fatal(plan, err)
		}
	}
	dsn := baselineDatabase(t)
	ctx, cancel := context.WithCancel(t.Context())
	if _, err := UpgradeDatabase(ctx, dsn, func(context.Context, string) (UpgradeBackup, error) { cancel(); return syntheticBackup(ctx, "") }); err == nil {
		t.Fatal("canceled upgrade succeeded")
	}
	assertBaseline(t, dsn)
}
