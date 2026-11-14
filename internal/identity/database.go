package identity

import (
	"context"
	_ "embed"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var initialSchema string

type Store struct{ pool *pgxpool.Pool }

var ErrDatabaseConfiguration = errors.New("invalid database connection settings")

// Initialize only applies the initial schema to an explicitly selected empty database.
func Initialize(ctx context.Context, databaseURL string) error {
	if strings.TrimSpace(databaseURL) == "" {
		return ErrDatabaseConfiguration
	}
	config, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return ErrDatabaseConfiguration
	}
	config.RuntimeParams["search_path"] = "public"
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 5 * time.Second
	}
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return err
	}
	defer connection.Close(context.Background())
	return pgx.BeginFunc(ctx, connection, func(transaction pgx.Tx) error {
		if _, err := transaction.Exec(ctx, "SELECT pg_advisory_xact_lock(782348912)"); err != nil {
			return err
		}
		var populated bool
		err := transaction.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg_%')").Scan(&populated)
		if err != nil {
			return err
		}
		if populated {
			return ErrDatabaseNotEmpty
		}
		_, err = transaction.Exec(ctx, initialSchema)
		return err
	})
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, ErrDatabaseConfiguration
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, ErrDatabaseConfiguration
	}
	config.ConnConfig.RuntimeParams["search_path"] = "public"
	if config.ConnConfig.ConnectTimeout == 0 {
		config.ConnConfig.ConnectTimeout = 5 * time.Second
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	var version int
	if err = pool.QueryRow(ctx, "SELECT version FROM memberid_schema").Scan(&version); err != nil || version != 16 {
		pool.Close()
		var postgresError *pgconn.PgError
		if err == nil || errors.Is(err, pgx.ErrNoRows) || errors.As(err, &postgresError) && postgresError.Code == "42P01" {
			return nil, ErrSchemaRequired
		}
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (store *Store) Close() { store.pool.Close() }

func storageError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "23505":
			return ErrConflict
		case "23503", "23514", "23502":
			return ErrInvalid
		}
	}
	return err
}
