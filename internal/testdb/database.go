//go:build integration

package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

func Create(t testing.TB) string {
	t.Helper()
	source := os.Getenv("MEMBERID_TEST_DATABASE_URL")
	parsed, err := url.Parse(source)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" {
		t.Fatal("MEMBERID_TEST_DATABASE_URL must name a disposable PostgreSQL test server")
	}
	admin, err := pgx.Connect(context.Background(), source)
	if err != nil {
		t.Fatal("connect to test database:", err)
	}
	var entropy [12]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		admin.Close(context.Background())
		t.Fatal(err)
	}
	name := "memberid_test_" + hex.EncodeToString(entropy[:])
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(context.Background(), "CREATE DATABASE "+quoted); err != nil {
		admin.Close(context.Background())
		t.Fatal("create isolated test database:", err)
	}
	t.Cleanup(func() {
		defer admin.Close(context.Background())
		if _, err := admin.Exec(context.Background(), "DROP DATABASE "+quoted); err != nil {
			t.Error("remove owned test database:", err)
		}
	})
	parsed.Path = "/" + name
	return parsed.String()
}
