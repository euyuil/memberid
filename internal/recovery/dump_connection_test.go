package recovery

import (
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jackc/pgservicefile"
)

func TestDumpEnvironmentUsesProtectedFiles(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	t.Setenv("PGHOST", "other.example.test")
	t.Setenv("PGUSER", "other_user")
	t.Setenv("PGPASSWORD", "inherited-placeholder")
	t.Setenv("PGSSLMODE", "disable")
	password := ` example:\fixture `
	connection := url.URL{
		Scheme: "postgresql", User: url.UserPassword("backup_role", password),
		Host: "backup.example.test:6432", Path: "/members",
		RawQuery: "sslrootcert=system&connect_timeout=8&channel_binding=require",
	}
	t.Setenv("MEMBERID_DATABASE_URL", connection.String())
	environment, cleanup, err := dumpEnvironment(connection.String())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	variables := make(map[string]string)
	for _, pair := range environment {
		key, value, _ := strings.Cut(pair, "=")
		variables[key] = value
	}
	for _, key := range []string{"MEMBERID_DATABASE_URL", "PGHOST", "PGUSER", "PGPASSWORD", "PGSSLMODE"} {
		if _, present := variables[key]; present {
			t.Errorf("inherited %s into pg_dump", key)
		}
	}
	serviceFile, err := pgservicefile.ReadServicefile(variables["PGSERVICEFILE"])
	if err != nil {
		t.Fatal(err)
	}
	service, err := serviceFile.GetService(variables["PGSERVICE"])
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"host": "backup.example.test", "port": "6432", "dbname": "members", "user": "backup_role",
		"sslmode": "verify-full", "sslrootcert": "system", "connect_timeout": "8", "channel_binding": "require",
	} {
		if service.Settings[key] != want {
			t.Errorf("did not preserve %s", key)
		}
	}
	if _, present := service.Settings["password"]; present {
		t.Fatal("wrote the database password to the connection settings")
	}
	stored, err := os.ReadFile(variables["PGPASSFILE"])
	if err != nil || string(stored) != "*:*:*:*: example\\:\\\\fixture \n" {
		t.Fatal("the private password file did not preserve the password bytes")
	}
	if runtime.GOOS != "windows" {
		for key, mode := range map[string]os.FileMode{"PGSERVICEFILE": 0600, "PGPASSFILE": 0600} {
			info, err := os.Stat(variables[key])
			if err != nil || info.Mode().Perm() != mode {
				t.Errorf("expected owner-only permissions on %s", key)
			}
		}
	}
	cleanup()
	if _, err := os.Stat(filepath.Dir(variables["PGSERVICEFILE"])); !os.IsNotExist(err) {
		t.Fatal("temporary connection settings survived cleanup")
	}
}

func TestDumpOptionsPreserveServiceAndKeywordOverrides(t *testing.T) {
	t.Setenv("PGSERVICE", "")
	t.Setenv("PGSSLMODE", "disable")
	servicePath := filepath.Join(t.TempDir(), "pg_service.conf")
	if err := os.WriteFile(servicePath, []byte("[backup]\nsslmode=require\nconnect_timeout=9\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGSERVICEFILE", servicePath)
	settings, err := dumpConnectionOptions(`service = backup options='-c application_name=backup\ fixture' sslmode='verify-full'`)
	if err != nil {
		t.Fatal(err)
	}
	if settings["sslmode"] != "verify-full" || settings["connect_timeout"] != "9" || settings["options"] != "-c application_name=backup fixture" {
		t.Fatal("did not preserve service options and explicit overrides")
	}
	settings, err = dumpConnectionOptions(`sslmode=prefer sslnegotiation=direct`)
	if err != nil || settings["sslmode"] != "require" {
		t.Fatal("did not preserve the TLS mode for direct negotiation")
	}
}
