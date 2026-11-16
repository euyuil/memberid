package recovery

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/jackc/pgservicefile"
	"github.com/jackc/pgx/v5/pgconn"
)

// These options must be carried over separately from pgx's resolved endpoint
// and credentials. pgx consumes TLS file paths when it builds its TLS config.
var dumpOptions = map[string]string{
	"application_name": "PGAPPNAME", "options": "PGOPTIONS",
	"connect_timeout": "PGCONNECT_TIMEOUT", "target_session_attrs": "PGTARGETSESSIONATTRS",
	"sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT", "sslcert": "PGSSLCERT",
	"sslkey": "PGSSLKEY", "sslpassword": "PGSSLPASSWORD", "sslnegotiation": "PGSSLNEGOTIATION", "sslsni": "PGSSLSNI",
	"channel_binding": "PGCHANNELBINDING", "require_auth": "PGREQUIREAUTH", "krbsrvname": "PGKRBSRVNAME",
	"min_protocol_version": "PGMINPROTOCOLVERSION", "max_protocol_version": "PGMAXPROTOCOLVERSION",
}

func dumpEnvironment(databaseURL string) ([]string, func(), error) {
	connection, err := pgconn.ParseConfig(databaseURL)
	if err != nil {
		return nil, nil, errors.New("invalid database connection settings for pg_dump")
	}
	settings, err := dumpConnectionOptions(databaseURL)
	if err != nil {
		return nil, nil, err
	}
	hosts := []string{connection.Host}
	ports := []string{strconv.Itoa(int(connection.Port))}
	for _, fallback := range connection.Fallbacks {
		port := strconv.Itoa(int(fallback.Port))
		// pgx includes separate TLS and plaintext fallbacks for the same address.
		if hosts[len(hosts)-1] != fallback.Host || ports[len(ports)-1] != port {
			hosts = append(hosts, fallback.Host)
			ports = append(ports, port)
		}
	}
	settings["host"], settings["port"] = strings.Join(hosts, ","), strings.Join(ports, ",")
	settings["user"], settings["dbname"] = connection.User, connection.Database
	if settings["dbname"] == "" {
		settings["dbname"] = connection.User
	}
	if connection.User == "" || strings.ContainsAny(connection.Password, "\r\n\x00") {
		return nil, nil, errors.New("database credentials cannot be passed to pg_dump")
	}

	// PGDATABASE is a database name, not an input that libpq expands as a URI.
	// A private service file supplies the connection options without putting them
	// on the command line. Use a separate password file to preserve escaping.
	var service strings.Builder
	service.WriteString("[memberid-backup]\n")
	for key, value := range settings {
		if strings.ContainsAny(value, "\r\n\x00") || strings.TrimSpace(value) != value {
			return nil, nil, errors.New("database connection option cannot be represented in a pg_dump service file")
		}
		service.WriteString(key + "=" + value + "\n")
	}
	directory, err := os.MkdirTemp("", "memberid-pg-dump-")
	if err != nil {
		return nil, nil, errors.New("could not create protected pg_dump settings directory")
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	servicePath := filepath.Join(directory, "pg_service.conf")
	passPath := filepath.Join(directory, "pgpass")
	var pass string
	if connection.Password != "" {
		escaped := strings.NewReplacer(`\`, `\\`, ":", `\:`).Replace(connection.Password)
		pass = "*:*:*:*:" + escaped + "\n"
	}
	if err := os.WriteFile(servicePath, []byte(service.String()), 0600); err != nil {
		cleanup()
		return nil, nil, errors.New("could not write protected pg_dump service file")
	}
	if err := os.WriteFile(passPath, []byte(pass), 0600); err != nil {
		cleanup()
		return nil, nil, errors.New("could not write protected pg_dump password file")
	}
	environment := make([]string, 0, len(os.Environ())+3)
	for _, pair := range os.Environ() {
		key, _, _ := strings.Cut(pair, "=")
		key = strings.ToUpper(key)
		if !strings.HasPrefix(key, "PG") && key != "MEMBERID_DATABASE_URL" {
			environment = append(environment, pair)
		}
	}
	environment = append(environment, "PGSERVICE=memberid-backup", "PGSERVICEFILE="+servicePath, "PGPASSFILE="+passPath)
	return environment, cleanup, nil
}

func dumpConnectionOptions(databaseURL string) (map[string]string, error) {
	explicit, err := connectionStringOptions(databaseURL)
	if err != nil {
		return nil, err
	}
	serviceName := os.Getenv("PGSERVICE")
	if name, present := explicit["service"]; present {
		serviceName = name
	}
	var service map[string]string
	if serviceName != "" {
		path, present := explicit["servicefile"]
		if !present {
			path = os.Getenv("PGSERVICEFILE")
			if path == "" {
				home, _ := os.UserHomeDir()
				path = filepath.Join(home, ".pg_service.conf")
			}
		}
		file, err := pgservicefile.ReadServicefile(path)
		if err != nil {
			return nil, errors.New("could not read database service settings for pg_dump")
		}
		entry, err := file.GetService(serviceName)
		if err != nil {
			return nil, errors.New("could not resolve database service settings for pg_dump")
		}
		service = entry.Settings
	}
	settings := make(map[string]string)
	// Match the default TLS files used by pgx even when libpq cannot look up
	// the operating-system account of the process running pg_dump.
	home, _ := os.UserHomeDir()
	certDirectory := filepath.Join(home, ".postgresql")
	if runtime.GOOS == "windows" {
		home = os.Getenv("APPDATA")
		certDirectory = filepath.Join(home, "postgresql")
	}
	if home != "" {
		cert := filepath.Join(certDirectory, "postgresql.crt")
		key := filepath.Join(certDirectory, "postgresql.key")
		if _, certErr := os.Stat(cert); certErr == nil {
			if _, keyErr := os.Stat(key); keyErr == nil {
				settings["sslcert"], settings["sslkey"] = cert, key
			}
		}
		root := filepath.Join(certDirectory, "root.crt")
		if _, err := os.Stat(root); err == nil {
			settings["sslrootcert"] = root
		}
	}
	for key, envName := range dumpOptions {
		if value := os.Getenv(envName); value != "" {
			settings[key] = value
		}
		if value, present := service[key]; present {
			settings[key] = value
		}
		if value, present := explicit[key]; present {
			settings[key] = value
		}
	}
	// Match pgx's TLS choices when it promotes the default mode.
	if settings["sslrootcert"] == "system" {
		settings["sslmode"] = "verify-full"
	} else if mode := settings["sslmode"]; settings["sslnegotiation"] == "direct" && (mode == "" || mode == "prefer") {
		settings["sslmode"] = "require"
	}
	// pgx does not negotiate GSS transport encryption. libpq otherwise prefers
	// it over TLS when Kerberos credentials are available.
	settings["gssencmode"] = "disable"
	return settings, nil
}

// Read options from the URI query or PostgreSQL's keyword/value syntax. pgx
// resolves the database, username, password and addresses separately.
func connectionStringOptions(dsn string) (map[string]string, error) {
	options := make(map[string]string)
	invalid := errors.New("invalid database connection options for pg_dump")
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		_, query, _ := strings.Cut(dsn, "?")
		var sslAlias bool
		for _, pair := range strings.Split(query, "&") {
			if pair == "" {
				continue
			}
			key, value, _ := strings.Cut(pair, "=")
			key, keyErr := url.PathUnescape(key)
			value, valueErr := url.PathUnescape(value)
			if keyErr != nil || valueErr != nil {
				return nil, invalid
			}
			if key == "ssl" || key == "sslmode" {
				sslAlias = key == "ssl" && value == "true"
			}
			options[key] = value
		}
		if sslAlias {
			options["sslmode"] = "require"
		}
		return options, nil
	}

	const space = " \t\r\n\v\f"
	for dsn = strings.TrimLeft(dsn, space); dsn != ""; dsn = strings.TrimLeft(dsn, space) {
		key, rest, ok := strings.Cut(dsn, "=")
		if !ok {
			return nil, invalid
		}
		dsn = strings.TrimLeft(rest, space)
		var value strings.Builder
		quoted := strings.HasPrefix(dsn, "'")
		if quoted {
			dsn = dsn[1:]
		}
		closed := !quoted
		for len(dsn) != 0 {
			char := dsn[0]
			if !quoted && strings.ContainsRune(space, rune(char)) {
				break
			}
			dsn = dsn[1:]
			if quoted && char == '\'' {
				closed = true
				break
			}
			if char == '\\' {
				if dsn == "" {
					break
				}
				char, dsn = dsn[0], dsn[1:]
			}
			value.WriteByte(char)
		}
		if !closed {
			return nil, invalid
		}
		options[strings.Trim(key, space)] = value.String()
	}
	return options, nil
}
