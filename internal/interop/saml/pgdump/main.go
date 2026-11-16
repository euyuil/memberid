// This test-only adapter runs the fixture's real PostgreSQL 18 pg_dump inside
// its disposable container. It is not part of a MemberID distribution.
package main

import (
	"archive/tar"
	"bytes"
	"os"
	"os/exec"
)

func main() {
	container := os.Getenv("MEMBERID_TEST_PGDUMP_CONTAINER")
	args := []string{"exec", "-i", "--user", "65532:65532", container}
	var input bytes.Buffer
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		args = append(args, "pg_dump", "--version")
	} else {
		archive := tar.NewWriter(&input)
		for name, variable := range map[string]string{"pg_service.conf": "PGSERVICEFILE", "pgpass": "PGPASSFILE"} {
			contents, err := os.ReadFile(os.Getenv(variable))
			if err != nil || archive.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(contents))}) != nil {
				os.Exit(1)
			}
			if _, err := archive.Write(contents); err != nil {
				os.Exit(1)
			}
		}
		if archive.Close() != nil {
			os.Exit(1)
		}
		// Only the loopback address and published port differ inside the fixture
		// container. In particular the adapter supplies no database or user.
		const dump = `set -eu
umask 077
directory=$(mktemp -d)
trap 'rm -rf "$directory"' EXIT
tar -xf - -C "$directory"
export PGSERVICE="$1" PGSERVICEFILE="$directory/pg_service.conf" PGPASSFILE="$directory/pgpass"
shift
pg_dump --host=127.0.0.1 --port=5432 "$@"`
		args = append(args, "sh", "-c", dump, "pgdump", os.Getenv("PGSERVICE"))
		args = append(args, os.Args[1:]...)
	}
	command := exec.Command("docker", args...)
	command.Stdin = &input
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		os.Exit(1)
	}
}
