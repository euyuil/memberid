// This test-only adapter runs the fixture's real PostgreSQL 18 pg_dump inside
// its disposable container. It is not part of a MemberID distribution.
package main

import (
	"net/url"
	"os"
	"os/exec"
)

func main() {
	dsn, err := url.Parse(os.Getenv("PGDATABASE"))
	if err != nil {
		os.Exit(1)
	}
	name := "postgres"
	if len(dsn.Path) > 1 {
		name = dsn.Path[1:]
	}
	args := []string{"exec", "--env", "PGDATABASE=" + name, "--env", "PGUSER=postgres", os.Getenv("MEMBERID_TEST_PGDUMP_CONTAINER"), "pg_dump"}
	args = append(args, os.Args[1:]...)
	command := exec.Command("docker", args...)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		os.Exit(1)
	}
}
