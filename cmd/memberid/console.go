package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/console"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/server"
)

func serveConsole(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if !console.AssetsReady() {
		return errors.New("console assets are missing; run npm --prefix web ci and npm --prefix web run build before building MemberID")
	}
	f := flag.NewFlagSet("serve-console", flag.ContinueOnError)
	f.SetOutput(stderr)
	directory := f.String("directory", "", "protected installation directory")
	listen := f.String("listen", "127.0.0.1:8082", "console listen address")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *directory == "" || f.NArg() != 0 {
		return errors.New("serve-console requires --directory")
	}
	loaded, err := config.Load(*directory)
	if err != nil {
		return err
	}
	var settings console.Settings
	if err = config.ReadJSON(filepath.Join(*directory, "console.json"), &settings); err != nil {
		return err
	}
	if settings.ClientSecretFile == "" || filepath.Base(settings.ClientSecretFile) != settings.ClientSecretFile || strings.ContainsAny(settings.ClientSecretFile, `/\:`) {
		return errors.New("console client secret must be a protected local filename")
	}
	data, err := os.ReadFile(filepath.Join(*directory, settings.ClientSecretFile))
	if err != nil {
		return err
	}
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer store.Close()
	h, err := console.New(ctx, store, loaded, settings, strings.TrimSpace(string(data)))
	if err != nil {
		return err
	}
	s := server.New()
	s.Handler = h
	return serveHTTP(ctx, *listen, s, stdout)
}
