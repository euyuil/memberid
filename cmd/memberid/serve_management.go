package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/management"
	"github.com/euyuil/memberid/internal/server"
)

func serveManagement(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("serve-management", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "protected installation directory")
	address := flags.String("listen", "127.0.0.1:8081", "private management HTTP listen address")
	private := flags.Bool("allow-private-listen", false, "explicitly allow an isolated private-network or container listener")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *directory == "" {
		return errors.New("serve-management requires --directory and takes flags only")
	}
	if err := managementAddress(*address, *private); err != nil {
		return err
	}
	loaded, err := config.Load(*directory)
	if err != nil {
		return err
	}
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer store.Close()
	handler, err := management.New(store, loaded.Secrets.ManagementSecretSHA256)
	if err != nil {
		return err
	}
	httpServer := server.New()
	httpServer.Handler = handler
	return serveHTTP(ctx, *address, httpServer, stdout)
}

func managementAddress(address string, allowPrivate bool) error {
	host, _, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() && !(allowPrivate && (ip.IsPrivate() || ip.IsUnspecified())) {
		return errors.New("management requires a literal loopback address; private or wildcard addresses require --allow-private-listen and network isolation")
	}
	return nil
}

func serveHTTP(ctx context.Context, address string, httpServer *http.Server, stdout io.Writer) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	finished := make(chan error, 1)
	go func() { finished <- httpServer.Serve(listener) }()
	fmt.Fprintln(stdout, "MemberID listening on", listener.Addr())
	select {
	case err := <-finished:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdown); err != nil {
			_ = httpServer.Close()
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
}
