package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/euyuil/memberid/internal/server"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "memberid:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: memberid <version|serve|serve-management|config|client|database|organization|member|administrator|factor|grant|dingtalk>")
	}
	switch args[0] {
	case "administrator":
		return manageAdministrator(ctx, args[1:], stdout, stderr)
	case "dingtalk":
		return manageDingTalk(ctx, args[1:], stdout, stderr)
	case "grant":
		return manageGrant(ctx, args[1:], stdout, stderr)
	case "config", "client":
		return configure(args, stdout, stderr)
	case "database", "organization", "member", "factor":
		return manage(ctx, args, stdout, stderr)
	case "version":
		if len(args) != 1 {
			return errors.New("version takes no arguments")
		}
		fmt.Fprintln(stdout, "MemberID", version)
		return nil
	case "serve-management":
		return serveManagement(ctx, args[1:], stdout, stderr)
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		flags.SetOutput(stderr)
		address := flags.String("listen", "127.0.0.1:8080", "HTTP listen address")
		directory := flags.String("directory", "", "protected installation directory for OIDC; omit for health-only mode")
		if err := flags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("serve takes flags only")
		}
		httpServer := server.New()
		if *directory != "" {
			handler, closeStore, err := authenticationHandler(ctx, *directory)
			if err != nil {
				return err
			}
			defer closeStore()
			httpServer.Handler = handler
		}
		return serveHTTP(ctx, *address, httpServer, stdout)
	default:
		return fmt.Errorf("unknown command %q; use version or serve", args[0])
	}
}
