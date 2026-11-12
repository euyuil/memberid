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
	"os/signal"
	"syscall"
	"time"

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
		return errors.New("usage: memberid <version|serve>")
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			return errors.New("version takes no arguments")
		}
		fmt.Fprintln(stdout, "MemberID", version)
		return nil
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		flags.SetOutput(stderr)
		address := flags.String("listen", "127.0.0.1:8080", "HTTP listen address")
		if err := flags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("serve takes flags only")
		}
		listener, err := net.Listen("tcp", *address)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
		httpServer := server.New()
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
	default:
		return fmt.Errorf("unknown command %q; use version or serve", args[0])
	}
}
