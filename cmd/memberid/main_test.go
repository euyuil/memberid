package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCommands(t *testing.T) {
	for _, test := range []struct {
		name      string
		args      []string
		wantError bool
	}{
		{"version", []string{"version"}, false},
		{"version arguments", []string{"version", "extra"}, true},
		{"missing command", nil, true},
		{"unknown command", []string{"unknown"}, true},
		{"unknown flag", []string{"serve", "--unknown"}, true},
		{"positional argument", []string{"serve", "extra"}, true},
		{"invalid address", []string{"serve", "--listen", "invalid"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := run(context.Background(), test.args, &stdout, &stderr)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, want error = %v", err, test.wantError)
			}
			if test.name == "version" && stdout.String() != "MemberID dev\n" {
				t.Fatalf("version output = %q", stdout.String())
			}
		})
	}
}

func TestServeStopsWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if err := run(ctx, []string{"serve", "--listen", "127.0.0.1:0"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout.String(), "MemberID listening on 127.0.0.1:") {
		t.Fatalf("unexpected listen output: %q", stdout.String())
	}
}
