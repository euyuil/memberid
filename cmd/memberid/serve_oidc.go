package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/euyuil/memberid/internal/config"
	"github.com/euyuil/memberid/internal/identity"
	"github.com/euyuil/memberid/internal/oidcprovider"
	"github.com/euyuil/memberid/internal/sms"
)

func authenticationHandler(ctx context.Context, directory string) (http.Handler, func(), error) {
	loaded, err := config.Load(directory)
	if err != nil {
		return nil, nil, err
	}
	if len(loaded.Clients) == 0 {
		return nil, nil, errors.New("register at least one OIDC client before starting authentication")
	}
	sender, err := sms.FromEnvironment(os.Getenv)
	if err != nil {
		return nil, nil, err
	}
	if sender == nil {
		return nil, nil, errors.New("enable and configure phone authentication before starting the current OIDC provider")
	}
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return nil, nil, err
	}
	key, _ := base64.StdEncoding.DecodeString(loaded.Secrets.PhoneCodeKey)
	verifier, err := identity.NewPhoneVerifier(store, key, sender)
	if err != nil {
		store.Close()
		return nil, nil, err
	}
	provider, err := oidcprovider.New(loaded, store, verifier)
	if err != nil {
		store.Close()
		return nil, nil, err
	}
	cleanup, cancel := context.WithCancel(ctx)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-cleanup.Done():
				return
			case <-ticker.C:
				timeout, stop := context.WithTimeout(cleanup, 10*time.Second)
				if err := provider.Cleanup(timeout); err != nil && cleanup.Err() == nil {
					slog.Warn("Expired authentication record cleanup failed")
				}
				stop()
			}
		}
	}()
	return provider, func() { cancel(); <-finished; store.Close() }, nil
}
