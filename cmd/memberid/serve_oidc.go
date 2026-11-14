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
	"github.com/euyuil/memberid/internal/dingtalk"
	"github.com/euyuil/memberid/internal/feishu"
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
	dingTalkEnabled := os.Getenv("MEMBERID_DINGTALK_ENABLED")
	if dingTalkEnabled != "" && dingTalkEnabled != "false" && dingTalkEnabled != "true" {
		return nil, nil, errors.New("MEMBERID_DINGTALK_ENABLED must be true or false")
	}
	feishuEnabled := os.Getenv("MEMBERID_FEISHU_ENABLED")
	if feishuEnabled != "" && feishuEnabled != "false" && feishuEnabled != "true" {
		return nil, nil, errors.New("MEMBERID_FEISHU_ENABLED must be true or false")
	}
	if sender == nil && dingTalkEnabled != "true" && feishuEnabled != "true" {
		return nil, nil, errors.New("enable and configure at least one authentication provider before starting OIDC")
	}
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return nil, nil, err
	}
	var phone *identity.PhoneVerifier
	if sender != nil {
		key, _ := base64.StdEncoding.DecodeString(loaded.Secrets.PhoneCodeKey)
		phone, err = identity.NewPhoneVerifier(store, key, sender)
		if err != nil {
			store.Close()
			return nil, nil, err
		}
	}
	key, _ := base64.StdEncoding.DecodeString(loaded.Secrets.ProviderKey)
	client := dingtalk.New()
	applications, err := identity.NewDingTalkApplications(store, key, client)
	if err != nil {
		store.Close()
		return nil, nil, err
	}
	directoryVerifier, err := identity.NewDingTalkDirectory(applications, client)
	if err != nil {
		store.Close()
		return nil, nil, err
	}
	var dingTalkVerifier *identity.DingTalkVerifier
	if dingTalkEnabled == "true" {
		dingTalkVerifier, err = identity.NewDingTalkVerifier(applications, client)
		if err != nil {
			store.Close()
			return nil, nil, err
		}
	}
	var feishuApps *identity.FeishuApplications
	if feishuEnabled == "true" {
		feishuApps, err = identity.NewFeishuApplications(store, key, feishu.New())
		if err != nil {
			store.Close()
			return nil, nil, err
		}
	}
	provider, err := oidcprovider.New(loaded, store, phone, dingTalkVerifier, directoryVerifier, feishuApps)
	if err != nil {
		store.Close()
		return nil, nil, err
	}
	cleanup, cancel := context.WithCancel(ctx)
	finished := make(chan struct{})
	synchronized := make(chan struct{})
	go func() {
		defer close(synchronized)
		directoryVerifier.RunSynchronization(cleanup, func() { slog.Warn("DingTalk background synchronization incomplete") })
	}()
	feishuFinished := make(chan struct{})
	go func() {
		defer close(feishuFinished)
		if feishuApps == nil {
			return
		}
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			if err := feishuApps.CheckApplications(cleanup); err != nil && cleanup.Err() == nil {
				slog.Warn("Feishu application checks incomplete")
			}
			select {
			case <-cleanup.Done():
				return
			case <-ticker.C:
			}
		}
	}()
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
	return provider, func() { cancel(); <-finished; <-synchronized; <-feishuFinished; store.Close() }, nil
}
