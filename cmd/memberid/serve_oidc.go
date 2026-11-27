package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/zhizhun-tech/memberid/internal/authevent"
	"github.com/zhizhun-tech/memberid/internal/config"
	"github.com/zhizhun-tech/memberid/internal/dingtalk"
	"github.com/zhizhun-tech/memberid/internal/feishu"
	"github.com/zhizhun-tech/memberid/internal/identity"
	"github.com/zhizhun-tech/memberid/internal/oidcprovider"
	"github.com/zhizhun-tech/memberid/internal/sms"
)

func authenticationHandler(ctx context.Context, directory string) (http.Handler, func(), error) {
	loaded, err := config.Load(directory)
	if err != nil {
		return nil, nil, err
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
	store, err := identity.Open(ctx, os.Getenv("MEMBERID_DATABASE_URL"))
	if err != nil {
		return nil, nil, err
	}
	capabilities, err := store.OIDCClientCapabilities(ctx)
	if err != nil {
		store.Close()
		return nil, nil, err
	}
	if capabilities.ActiveClients == 0 {
		if loaded.SAML == nil || !loaded.SAML.Enabled {
			store.Close()
			return nil, nil, errors.New("register an enabled OIDC client or enable SAML before starting authentication")
		}
		registrations, err := store.SAMLServiceProviders(ctx)
		active := false
		for _, sp := range registrations {
			active = active || sp.Enabled && !sp.Retired
		}
		if err != nil || !active {
			store.Close()
			return nil, nil, errors.New("register an enabled SAML service provider before starting SAML-only authentication")
		}
	}
	var phone *identity.PhoneVerifier
	if sender != nil {
		key, _ := base64.StdEncoding.DecodeString(loaded.Secrets.PhoneCodeKey)
		phone, err = identity.NewPhoneVerifier(store, key, sender, loaded.PhoneSendLimitsPerHour)
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
	events, err := authevent.Open(os.Getenv("MEMBERID_DATABASE_URL"), loaded.AuthenticationEventRetention())
	if err != nil {
		slog.Warn("Authentication event writer unavailable")
	}
	provider.SetEventRecorder(events)
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
		feishuApps.RunSynchronization(cleanup, func(result identity.FeishuReconciliation, err error) {
			if err != nil {
				slog.Warn("Feishu synchronization incomplete", "membership", result)
			}
		})
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
	return provider, func() {
		cancel()
		<-finished
		<-synchronized
		<-feishuFinished
		events.Close(5 * time.Second)
		store.Close()
	}, nil
}
