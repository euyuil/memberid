package config

import (
	"slices"

	"github.com/go-jose/go-jose/v4"
)

// JWKS exports the validated public bundle, including retained verification keys.
// It never serializes the active private key or installation credentials.
func (loaded *Loaded) JWKS() jose.JSONWebKeySet {
	ids := make([]string, 0, len(loaded.PublicKeys))
	for id := range loaded.PublicKeys {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	result := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(ids))}
	for _, id := range ids {
		result.Keys = append(result.Keys, jose.JSONWebKey{Key: loaded.PublicKeys[id], KeyID: id, Algorithm: string(jose.RS256), Use: "sig"})
	}
	return result
}
