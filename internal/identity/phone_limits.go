package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
)

// PhoneSendLimits caps admitted sends in a rolling hour, including failed delivery.
// Zero selects the default for that dimension; negative values are invalid.
type PhoneSendLimits struct {
	Transaction  int `json:"transaction,omitempty"`
	Browser      int `json:"browser,omitempty"`
	Source       int `json:"source,omitempty"`
	Client       int `json:"client,omitempty"`
	Installation int `json:"installation,omitempty"`
}

func (limits PhoneSendLimits) WithDefaults() (PhoneSendLimits, error) {
	for _, entry := range []struct {
		value    *int
		fallback int
	}{
		{&limits.Transaction, 6}, {&limits.Browser, 12}, {&limits.Source, 60},
		{&limits.Client, 300}, {&limits.Installation, 1000},
	} {
		if *entry.value < 0 {
			return PhoneSendLimits{}, ErrInvalid
		}
		if *entry.value == 0 {
			*entry.value = entry.fallback
		}
	}
	return limits, nil
}

// PhoneSendSource comes from validated server-side request state, never form fields.
// An empty ClientID denotes the shared account-page bucket without a return client.
type PhoneSendSource struct {
	BrowserID string
	ClientID  string
	Address   netip.Addr
}

type phoneSendHashes struct {
	browser, source, client []byte
}

func (verifier *PhoneVerifier) sendHashes(source PhoneSendSource) (phoneSendHashes, error) {
	if len(source.BrowserID) != 43 || !validText(source.BrowserID, 43) || len(source.ClientID) > 128 ||
		(source.ClientID != "" && !validText(source.ClientID, 128)) || !source.Address.IsValid() || source.Address.Zone() != "" {
		return phoneSendHashes{}, ErrInvalid
	}
	address := source.Address.Unmap()
	network := address.String()
	if address.Is6() {
		network = netip.PrefixFrom(address, 64).Masked().String()
	}
	hash := func(dimension, value string) []byte {
		mac := hmac.New(sha256.New, verifier.key)
		_, _ = mac.Write([]byte("phone-send\x00" + dimension + "\x00" + value))
		return mac.Sum(nil)
	}
	return phoneSendHashes{hash("browser", source.BrowserID), hash("source", network), hash("client", source.ClientID)}, nil
}

// The caller holds the installation send lock until the challenge is inserted.
// A single bounded hourly scan checks every dimension against the same history.
func (verifier *PhoneVerifier) checkSendLimits(ctx context.Context, tx pgx.Tx, phone string, binding []byte, hashes phoneSendHashes, now time.Time) error {
	var total, transaction, browser, source, client, number int
	var recent bool
	err := tx.QueryRow(ctx, `SELECT count(*),
		count(*) FILTER (WHERE binding_hash=$2),
		count(*) FILTER (WHERE browser_hash=$3),
		count(*) FILTER (WHERE source_hash=$4),
		count(*) FILTER (WHERE client_hash=$5),
		count(*) FILTER (WHERE phone_number=$6),
		COALESCE(bool_or(phone_number=$6 AND created_at>$1::timestamptz-interval '60 seconds'),false)
		FROM phone_challenges WHERE created_at>$1::timestamptz-interval '1 hour'`,
		now, binding, hashes.browser, hashes.source, hashes.client, phone).
		Scan(&total, &transaction, &browser, &source, &client, &number, &recent)
	if err != nil {
		return err
	}
	limits := verifier.limits
	if total >= limits.Installation || transaction >= limits.Transaction || browser >= limits.Browser ||
		source >= limits.Source || client >= limits.Client || number >= 6 || recent {
		return ErrRateLimited
	}
	return nil
}
