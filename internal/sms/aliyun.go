package sms

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("SMS provider unavailable")

type AliyunConfig struct{ AccessKeyID, AccessKeySecret, SignName, TemplateCode string }
type Aliyun struct {
	config AliyunConfig
	client *http.Client
}

// FromEnvironment leaves phone authentication disabled unless explicitly enabled.
func FromEnvironment(getenv func(string) string) (*Aliyun, error) {
	enabled := getenv("MEMBERID_PHONE_ENABLED")
	if enabled == "" || enabled == "false" {
		return nil, nil
	}
	if enabled != "true" {
		return nil, errors.New("MEMBERID_PHONE_ENABLED must be true or false")
	}
	config := AliyunConfig{getenv("MEMBERID_SMS_ACCESS_KEY_ID"), getenv("MEMBERID_SMS_ACCESS_KEY_SECRET"), getenv("MEMBERID_SMS_SIGN_NAME"), getenv("MEMBERID_SMS_TEMPLATE_CODE")}
	for _, value := range []string{config.AccessKeyID, config.AccessKeySecret, config.SignName, config.TemplateCode} {
		if strings.TrimSpace(value) == "" {
			return nil, errors.New("enabled phone authentication requires all MEMBERID_SMS settings")
		}
	}
	return &Aliyun{config: config, client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func hash(data []byte) string { digest := sha256.Sum256(data); return hex.EncodeToString(digest[:]) }

func sign(request *http.Request, config AliyunConfig, date, nonce string) {
	const signed = "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version"
	request.Header.Set("x-acs-action", "SendSmsVerifyCode")
	request.Header.Set("x-acs-version", "2017-05-25")
	request.Header.Set("x-acs-content-sha256", hash(nil))
	request.Header.Set("x-acs-date", date)
	request.Header.Set("x-acs-signature-nonce", nonce)
	var headers strings.Builder
	for _, name := range strings.Split(signed, ";") {
		value := request.Header.Get(name)
		if name == "host" {
			value = request.URL.Host
		}
		headers.WriteString(name + ":" + value + "\n")
	}
	canonical := request.Method + "\n/\n" + request.URL.RawQuery + "\n" + headers.String() + "\n" + signed + "\n" + hash(nil)
	mac := hmac.New(sha256.New, []byte(config.AccessKeySecret))
	_, _ = mac.Write([]byte("ACS3-HMAC-SHA256\n" + hash([]byte(canonical))))
	request.Header.Set("Authorization", "ACS3-HMAC-SHA256 Credential="+config.AccessKeyID+",SignedHeaders="+signed+",Signature="+hex.EncodeToString(mac.Sum(nil)))
}

func (sender *Aliyun) Send(ctx context.Context, phone, code string) error {
	parameters, _ := json.Marshal(map[string]string{"code": code, "min": "5"})
	query := url.Values{
		"CountryCode": {"86"}, "PhoneNumber": {strings.TrimPrefix(phone, "+86")},
		"SignName": {sender.config.SignName}, "TemplateCode": {sender.config.TemplateCode}, "TemplateParam": {string(parameters)},
		"CodeLength": {"6"}, "ValidTime": {"300"}, "Interval": {"60"}, "DuplicatePolicy": {"1"}, "ReturnVerifyCode": {"false"}, "AutoRetry": {"0"},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://dypnsapi.aliyuncs.com/?"+strings.ReplaceAll(query.Encode(), "+", "%20"), nil)
	if err != nil {
		return ErrUnavailable
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrUnavailable
	}
	sign(request, sender.config, time.Now().UTC().Format("2006-01-02T15:04:05Z"), hex.EncodeToString(nonce[:]))
	response, err := sender.client.Do(request)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || response.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	var result struct {
		Code    string
		Success bool
	}
	if json.Unmarshal(data, &result) != nil || result.Code != "OK" || !result.Success {
		return ErrUnavailable
	}
	return nil
}
