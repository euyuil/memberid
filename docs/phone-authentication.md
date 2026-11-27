# Phone verification

Phone authentication is optional. The adapter uses Alibaba Cloud Phone Number Verification Service (PNVS) and the `SendSmsVerifyCode` operation. It currently supports Chinese mainland mobile numbers only. Other installations can leave it disabled.

## Configuration

Set `MEMBERID_PHONE_ENABLED=true` and supply all of these protected environment values:

- `MEMBERID_SMS_ACCESS_KEY_ID`
- `MEMBERID_SMS_ACCESS_KEY_SECRET`
- `MEMBERID_SMS_SIGN_NAME`
- `MEMBERID_SMS_TEMPLATE_CODE`

An absent enable flag or the explicit value `false` disables the provider without requiring SMS credentials. Other enable values and incomplete enabled configurations fail validation. `memberid config check --directory INSTALLATION_DIRECTORY` checks these settings without contacting the provider or sending messages.

Use PNVS-compatible signatures and templates with the `code` and `min` variables. The adapter supplies a literal six-digit code and a five-minute lifetime. The ordinary SMS `SendSms` product uses different configuration. Follow the provider's current [SendSmsVerifyCode reference](https://help.aliyun.com/en/pnvs/developer-reference/api-dypnsapi-2017-05-25-sendsmsverifycode) for account setup, templates, billing, and `dypns:SendSmsVerifyCode` permission. Provider activation and real-message delivery remain operator setup steps.

The request uses the official HTTPS endpoint and [ACS3-HMAC-SHA256 signing](https://www.alibabacloud.com/help/en/sdk/product-overview/v3-request-structure-and-signature). It does not follow redirects or retry deliveries, and explicitly disables provider automatic retry and code return. Only HTTP 200 with `Code=OK` and `Success=true` marks a challenge ready. This indicates provider acceptance, not confirmed handset delivery. Failures return a fixed error without signed URLs or supplier response contents.

## Send quotas

Login and self-service phone linking share the same send budget. Every admitted
send counts, even if delivery fails, times out, is canceled, or is never verified.
Changing the destination number does not reset these limits:

| Dimension | Default sends per rolling hour | Identity used |
| --- | ---: | --- |
| Transaction | 6 | Server-created login or account-linking request |
| Browser | 12 | MemberID browser cookie, shared across its transactions |
| Source | 60 | IPv4 address or IPv6 /64 network |
| Client | 300 | Registered client; account pages without a return client share a separate bucket |
| Installation | 1,000 | All sends in the MemberID database |

All dimensions must allow the request. The existing per-number limit of six per
hour and sixty-second cooldown also apply. Quota rejection happens before
provider I/O and does not invalidate a previously issued challenge. The page
shows a generic wait message without exposing which shared budget was exhausted.
Cancel the pending attempt before retrying; cancellation does not refund a send.

Optional fields in `memberid.json` override individual defaults:

```json
{
  "phoneSendLimitsPerHour": {
    "transaction": 6,
    "browser": 12,
    "source": 60,
    "client": 300,
    "installation": 1000
  },
  "phoneTrustedProxyCidrs": []
}
```

Add these fields to the existing installation object. Omitted fields and zero
values select defaults; negative values are rejected. There is no unlimited
setting. Validate with `memberid config check` and restart all authentication
replicas after configuration changes. Use identical limits, phone-code keys and
synchronized clocks across replicas. Keep the phone-code key stable: rotating it
changes the hashed browser/source/client buckets and invalidates outstanding
codes; transaction, number and installation history remains effective.

The limiter uses PostgreSQL challenge history, including consumed and failed
challenges. Cleanup retains the full rolling-hour history. A short installation
lock serializes quota admission and challenge insertion across replicas; the
lock is released before contacting the SMS provider. There is no per-process
allowance or automatic retry after database failure. Admission scans the last
hour through a time index; its work grows with the configured installation
budget. Raising that budget substantially requires measuring database load and
lock contention.

Browser cookies are resettable, and many legitimate users can share a NAT or
proxy. Browser and source limits are supplementary controls; client and
installation limits bound admitted sends even when the caller rotates browsers,
addresses and phone numbers. Size the shared limits for expected traffic and SMS
cost. A caller can exhaust a shared budget and temporarily prevent legitimate
sends. These quotas do not replace ingress request limits or the provider's
billing controls, and do not limit cumulative spending over multiple hours.

### Source addresses behind a proxy

By default, source limits use the TCP peer address and ignore forwarded headers.
Behind a reverse proxy this puts all its callers in the proxy's source bucket.
To distinguish callers, list only the actual proxy addresses or dedicated proxy
subnets in `phoneTrustedProxyCidrs`, using IPv4 or IPv6 CIDRs. All-address ranges
are rejected. Do not trust a shared network that also contains untrusted clients.

Only a trusted immediate peer can supply `X-Forwarded-For`. MemberID walks the
chain from right to left through trusted proxies and uses the first untrusted
address, ignoring any client-controlled prefix. Configure each trusted proxy to
overwrite untrusted headers or append the observed peer address. A missing header
uses the peer's bucket; a malformed address in the trusted chain rejects the
send. Other forwarding headers are not used. This setting affects SMS quotas
only, not issuer selection, redirects or authentication.

Browser, source and client quota keys are stored as domain-separated HMACs using
the phone-code key. The limiter adds no raw source IP or browser cookie to the
database. IPv4-mapped addresses share their IPv4 bucket; IPv6 addresses within a
/64 share one bucket.

## Verification state

MemberID generates the code using cryptographic randomness. PostgreSQL stores a keyed HMAC bound to the challenge, normalized phone number, and initiating login or account-linking transaction. It never stores the raw code. A code cannot be used by a different transaction.

The current policy is a five-minute lifetime, at most five wrong attempts, a sixty-second resend cooldown, and at most six sends per phone number per hour. Failed deliveries retain their cooldown. Creating a replacement invalidates previous challenges for that number. Database locks serialize concurrent sends and code consumption; restarting a process does not reset those limits. Cleanup retains enough expired challenge history to preserve the hourly limit.

Successful verification returns a typed server-local authentication result with the factor, authentication time, and `sms` authentication method. It does not issue a credential, create a Member, infer a binding, or grant application access. Standard OIDC issuance remains the protocol layer's responsibility.

The login page reserves its phone attempt before contacting the SMS provider.
Concurrent sends, including sends to different numbers, cannot replace that
attempt. Failed or uncertain delivery remains pending until explicitly canceled;
cancellation during delivery prevents the returning result from reviving it.

A successful login consumes the code, creates its SSO session, and advances the
login transaction in one database transaction. A cancellation or competing state
change that wins before this commit prevents the login. Database failures roll
back the code consumption and any newly created factor or session together. The
browser receives its session cookie only after commit. Incorrect codes still
persist their attempt counts. Canceling an unfinished verification does not
revoke an already committed SSO session; use logout for that operation.

## Explicit account linking

An already eligible Member can use the MemberID-hosted [phone linking page](account-linking.md) after fresh authentication through a registered application. Verification and the explicit binding commit together. This operation preserves the existing Member, session, and grants and cannot replace, transfer, or restore a binding. Normal phone login remains standard OIDC; linking introduces no private authentication proof or renewal endpoint.

## Current availability and validation

The adapter and persisted verification service are implemented and tested. The configured [OIDC provider](oidc.md) exposes the phone login UI; health-only mode leaves authentication disabled. Production builds contain no synthetic sender or code-return mode.

Tests inject a synthetic sender and use uniquely named databases in a disposable PostgreSQL server. They cover every cross-number quota, process recreation, concurrent budget admission, shared login/linking budgets, source-address normalization, spoofed forwarding headers, concurrent sends, concurrent verification, cross-transaction rejection, replay, persisted attempt limits, replacement, expiry, failed delivery, and absence of inferred membership. HTTP transport tests cover request encoding, an independently calculated signature vector, provider denials, redirect refusal, redacted errors, and no retries. These checks do not establish real SMS delivery.

The current database schema is version 36. Normal startup checks its version and never upgrades or resets an existing database. Fresh installation and [explicit forward upgrades from schema 26](database-upgrades.md) are supported; validate upgrades and recovery against isolated synthetic installations and preserve existing user databases.
