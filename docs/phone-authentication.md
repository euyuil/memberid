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

## Verification state

MemberID generates the code using cryptographic randomness. PostgreSQL stores a keyed HMAC bound to the challenge, normalized phone number, and initiating login transaction. It never stores the raw code. A code cannot be used by a different transaction.

The current policy is a five-minute lifetime, at most five wrong attempts, a sixty-second resend cooldown, and at most six sends per phone number per hour. Failed deliveries retain their cooldown. Creating a replacement invalidates previous challenges for that number. Database locks serialize concurrent sends and code consumption; restarting a process does not reset those limits. Cleanup retains enough expired challenge history to preserve the hourly limit.

Successful verification returns a typed server-local authentication result with the factor, authentication time, and `sms` authentication method. It does not issue a credential, create a Member, infer a binding, or grant application access. Standard OIDC issuance remains the protocol layer's responsibility.

## Current availability and validation

The adapter and persisted verification service are implemented and tested. The configured [OIDC provider](oidc.md) exposes the phone login UI; health-only mode leaves authentication disabled. Production builds contain no synthetic sender or code-return mode.

Tests inject a synthetic sender and use uniquely named databases in a disposable PostgreSQL server. They cover concurrent sends, concurrent verification, cross-transaction rejection, replay, persisted attempt limits, replacement, expiry, failed delivery, and absence of inferred membership. HTTP transport tests cover request encoding, an independently calculated signature vector, provider denials, redirect refusal, redacted errors, and no retries. These checks do not establish real SMS delivery.

The initial database schema is now version 3. Normal startup checks its version and never upgrades or resets an existing database. This early development increment supports fresh installation; preserve existing databases and use an explicitly selected new database when testing the new schema.
