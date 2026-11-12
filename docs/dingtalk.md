# DingTalk application configuration

An installation may configure a DingTalk application for an existing enabled MemberID organization without SMS, Members, or OIDC clients. Application configuration is implemented through the operator CLI and the separate management API. Interactive DingTalk login, Member admission, and provider event processing are subsequent increments; configuring an application alone does not make DingTalk login available in this version.

## Configure and inspect

Create an organization using the [operator commands](operations.md). Obtain a DingTalk corporation identifier, application client identifier, and client secret from the organization's authorized application administrator. The application must be authorized for that corporation. Review the intended corporation and permissions before saving the configuration.

Place the client secret in a protected local file outside version control. One final LF or CRLF is accepted; other leading/trailing whitespace and control characters are rejected. Do not put the secret on the command line, in query strings, or in retained logs.

```sh
memberid dingtalk configure --directory .local/memberid \
  --organization '<organization-id>' --corp '<dingtalk-corp-id>' \
  --client '<dingtalk-client-id>' --secret-file '<protected-secret-file>' \
  --expected-revision 0
memberid dingtalk inspect --directory .local/memberid \
  --organization '<organization-id>'
```

The CLI requires `MEMBERID_DATABASE_URL` and the installation's protected configuration. It uses the same domain operation as the management API. Inspection returns organization ID, an opaque provider namespace, corporation ID, client ID, revision, and creation/update timestamps. It never returns the client secret, ciphertext, or provider access token.

The management operations are:

- `GET /v1/organizations/{organizationId}/dingtalk-application`: inspect existing metadata, or 404 if unconfigured.
- `PUT /v1/organizations/{organizationId}/dingtalk-application`: submit `corpId`, `clientId`, `clientSecret`, and `expectedRevision` in a JSON body. Successful creation, rotation, and unchanged-secret updates return 200 with metadata.

Both require the installation management credential on the private management listener. They are absent from the public OIDC listener. See the [management boundary](management-api.md) and [OpenAPI contract](management.openapi.json).

## Stable binding and rotation

Initial configuration requires `expectedRevision: 0`; its accepted revision is 1. MemberID generates and retains an independent provider namespace for that organization. A DingTalk application client ID can be registered to only one MemberID organization in this initial profile. Different application registrations can refer to the same corporation while retaining separate MemberID identities and namespaces.

The corporation and client identifiers cannot be replaced in place. Changing either returns 409 and does not reassign existing identity evidence. This version provides no deletion or reassignment operation.

To rotate a secret, inspect the current revision, submit the same corporation and client IDs with the new secret, and set `expectedRevision` to that revision. A successful change advances the revision. An unchanged secret is verified again but leaves its revision and timestamps unchanged. Old revisions return 409. After an uncertain response, inspect current metadata before retrying; do not blindly overwrite a newer revision. Configuration revisions are intended to bind subsequent provider operations to the configuration they used.

Provider validation occurs before the write transaction. MemberID rechecks the organization status and expected revision while holding the organization row lock. Disabling an organization or accepting a competing update during external I/O prevents the stale operation from applying. Invalid credentials, denied authorization, timeouts, and unknown provider failures return 503 `provider_unavailable` without changing an existing configuration or Member eligibility. This configuration operation does not infer departure or revoke existing identities from a failed candidate credential.

## Credential protection and provider protocol

MemberID stores the client secret using Go's AES-256-GCM implementation with a random nonce. Authenticated associated data binds the ciphertext to the MemberID organization, provider namespace, DingTalk corporation, client, and configuration revision. Substituting another organization's ciphertext or replaying ciphertext from an older revision fails decryption. The installation `providerKey` remains in its protected secrets file, separate from PostgreSQL. Back up that key securely with the installation; replacing it does not rotate or recover existing encrypted credentials. Automated encryption-key rotation is not implemented.

Application authorization is verified using DingTalk's [documented application token endpoint](https://open-dingtalk.github.io/developerpedia/docs/develop/permission/single_to_multi/new_get_app_token/) at `https://api.dingtalk.com/v1.0/oauth2/{corpId}/token`, with the standard provider field names `client_id`, `client_secret`, and `grant_type=client_credentials`. The transport uses the fixed HTTPS provider origin, a ten-second timeout, bounded responses, no redirects, and no automatic retries. It requests a fresh token for each configuration check and discards that token. Provider response messages and credential-bearing transport errors are not exposed.

Management request logs record only the installation principal, method, route template, and response status. Protect any reverse proxy and external tracing configuration as well; MemberID cannot prevent independently configured infrastructure from capturing request bodies. These operations do not create a durable human audit history or accept a caller-supplied human identity as proof of authorization.

## Validation

Tests simulate DingTalk responses and use disposable PostgreSQL databases. They cover request encoding, error redaction, redirect rejection, response limits, encrypted storage and restart, wrong keys, ciphertext substitution, stable bindings, failed-candidate preservation, conflicting initial configuration and rotations, disabled organizations during provider I/O, and the CLI/HTTP contracts. These checks do not establish live DingTalk credentials, actual provider consent, or successful DingTalk login.

The fresh-install schema is version 6. Startup refuses older schemas without resetting or migrating their data.
