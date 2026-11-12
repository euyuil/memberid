# DingTalk authentication

An installation may configure a DingTalk application for an existing enabled MemberID organization without SMS, Members, or OIDC clients. Application configuration is implemented through the operator CLI and the separate management API. Interactive DingTalk login and verified Member admission are implemented. Provider event processing remains a subsequent increment.

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

To rotate a secret, inspect the current revision, submit the same corporation and client IDs with the new secret, and set `expectedRevision` to that revision. A successful change advances the revision. An unchanged secret is verified again but leaves its revision and timestamps unchanged. Old revisions return 409. After an uncertain response, inspect current metadata before retrying; do not blindly overwrite a newer revision. Pending login attempts bind to the configuration revision they used. Rotating the secret invalidates those attempts; it does not change Member identifiers or reset existing grant authentication times.

Provider validation occurs before the write transaction. MemberID rechecks the organization status and expected revision while holding the organization row lock. Disabling an organization or accepting a competing update during external I/O prevents the stale operation from applying. Invalid credentials, denied authorization, timeouts, and unknown provider failures return 503 `provider_unavailable` without changing an existing configuration or Member eligibility. This configuration operation does not infer departure or revoke existing identities from a failed candidate credential.

## Credential protection and provider protocol

MemberID stores the client secret using Go's AES-256-GCM implementation with a random nonce. Authenticated associated data binds the ciphertext to the MemberID organization, provider namespace, DingTalk corporation, client, and configuration revision. Substituting another organization's ciphertext or replaying ciphertext from an older revision fails decryption. The installation `providerKey` remains in its protected secrets file, separate from PostgreSQL. Back up that key securely with the installation; replacing it does not rotate or recover existing encrypted credentials. Automated encryption-key rotation is not implemented.

Application authorization is verified using DingTalk's [documented application token endpoint](https://open-dingtalk.github.io/developerpedia/docs/develop/permission/single_to_multi/new_get_app_token/) at `https://api.dingtalk.com/v1.0/oauth2/{corpId}/token`, with the standard provider field names `client_id`, `client_secret`, and `grant_type=client_credentials`. The transport uses the fixed HTTPS provider origin, a ten-second timeout, bounded responses, no redirects, and no automatic retries. It requests a fresh token for each configuration check and discards that token. Provider response messages and credential-bearing transport errors are not exposed.

Management request logs record only the installation principal, method, route template, and response status. Protect any reverse proxy and external tracing configuration as well; MemberID cannot prevent independently configured infrastructure from capturing request bodies. These operations do not create a durable human audit history or accept a caller-supplied human identity as proof of authorization.

## Validation

Tests simulate DingTalk responses and use disposable PostgreSQL databases. They cover request encoding, error redaction, redirect rejection, response limits, encrypted storage and restart, wrong keys, ciphertext substitution, stable bindings, failed-candidate preservation, conflicting initial configuration and rotations, disabled organizations during provider I/O, and the CLI/HTTP contracts. HTTP and database tests also cover DingTalk-only OIDC login, distinct organization subjects, standard refresh, callback browser binding and replay, and cancellation or configuration changes during provider verification. These checks simulate the upstream provider; they do not establish live DingTalk credentials or actual provider consent.

The fresh-install schema is version 7. Startup refuses older schemas without resetting or migrating their data.

## Enable interactive login

Set `MEMBERID_DINGTALK_ENABLED=true` for the public authentication process. `MEMBERID_PHONE_ENABLED` is independent; a DingTalk-only installation needs no SMS credentials. Register at least one confidential Member client and configure a usable organization application before sending users to login. Management may configure applications while the server is running. Provider enablement and file-backed OIDC client changes require a restart.

Register `<issuer>/login/dingtalk/callback` as the exact upstream redirect URL in the DingTalk application's settings. The issuer is the same configured HTTPS origin used for OIDC. The explicit loopback development exception uses `http://127.0.0.1` and still needs a provider-accepted callback registration. MemberID requests `openid corpid` as described in DingTalk's [browser authorization flow](https://open-dingtalk.github.io/developerpedia/docs/develop/permission/token/browser/get_user_app_token_browser/). The application also needs the user-profile and employee-directory permissions used to resolve `unionId`, find the corresponding employee, and read that employee's details.

An organization-restricted OIDC client supplies the MemberID organization context. An unrestricted client asks the user for that organization's MemberID identifier; this does not expose a public organization directory. The sign-in button navigates to the fixed DingTalk authorization origin. After successful verification, the user selects the independent Member and follows the same OIDC consent policy as phone login. The factor-only registration profile continues to require phone authentication and does not accept a DingTalk session.

MemberID stores only a hash of the random upstream state, binds it to the browser and OIDC authorization request, and expires the attempt after five minutes. State is consumed before the code exchange. A replay, wrong browser, expired attempt, changed application revision, canceled request, disabled organization, blocked Member, or revoked binding cannot complete login. Lost or failed upstream responses require canceling that verification and starting a fresh authorization. No upstream access or refresh token is returned to the browser or relying party.

## Member admission and identity evidence

A successful code exchange must report the configured corporation. MemberID resolves the verified `unionId`, obtains a fresh application token for that corporation, requires an internal employee (`contact_type=0`), and verifies consistent `userid` and `unionid` in the employee detail response. Missing visibility, unknown contact types, provider errors, and conflicting identifiers fail closed; they do not prove departure. See the provider's [subject mapping](https://developer.alibaba.com/docs/api.htm?apiId=52234) and [employee detail](https://jaq-doc.alibaba.com/docs/api.htm?apiId=52243) contracts.

The first verified admission creates a new independent Member and binding, unless an authorized operator already explicitly bound that factor to a Member in the same organization's provider namespace. Matching contacts, names, or identities in another organization never link Members. Repeated verification preserves the Member identifier. A verified change to an employee ID can retain the same `unionId` identity, but collisions with another identity are rejected. Provider profile updates do not overwrite an existing locally managed display name.

Fresh verified membership may clear an external-departure block, but never a manual block or revoked binding. Member admission, local SSO session creation, and the OIDC login-request update commit in one transaction. An invalidated request leaves none of those partial results. Optional department evidence is retained in MemberID, with unavailable data distinguished from a verified empty list; it is not added to authentication tokens or converted into business permissions. Upstream contact fields are not treated as verified phone or email factors.

The issued OIDC profile, token lifetimes, refresh rotation, and logout behavior are the same as for phone authentication. `amr` and authentication evidence use the provider method `dingtalk`. Refresh preserves the original authentication time; it does not exchange another DingTalk authorization code.

Current eligibility checks use stored organization, Member, factor, binding, and provider-namespace facts. Automated directory events and continuous provider-authorization synchronization are not yet implemented. A later upstream departure is therefore not automatically reflected by this increment; operators must block the Member or revoke its binding/grants when access must end. Provider outages alone do not turn into departure evidence. Disabling the login adapter stops new DingTalk authentication and SSO reuse, but does not itself revoke existing client grants.
