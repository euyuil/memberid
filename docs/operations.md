# Operator commands

Use PostgreSQL 18.6 and the Go toolchain documented in [CONTRIBUTING.md](../CONTRIBUTING.md). Give MemberID its own database and application database role. Supply `MEMBERID_DATABASE_URL` through protected environment configuration; do not store real connection strings in the repository or pass passwords on the command line.

## Initialize an empty database

```sh
memberid database init
```

This is an explicit installation operation. It refuses existing user relations and never resets, replaces, or migrates an existing database. Normal startup does not initialize schema.

## Provision identities

```sh
memberid organization create --name "Example organization"
memberid member create --organization ORGANIZATION_ID --name "Example member"
memberid member block --organization ORGANIZATION_ID --member MEMBER_ID
memberid member unblock --organization ORGANIZATION_ID --member MEMBER_ID
```

Commands return JSON containing the affected identity. Use the identifiers returned by creation in subsequent commands. Names do not establish identity or verified contact ownership.

These commands use the operator's explicit database access. They do not create an end-user password, bypass an authentication provider, or grant permissions in another application. Manual unblocking preserves any external-departure block.

The executable can run the [OIDC web-client profile](oidc.md) with `serve --directory`. Run the separate protected [HTTP management interface](management-api.md) with `serve-management --directory` for organization and Member administration and current eligibility queries. Optional phone-provider configuration is documented in [phone authentication](phone-authentication.md).

## Create protected installation configuration

Create a parent directory that only the operator can access, then initialize a new child:

```sh
mkdir -p .local
memberid config init --directory .local/memberid --issuer https://login.example.invalid
memberid config check --directory .local/memberid
```

Initialization refuses an existing destination directory. It generates a 3072-bit RSA signing key, a public-key bundle, independent 256-bit protocol/phone/provider keys, a management credential and its SHA-256 verifier, and an empty client registry. It never prints key material. If creation fails after the directory is created, inspect the incomplete installation and choose a new empty destination; initialization does not delete or repair existing files.

On POSIX systems, the new directory uses mode `0700` and files use `0600`. On Windows, establish a restrictive directory ACL before running these commands; Go's mode argument does not configure Windows access-control lists. Protect backups and the `management-secret` file as credentials. Supply database credentials separately through `MEMBERID_DATABASE_URL`.

For local development only, use `--issuer http://127.0.0.1:8080 --allow-loopback-http`. This exception permits HTTP only for the explicit loopback address. Production issuers must be exact HTTPS origins, without paths, query strings, fragments, or user information.

Pass `--directory` to `serve` to load this installation and enable OIDC. Omitting it retains health-only mode.

## Rotate the management credential

The installation manager has one credential, independent of OIDC clients, signing keys, and user sessions. Rotation requires coordinated management-process restarts; the running processes retain their loaded verifier and do not watch configuration files.

1. Choose a maintenance window and pause management callers. Stop all management replicas so an old replica cannot keep accepting the previous credential during the change. The separate OIDC process can continue serving.
2. In a protected directory, choose a new credential filename that does not already exist:

   ```sh
   memberid config rotate-management-secret --directory .local/memberid \
     --output-file .local/memberid/management-secret-next
   memberid config check --directory .local/memberid
   ```

3. Load that new file into the trusted callers' secret stores, then start every management replica with the updated installation configuration. Check authenticated `/healthz` using the new credential, and verify that the old credential receives 401. Resume callers only after all replicas have changed.

The command generates a random 256-bit credential, saves and syncs it with mode `0600`, then replaces only `managementSecretSha256` in the configured secrets file. It prints only `rotated` and `restartRequired` booleans. Signing material, protocol/phone/provider keys, clients, identity records, and OIDC sessions/grants are unchanged. The old bootstrap `management-secret` file is preserved and is no longer the current credential after rotation; use the explicitly selected new file. Protect its parent directory and establish restrictive Windows ACLs before use, as with installation initialization.

An exclusive `.management-secret.lock` serializes rotations. Existing output files and directories are refused, including on retry. A failed or interrupted command may leave a candidate credential file, temporary verifier file, or lock; the existence of a candidate is not proof that rotation succeeded. Inspect the protected configuration and candidate locally before restarting or retrying, and remove a stale lock only after confirming no rotation is running. The credential and verifier live in separate files, so this is not a multi-file crash transaction. Keep protected backups and coordinate any manual secrets edits through the same maintenance boundary. Never print credentials or their files into ordinary logs.

## Register confidential clients

```sh
memberid client add --directory .local/memberid --id example \
  --redirect https://app.example.invalid/callback \
  --post-logout-redirect https://app.example.invalid/signed-out \
  --refresh
memberid client rotate-secret --directory .local/memberid --id example
```

Each successful add or rotation writes the client identifier and newly generated secret to standard output once. Capture it directly into protected application configuration; do not publish it, retain it in ordinary logs, or commit it. The registry stores only a SHA-256 verifier of the random 256-bit secret. Duplicate registration refuses replacement. Rotation preserves client policy and replaces only the verifier.

The [MemberID account linking page](account-linking.md) uses `--account-return` destinations independently of OIDC callbacks and logout. Callback, post-logout, and account-management return destinations are separately registered exact URLs; no wildcards, fragments, or URL user information are allowed. Repeat `--redirect`, `--post-logout-redirect`, or `--account-return` for additional destinations. A localhost alias or an arbitrary HTTP address does not qualify for the loopback exception.

Clients default to independent Member subjects. Optional `--organization ORGANIZATION_ID` restricts the allowed organization. An explicit `--subject factor` policy represents a verified authentication factor without asserting organization membership; it requires both `--evidence-scope` and `--evidence-audience` and cannot select an organization. Ordinary Member clients cannot accidentally become factor clients.

An evidence policy uses an operator-chosen custom scope and a fixed resource URL audience. Both must be configured together. Clients cannot set their own audience or claim policy through authorization-request parameters. Standard scopes cannot be repurposed as evidence scopes. Evidence contains identity facts, not application roles or resource permissions. `--preauthorized` records an operator's explicit consent decision for the registered scope policy; omit it when interactive consent is required.

Client configuration is file-backed and requires an explicit server restart. This is operator registration, not OAuth dynamic client registration. The implemented profile uses Authorization Code with PKCE S256 and `client_secret_basic`. The `--refresh` flag permits `offline_access` and standard rotating Refresh Tokens; omit it for clients that should not retain a refresh grant.

Registry edits acquire an exclusive `.clients.lock`, validate the whole configuration, and replace the registry atomically. Concurrent edits fail without modifying the registry. A crashed operator can leave a lock: remove it only after confirming no registration command is running. Keep the installation directory writable only by trusted operators and coordinate hand-edited changes with the same maintenance boundary.

## Signing-key material

Private keys may be PKCS#8 or PKCS#1 PEM, with RSA keys of at least 2048 bits. Newly generated keys use 3072 bits. The public bundle contains one or more PKIX `PUBLIC KEY` PEM blocks, including the active signing key. Key identifiers are derived from the public key, so changing a filename does not change its identity. Validation rejects missing, malformed, duplicate, or mismatched keys.

Retain old public keys when preparing a rollover, and retain old private material only in protected backups if operationally required. Do not remove verification keys while issued tokens can still be accepted. The configured public bundle is published through JWKS. Coordinate private-key replacement, retained public keys, and server restarts; deployed rollover acceptance remains pending.

## Inspect and revoke OIDC grants

These commands use the operator's direct `MEMBERID_DATABASE_URL` access. They do not need an OIDC login or provider configuration:

```sh
memberid grant list --client example --limit 50
memberid grant list --subject MEMBER_ID --after GRANT_ID --limit 50
memberid grant inspect --id GRANT_ID
memberid grant revoke --id GRANT_ID
```

Listing returns `items` and an optional `nextAfter` cursor. Filters are exact client and Member/factor subject identifiers; omitting a filter includes all matching records. Page sizes range from 1 through 100. Use `nextAfter` as `--after` for the next page. Pages are ordered by the opaque grant identifier and reflect current stored records, not a snapshot. Periodic cleanup removes expired records; these commands are not a historical audit archive.

Grant metadata includes the client, subject, organization when applicable, factor, session identifier, original authentication time, original scopes, audience, current inactivity deadline (`expiresAt`), absolute deadline, and grant/session revocation timestamps. It contains no access tokens, Refresh Tokens, browser credentials, or credential verifiers. Treat the identity metadata as private operator data. `originalScopes` describes the initial grant: an individual refresh chain may have narrowed its scopes afterward and cannot regain removed scopes by using this metadata.

`state` is `active`, `expired`, or `revoked`. It describes the persisted grant/session lifecycle only. An active record is not a guarantee that its client is still registered or that its Member, organization, factor, and binding remain eligible; actual token use rechecks those policies. Expiry of the separate browser SSO cookie does not by itself expire a still-active refresh grant.

Revocation targets exactly one grant and serializes with refresh rotation on that grant's database row. It invalidates the grant's Refresh Token family and its access tokens at online verifiers. Repeating the command preserves the first revocation timestamp. It does not revoke another grant, end the parent browser SSO session, remove an application's local session, or erase identity records. A new authorization flow may create a new grant if login and consent policy permit it. Already issued JWTs remain usable at offline verifiers until their short expiry. Use standard RP-initiated logout when the intended operation is to end the associated MemberID SSO session and its grants.

Missing grants fail explicitly. There is no bulk revoke, expiry-extension, restore, or credential-export command. Keep database access limited to trusted operators; knowing a grant identifier is not authorization to administer it.

## Configure an optional DingTalk application

Use `memberid dingtalk configure`, `memberid dingtalk inspect`, `memberid dingtalk sync`, and `memberid dingtalk reconcile` to manage an organization application with protected secret files and explicit configuration revisions. Configuration and metadata inspection are also available through the separate management API; explicit authorization synchronization and one-organization reconciliation are operator commands. The authentication process also runs periodic reconciliation across configured enabled organizations, coordinated through one additional PostgreSQL session per active leader. See [DingTalk authentication](dingtalk.md) for authorization checks, encryption, rotation, and the current login limitations.
