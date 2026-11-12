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

The executable can run the [OIDC web-client profile](oidc.md) with `serve --directory`. The protected HTTP management interface remains pending. Optional phone-provider configuration is documented in [phone authentication](phone-authentication.md).

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

## Register confidential clients

```sh
memberid client add --directory .local/memberid --id example \
  --redirect https://app.example.invalid/callback \
  --post-logout-redirect https://app.example.invalid/signed-out \
  --refresh
memberid client rotate-secret --directory .local/memberid --id example
```

Each successful add or rotation writes the client identifier and newly generated secret to standard output once. Capture it directly into protected application configuration; do not publish it, retain it in ordinary logs, or commit it. The registry stores only a SHA-256 verifier of the random 256-bit secret. Duplicate registration refuses replacement. Rotation preserves client policy and replaces only the verifier.

Callback, post-logout, and account-management return destinations are separately registered exact URLs; no wildcards, fragments, or URL user information are allowed. Repeat `--redirect`, `--post-logout-redirect`, or `--account-return` for additional destinations. A localhost alias or an arbitrary HTTP address does not qualify for the loopback exception.

Clients default to independent Member subjects. Optional `--organization ORGANIZATION_ID` restricts the allowed organization. An explicit `--subject factor` policy represents a verified authentication factor without asserting organization membership; it requires both `--evidence-scope` and `--evidence-audience` and cannot select an organization. Ordinary Member clients cannot accidentally become factor clients.

An evidence policy uses an operator-chosen custom scope and a fixed resource URL audience. Both must be configured together. Clients cannot set their own audience or claim policy through authorization-request parameters. Standard scopes cannot be repurposed as evidence scopes. Evidence contains identity facts, not application roles or resource permissions. `--preauthorized` records an operator's explicit consent decision for the registered scope policy; omit it when interactive consent is required.

Client configuration is file-backed and requires an explicit server restart. This is operator registration, not OAuth dynamic client registration. The implemented profile uses Authorization Code with PKCE S256 and `client_secret_basic`. The `--refresh` flag permits `offline_access` and standard rotating Refresh Tokens; omit it for clients that should not retain a refresh grant.

Registry edits acquire an exclusive `.clients.lock`, validate the whole configuration, and replace the registry atomically. Concurrent edits fail without modifying the registry. A crashed operator can leave a lock: remove it only after confirming no registration command is running. Keep the installation directory writable only by trusted operators and coordinate hand-edited changes with the same maintenance boundary.

## Signing-key material

Private keys may be PKCS#8 or PKCS#1 PEM, with RSA keys of at least 2048 bits. Newly generated keys use 3072 bits. The public bundle contains one or more PKIX `PUBLIC KEY` PEM blocks, including the active signing key. Key identifiers are derived from the public key, so changing a filename does not change its identity. Validation rejects missing, malformed, duplicate, or mismatched keys.

Retain old public keys when preparing a rollover, and retain old private material only in protected backups if operationally required. Do not remove verification keys while issued tokens can still be accepted. The configured public bundle is published through JWKS. Coordinate private-key replacement, retained public keys, and server restarts; deployed rollover acceptance remains pending.
