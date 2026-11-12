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

The executable's HTTP listener still exposes only process health. OIDC login, provider configuration, and the protected HTTP management interface remain separate implementation steps.
