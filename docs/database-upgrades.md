# Database upgrades and recovery

Schema 26 is the first supported baseline. Upgrades are explicit operator operations during a maintenance window. Ordinary startup and `database check` never initialize, migrate, reset or downgrade a database.

## Support matrix

| Source | Target | Result |
| --- | --- | --- |
| Empty database | 27 | Explicit `database init`; refuses existing user relations. |
| 26 | 27 | Supported forward migration with a required recovery set. |
| 27 | 27 | No change; `upgraded: false`, no new backup or history row. |
| Before 26, after 27, missing/ambiguous version | 27 | Refused without changing the source. |
| 27 | 26 | No reverse migration. Restore the pre-upgrade recovery set with the schema 26 executable into new destinations. |

The baseline executable is the ordinary distribution built from commit `a7c3ebed19d4cfb7196108f80c6360fc9449f882`. Schema 27 introduces the `database_upgrades` ledger. Its 26-to-27 migration leaves all existing business and protocol rows unchanged and records the source/target versions, migration SQL checksum, recovery-set ID and manifest checksum in the same transaction as the version change. Fresh schema 27 installations have an empty ledger. This first migration establishes the supported upgrade boundary; it is not a claim that every past or future version pair is compatible.

## Preflight and maintenance

Use PostgreSQL 18 and its `pg_dump`/`pg_restore` clients (acceptance pins 18.6). The ordinary MemberID executable does not bundle those tools. The upgrading database role needs full read access for the backup and ownership/DDL privileges for the MemberID tables. Use a dedicated database. Preserve the old executable, its checksums and deployment configuration, including database credentials and any external TLS/service-manager configuration.

Connect directly to the dedicated PostgreSQL primary during maintenance, without a transaction pooler or independently routed replicas. The upgrader exports its transaction snapshot and passes it to `pg_dump`, tying the archive to that database snapshot while its write-excluding locks remain held.

Select the installation directory actually used with this database. Schema 26 has no installation-wide issuer/key binding that can prove that association automatically. Configuration validation checks the files and key pairs internally; successful login before maintenance and the deployment configuration establish which directory belongs with the database.

```sh
memberid database upgrade-plan
```

This reads `MEMBERID_DATABASE_URL`, reports `currentVersion`, `targetVersion`, `supported` and `upgradeRequired`, and writes no data. Unsupported versions return a nonzero status after the report. This is version inspection, not a full audit of a manually modified schema. Only unmodified supported MemberID schemas are supported; preserve and investigate unexpected custom objects or constraints.

Before upgrading:

1. Schedule downtime and stop all authentication, console and management replicas, background workers, CLI writers and database clients. Disable automatic restart/rollout controllers. Stop configuration/key edits and rotations as well. Restrict access so another administrator cannot introduce direct SQL or file changes during the operation.
2. Keep traffic closed through upgrade and validation. Do not change the issuer, regenerate keys, or replace Member identities as part of this upgrade.
3. Prepare an existing, protected backup parent directory on suitable storage, with enough space for the database archive and the entire installation. On Windows, configure restrictive ACLs; Unix mode bits do not establish Windows ACLs. Keep recovery sets and any copied deployment secrets confidential.

```sh
memberid database upgrade --directory ./installation \
  --backup-directory ./protected-backups/before-schema-27 \
  --maintenance-confirmed
```

`--pg-dump /path/to/pg_dump` selects an installed PostgreSQL 18 client if it is not on PATH. Database credentials are passed through the child process environment, never command arguments or backup metadata. The confirmation flag attests to the maintenance procedure; it does not stop services for the operator. Active or idle database clients cause a refusal. The installation files and source database remain in place.

The backup destination must be new and outside the installation. Existing destinations are never overwritten or removed. A successful recovery set contains:

- `database.dump`: a complete custom-format `pg_dump` archive, without ownership/ACL commands. Global database roles, tablespaces, external service settings and secrets outside the installation are not included; provision those separately on recovery.
- `installation/`: the complete protected directory, including the issuer/client configuration, SAML signing material, OIDC keys, protocol/provider secrets and management credentials. Symlinks and special files are rejected. Copied files are made owner-only on Unix and their contents flushed.
- `manifest.json`: schema 26, a random recovery-set ID, creation time and SHA-256 checksums for every file. Written last after verifying the copy and that source files did not change during backup. This detects damage/mixed sets, not a malicious operator able to rewrite both files and manifest.

The command creates the archive while holding PostgreSQL SHARE locks over the public tables, excluding writes while allowing `pg_dump` to read. It then takes an exclusive version-table lock, rechecks stopped clients and applies the migration and ledger atomically. A shared maintenance lock on current MemberID database connections prevents a new current-version process from starting during upgrade. The final version-table lock also prevents a late schema 26 process from reading the old version and starting after commit. These checks complement the required maintenance window; they do not coordinate arbitrary external SQL tools, filesystem writers or deployment controllers. See [PostgreSQL locking](https://www.postgresql.org/docs/18/explicit-locking.html) and [pg_dump](https://www.postgresql.org/docs/18/app-pgdump.html).

## Failure, interruption and retries

- Preflight or backup failure commits no database changes. An incomplete recovery directory may remain for inspection; it is not a completed backup without a valid manifest. Choose a new destination on a new attempt. Never delete the source to make initialization or upgrade pass.
- Concurrent upgrades fail promptly on the database advisory lock. No process is terminated automatically. Locks are released with the connection/transaction; there is no stale filesystem lock to remove.
- A SQL error or interruption before commit rolls back the DDL, ledger and version together. Keep the source offline, inspect it and correct the cause before retrying.
- A connection failure around commit is an uncertain response, not proof of rollback. Run `upgrade-plan` and `database check` after the first connection has ended. Schema 27 means the complete transaction committed; inspect `database_upgrades` and verify the recorded recovery set. Repeating `upgrade` at schema 27 returns a no-op without touching its backup destination. Schema 26 means retry the supported upgrade with a new recovery destination. Never attempt a reverse SQL script.
- Filesystem or storage failure can invalidate a backup independently of the database transaction. Verify and protect the complete recovery set; the workflow is not a distributed transaction between PostgreSQL and backup storage, a continuous backup service or protection against losing both copies on one disk.

```sh
memberid database backup-check --backup-directory ./protected-backups/before-schema-27
memberid database check
```

`backup-check` needs no database connection. It checks the manifest, exact file inventory/checksums and loadable configuration/key pairs, returning only the schema and recovery receipt. Keep that receipt with the deployment record. After upgrade, start the new executable with the unchanged installation and database, verify OIDC and SAML login, and then reopen traffic.

## Recover an unusable deployment

Recovery returns to the backup point. It does not preserve writes made after the backup and is not a reverse migration. Keep the upgraded database and failed deployment intact for investigation. Use new empty database and protected directory destinations; never restore over the source.

1. Keep traffic and all processes stopped. Verify the complete set with the new executable's `database backup-check`. Restore the external deployment configuration and retain the original issuer/keys.
2. Have the database administrator create a new empty destination with appropriate ownership and access. Restore using PostgreSQL 18 `pg_restore` with `--exit-on-error --single-transaction --no-owner --no-acl`. Set the destination host, port and user through `PGHOST`, `PGPORT` and `PGUSER`, and supply credentials through a protected `PGPASSFILE` or service configuration. Explicitly select the new database by name; do not put a password-bearing connection URI in command arguments. The following example uses `memberid_recovered`:

   ```sh
   pg_restore --dbname=memberid_recovered \
     --exit-on-error --single-transaction --no-owner --no-acl \
     ./protected-backups/before-schema-27/database.dump
   ```

3. Copy the backed-up `installation/` into a new protected directory, preserving contents and enforcing access controls. Select the schema 26 executable and configure its connection to the **new restored database**. Verify `config check`, `database check`, and key/certificate validity before starting services. The backup does not renew expired certificates or change SP trust.
4. Before exposing the recovered installation, invalidate restored sessions, grants and pending authentication/linking proofs using the supplied [recovery session script](recovery-sessions.sql), against the restored database only:

   ```sh
   psql --dbname=memberid_recovered --no-psqlrc \
     --set ON_ERROR_STOP=1 --file ./docs/recovery-sessions.sql
   ```

   This preserves identities, bindings, administrator assignments, registrations and NameID values. It deletes recovered browser/console sessions and phone challenges, and marks authentication requests consumed while retaining their replay reservations until normal expiry. Session deletion cascades to grants, access/refresh token records and account-link requests. Require fresh login. Reconcile administrator assignments, factor status and other revocations that occurred after the backup before reopening traffic. Offline JWT validation and existing SP application sessions remain subject to downstream expiry/revocation policy; clearing MemberID state alone cannot invalidate them.
5. Start the old executable in isolation, verify metadata and complete a fresh OIDC/SAML login with the same subject/NameID. Verify that recovered Refresh Tokens are rejected. Reopen traffic only after validation and authorization-state reconciliation. Leave post-backup data in the preserved upgraded database for explicit investigation/reconciliation.

## Session and grant contract

Normal 26-to-27 upgrade preserves sessions, grants, original authentication times, absolute/idle deadlines, consumed refresh tokens, replay reservations and revocations exactly. Maintenance downtime does not extend their lifetimes; expired state remains expired. No identities or keys are regenerated. A restored schema 26 backup contains point-in-time state and can resurrect subsequently revoked or consumed credentials. Recovery therefore requires the explicit invalidation and reconciliation step above before traffic resumes.

## Validation

PostgreSQL integration tests cover backup refusal, active legacy clients, competing upgrades, blocked current-version startup, cancellation, SQL failure after DDL starts, rollback, retry, unsupported versions, and catalog equivalence between a migrated and freshly initialized schema 27. Recovery-set tests reject changed, missing and extra files.

The [packaged SAML fixture](saml-interop.md) accepts `MEMBERID_UPGRADE_BASELINE_PACKAGE` pointing to the ordinary schema 26 distribution, with `MEMBERID_SAML_PACKAGE` pointing to the current distribution. It creates Members, password bindings, administrator assignments, managed email, persistent and legacy NameIDs, an OIDC client, sessions and a Refresh Token using the old executable. It verifies all existing database-table contents across upgrade, reuses the OIDC grant without changing subject/authentication time, and completes SAML login with the same NameID. It then restores the generated recovery set into new destinations, invalidates restored sessions, rejects the old Refresh Token, and completes fresh SAML login with the old executable. The original upgraded database is retained until owned fixture cleanup. CI builds the pinned baseline and runs this rehearsal on Linux; the same fixture supports Windows native packages. This is automated HTTPS acceptance, not actual-browser inspection or real external-provider verification.

On 2026-11-16, the Windows amd64 `0.0.0-upgrade106-acceptance` package passed all 17 scenarios (18 passing results including the parent) on HTTPS port 19001 with Go 1.27.4, Node 26.13.1, PostgreSQL 18.6 and Node-SAML 5.2.0. Its executable SHA-256 was `5a080532f8ab0187b3e3119ad457a7a33347faba1e2019be84eca226b6cc387b`. The baseline was the ordinary `0.0.0-nameid103` schema 26 package with executable SHA-256 `4598f5b6325a2c639fc85b79be2f16b205f721c846e563dfe41eb2fc077fa289`. The fixture removed its owned temporary environment and data after the run; it did not upgrade a persistent preview or user installation.
