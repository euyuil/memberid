# Database upgrades and recovery

Schema 26 is the first supported baseline. Upgrades are explicit operator operations during a maintenance window. Ordinary startup and `database check` never initialize, migrate, reset or downgrade a database.

## Support matrix

| Source | Target | Result |
| --- | --- | --- |
| Empty database | 34 | Explicit initialization and generated IDs for all new registrations. |
| 26–31 | 34 | Apply each outstanding version in one transaction with a matching recovery set and reviewed application ID manifest. |
| 32 | 34 | Preserve all application IDs and existing admission policies. Apply the sharing migration with a recovery set. |
| 33 | 34 | Validate the opt-in organization disclosure policy. Existing registrations remain opted out. |
| 34 | 34 | Return `upgraded: false` without creating a recovery set or generating IDs. |
| Earlier than 26, later than 34, missing/ambiguous version | 34 | Refuse the upgrade. |
| 34 | Earlier version | Restore the matching source database, installation, consumer configurations and executable to new destinations. |

The schema 26 baseline executable is the ordinary distribution built from commit `a7c3ebed19d4cfb7196108f80c6360fc9449f882`. The schema 27 baseline is the distribution built from `2e6881ef0190b4fbf9cc9ed84edd3fe9c6a55902`. Schema 27 introduced the `database_upgrades` ledger. Schema 28 adds `feishu_memberships`, seeding pending checks for existing Feishu bindings without inferring employment state.

Schema 29 imports the legacy OIDC client file from the installation copy in the verified recovery set. It keeps every client ID, credential verifier, registered URI, and protocol policy. When the installation has a `console.json`, its matched console client becomes protected and the upgrader verifies its configured callback and secret. The original installation files remain available to the source executable through the matching recovery set. The new executable uses the database registry for registration and authentication. Existing organization, Member, session, grant, and SAML records are preserved.

Schema 30 adds an empty organization login slug table. Existing organizations retain their permanent IDs. Operators can assign a slug after the upgrade.

Schema 31 records a management owner for each OIDC registration. All existing and legacy-file registrations belong to `org_system`, including clients restricted to another organization for sign-in. The migration preserves the protocol registration, credentials, revision, and grants. The protected console client must always belong to the system organization.

Schema 33 adds OIDC publication and explicit external organization enablements. All registrations start unpublished. Existing single-organization policies retain their exact restriction, and unrestricted clients continue to admit existing and future organizations. The migration preserves IDs, verifier hashes, requests, grant state and authentication times. It creates no enablements and never reactivates retired grants.

Schema 34 validates the optional organization-scope setting in each registration. Existing policies omit it and remain opted out. The upgrade preserves application IDs, credentials, organization enablements, grants and authentication times.

Each applied migration records its source and target versions and SQL checksum together with the recovery-set receipt. Registration import, all applied migrations, and the ledger commit in the same transaction. Fresh schema 34 installations have an empty ledger.

## Preflight and maintenance

Use PostgreSQL 18 and its `pg_dump`/`pg_restore` clients (acceptance pins 18.6). The ordinary MemberID executable does not bundle those tools. The upgrading database role needs full read access for the backup and ownership/DDL privileges for the MemberID tables. Use a dedicated database. Preserve the old executable, its checksums and deployment configuration, including database credentials and any external TLS/service-manager configuration.

Connect directly to the dedicated PostgreSQL primary during maintenance, without a transaction pooler or independently routed replicas. The upgrader exports its transaction snapshot and passes it to `pg_dump`, tying the archive to that database snapshot while its write-excluding locks remain held.

Select the installation directory actually used with this database. Schema 26 has no installation-wide issuer/key binding that can prove that association automatically. Configuration validation checks the files and key pairs internally; successful login before maintenance and the deployment configuration establish which directory belongs with the database.

```sh
memberid database upgrade-plan
```

This reads `MEMBERID_DATABASE_URL`, reports `currentVersion`, `targetVersion`, `supported` and `upgradeRequired`, and writes no data. Unsupported versions return a nonzero status after the report. This is version inspection, not a full audit of a manually modified schema. Only unmodified supported MemberID schemas are supported; preserve and investigate unexpected custom objects or constraints.

### Prepare the application ID cutover (sources 26–31 only)

Schema 32 replaces each OIDC client ID (including the protected console) and each internal SAML SP ID. New registrations use the same generator. Each assignment encodes a fresh UUIDv7 using the MemberID alphabet with a 27-character suffix after `app_`. Assignments are independent of application names, owners and previous IDs.

1. Inventory every relying party and stage its configuration before downtime. Run the following with the current database and matching installation directory. Versions 26–28 also read the legacy client file. Retired and disabled registrations are included.

   ```sh
   memberid database application-id-plan --directory ./installation \
     --output-file ./protected-backups/application-ids.json
   ```

2. Keep the resulting identifiers-only manifest with the change record. Look up the new ID by both `protocol` and `oldId`. Rehearse the upgrade and restoration on an isolated copy using the same file. For new registrations since rehearsal, supply `--previous-manifest OLD --output-file NEW` and review the additions. The planner preserves all previous assignments and refuses to overwrite output. Apply refuses unknown, duplicate or missing entries.
3. Stage `console.json` with its mapped `clientId` and each OIDC consumer (including GitLab) with the mapped client ID and audience settings. Keep the previous files and executable alongside the recovery set. Keep the issuer, credentials, registered URLs and keys. SAML management tools use the new internal IDs. The external SP entity ID, ACS, certificates and NameID values stay the same.

### Apply the upgrade

For a schema 32 or 33 source, skip the ID cutover and omit the manifest argument below. Keep existing relying-party and console configurations. Verify an existing grant can refresh with its original authentication time and client ID after the upgrade.

Before upgrading:

1. Schedule downtime and stop all authentication, console and management replicas, background workers, CLI writers and database clients. Disable automatic restart/rollout controllers. Stop configuration/key edits and rotations as well. Restrict access so another administrator cannot introduce direct SQL or file changes during the operation.
2. Keep traffic closed through upgrade and validation. Do not change the issuer, regenerate keys, or replace Member identities as part of this upgrade.
3. Prepare an existing, protected backup parent directory on suitable storage, with enough space for the database archive and the entire installation. On Windows, configure restrictive ACLs; Unix mode bits do not establish Windows ACLs. Keep recovery sets and any copied deployment secrets confidential.

```sh
memberid database upgrade --directory ./installation \
  --backup-directory ./protected-backups/before-schema-34 \
  --application-id-manifest ./protected-backups/application-ids.json \
  --maintenance-confirmed
```

For sources 26–31, activate the staged consumer configurations while traffic is still closed. Start the upgraded services and test a fresh console login, a real GitLab callback to the existing account, OIDC code exchange and refresh, and an existing SAML account with its original NameID. Check rejection of the old client ID, pending code and refresh token. Reopen traffic after these checks. If validation fails, keep traffic closed and restore the old consumer configurations together with the matching recovery set using the procedure below. Never point an old executable at the upgraded database.

`--pg-dump /path/to/pg_dump` selects an installed PostgreSQL 18 client if it is not on PATH. The upgrader supplies libpq connection settings and credentials through temporary service and password files. Keep the operator's temporary directory protected, especially on Windows where Unix permission modes do not establish ACLs. The files are removed when the command returns. The confirmation flag attests to the maintenance procedure; it does not stop services for the operator. Active or idle database clients cause a refusal. The installation files and source database remain in place.

The backup destination must be new and outside the installation. Existing destinations are never overwritten or removed. A successful recovery set contains:

- `database.dump`: a complete custom-format `pg_dump` archive, without ownership/ACL commands. Global database roles, tablespaces, external service settings and secrets outside the installation are not included; provision those separately on recovery.
- `installation/`: the complete protected directory, including the issuer/client configuration, SAML signing material, OIDC keys, protocol/provider secrets and management credentials. Symlinks and special files are rejected. Copied files are made owner-only on Unix and their contents flushed.
- `manifest.json`: the source schema (26 through 33), a random recovery-set ID, creation time and SHA-256 checksums for every file. Written last after verifying the copy and that source files did not change during backup. This detects damage/mixed sets, not a malicious operator able to rewrite both files and manifest.

The command creates the archive while holding PostgreSQL SHARE locks over the public tables, excluding writes while allowing `pg_dump` to read. It then takes an exclusive version-table lock, rechecks stopped clients and applies the migration and ledger atomically. A shared maintenance lock on current MemberID database connections prevents a new current-version process from starting during upgrade. The final version-table lock also prevents a late schema 26 process from reading the old version and starting after commit. These checks complement the required maintenance window; they do not coordinate arbitrary external SQL tools, filesystem writers or deployment controllers. See [PostgreSQL locking](https://www.postgresql.org/docs/18/explicit-locking.html) and [pg_dump](https://www.postgresql.org/docs/18/app-pgdump.html).

## Failure, interruption and retries

- Preflight or backup failure commits no database changes. An incomplete recovery directory may remain for inspection; it is not a completed backup without a valid manifest. Choose a new destination on a new attempt. Never delete the source to make initialization or upgrade pass.
- Concurrent upgrades fail promptly on the database advisory lock. No process is terminated automatically. Locks are released with the connection/transaction; there is no stale filesystem lock to remove.
- A SQL error or interruption before commit rolls back the DDL, ledger and version together. Keep the source offline, inspect it and correct the cause before retrying.
- A connection failure around commit is an uncertain response, not proof of rollback. Run `upgrade-plan` and `database check` after the first connection has ended. Schema 34 means the complete transaction committed. Inspect `database_upgrades` and verify the recorded recovery set. Repeating `upgrade` at schema 34 returns a no-op without touching its backup destination. An unchanged source version (26 through 33) means retry the supported upgrade with a new recovery destination. Never attempt a reverse SQL script.
- Filesystem or storage failure can invalidate a backup independently of the database transaction. Verify and protect the complete recovery set; the workflow is not a distributed transaction between PostgreSQL and backup storage, a continuous backup service or protection against losing both copies on one disk.

```sh
memberid database backup-check --backup-directory ./protected-backups/before-schema-34
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
     ./protected-backups/before-schema-34/database.dump
   ```

3. Copy the backed-up `installation/` into a new protected directory, preserving contents and enforcing access controls. Select the matching source-schema executable and configure its connection to the **new restored database**. Verify `config check`, `database check`, and key/certificate validity before starting services. The backup does not renew expired certificates or change SP trust.
4. Before exposing the recovered installation, invalidate restored sessions, grants and pending authentication/linking proofs using the supplied [recovery session script](recovery-sessions.sql), against the restored database only:

   ```sh
   psql --dbname=memberid_recovered --no-psqlrc \
     --set ON_ERROR_STOP=1 --file ./docs/recovery-sessions.sql
   ```

   This preserves identities, bindings, administrator assignments, registrations and NameID values. It deletes recovered browser/console sessions and phone challenges, and marks authentication requests consumed while retaining their replay reservations until normal expiry. Session deletion cascades to grants, access/refresh token records and account-link requests. Require fresh login. Reconcile administrator assignments, factor status, application publication, consumer withdrawals, disclosure policies and other revocations that occurred after the backup before reopening traffic. Record any slugs published after the backup with their original organization IDs. Restore those reservations when schema 30 is available again, before accepting new assignments. Offline JWT validation and existing SP application sessions remain subject to downstream expiry/revocation policy; clearing MemberID state alone cannot invalidate them.
5. Start the old executable in isolation, verify metadata and complete a fresh OIDC/SAML login with the same subject/NameID. Verify that recovered Refresh Tokens are rejected. Reopen traffic only after validation and authorization-state reconciliation. Leave post-backup data in the preserved upgraded database for explicit investigation/reconciliation.

## Session and grant contract

Schema 32 consumes pending application requests and revokes existing OIDC grants, including console grants. Fresh authorization uses the new ID. Revocation takes effect at online validation; offline token verifiers and independent application sessions retain their own expiry and session policies. Existing Members, issuer keys, SP entity IDs, NameID mappings, request replay reservations and immutable audit evidence survive. Use the manifest to correlate historical IDs. A restored source-schema backup contains point-in-time state and can resurrect subsequently revoked or consumed credentials. Recovery therefore requires the explicit invalidation and reconciliation step above before traffic resumes.

## Validation

PostgreSQL integration tests additionally preserve populated schema 27 Feishu identities and seed unknown membership observations. They cover backup refusal, active legacy clients, competing upgrades, blocked current-version startup, cancellation, SQL failure after DDL starts, rollback, retry, unsupported versions, and catalog equivalence between a migrated and freshly initialized schema 34. Recovery-set tests reject changed, missing and extra files.

The [packaged SAML fixture](saml-interop.md) accepts `MEMBERID_UPGRADE_BASELINE_PACKAGE` pointing to an ordinary schema 26 or 27 distribution, with `MEMBERID_SAML_PACKAGE` pointing to the current distribution. It creates Members, password bindings, administrator assignments, managed email, persistent and legacy NameIDs, an OIDC client, sessions and a Refresh Token using the old executable. It checks retained data across upgrade, rejects old-client credentials, obtains the same subject on a fresh grant, and completes SAML login with the same NameID. It then restores the generated recovery set into new destinations, invalidates restored sessions, rejects the old Refresh Token, and completes fresh SAML login with the matching old executable. The original upgraded database is retained until owned fixture cleanup. CI builds the pinned baseline and runs this rehearsal on Linux; the same fixture supports Windows native packages. This is automated HTTPS acceptance, not actual-browser inspection or real external-provider verification.

On 2026-11-27, the Windows amd64 schema 32 package passed the schema 26 upgrade and recovery rehearsal with PostgreSQL 18.6 and Node-SAML 5.2.0 over HTTPS. The old client ID, pending code and Refresh Token failed after cutover. Fresh OIDC login and renewal retained the Member subject. The SAML account retained its NameID through upgrade and recovery with the schema 26 executable. All 18 test results passed, including the parent.

On the same date, a separate fresh Linux amd64 installation verified the generated client ID with unmodified GitLab CE 19.5.5. GitLab sent a PKCE S256 request, completed its OIDC callback, and established a session for the previously linked GitLab account. Its authenticated user endpoint returned 401 before sign-in and 200 for that account afterward.

Before schema 28, on 2026-11-16, the Windows amd64 `0.0.0-upgrade106-acceptance` package passed all 17 scenarios (18 passing results including the parent) on HTTPS port 19001 with Go 1.27.4, Node 26.13.1, PostgreSQL 18.6 and Node-SAML 5.2.0. Its executable SHA-256 was `5a080532f8ab0187b3e3119ad457a7a33347faba1e2019be84eca226b6cc387b`. The baseline was the ordinary `0.0.0-nameid103` schema 26 package with executable SHA-256 `4598f5b6325a2c639fc85b79be2f16b205f721c846e563dfe41eb2fc077fa289`. The fixture removed its owned temporary environment and data after the run; it did not upgrade a persistent preview or user installation.

A populated schema 32 installation upgraded to 33 on Windows amd64 with PostgreSQL 18.6. Registration and grant snapshots matched before and after upgrade. A pre-upgrade Refresh Token retained its Member subject and authentication time, and an unrestricted client admitted a newly created organization. The matching schema 32 executable completed fresh login against the restored database and installation.

A populated schema 33 installation upgraded to 34 on Windows amd64 and PostgreSQL 18.6. Its original registration and Refresh Token retained the Member subject and authentication time with disclosure off. A new opted-in client received the signed organization ID. After restoring the paired schema 33 database and configuration and running the recovery session script, the original executable rejected the recovered Refresh Token and completed a fresh login for the same Member.
