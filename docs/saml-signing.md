# SAML signing operations

MemberID uses a dedicated RSA key and X.509 certificate to sign both the SAML Response and Assertion with RSA-SHA256. The private key must be unencrypted PKCS#8 or PKCS#1 PEM with at least 2048 bits; the certificate file must contain exactly one matching PEM certificate. If key usage is present, it must allow digital signatures. Unsupported keys, mismatched pairs, malformed material, and a key reused from the OIDC public-key set are rejected. Server startup, metadata, and assertion issuance reject an expired or not-yet-valid active certificate.

SAML signing trust is separate from HTTPS trust and OIDC JWKS. A self-signed SAML certificate is acceptable when distributed to SPs through a trusted operator channel. Replacing it does not change the issuer, SP registration, Member, persistent NameID, or OIDC keys. Do not change those identities as a shortcut for rotating signing material.

These commands require local operator access to the protected installation. They do not use a Member login, management HTTP credential, database connection, or external provider. Limit write access to trusted operators. Use restrictive directory ACLs on Windows; POSIX files created by activation use mode `0600`. Keep candidate and retained private keys in protected, versioned files, and do not edit them in place while inspecting, activating, or running a server.

## Inspect and export

```sh
memberid saml signing inspect --directory ./installation
memberid saml signing inspect --directory ./installation \
  --key-file saml-next-key.pem --certificate-file saml-next.pem
memberid saml signing export-certificate --directory ./installation \
  --key-file saml-next-key.pem --certificate-file saml-next.pem > saml-next-public.pem
```

Omit both candidate flags to inspect or export the configured signer. Both must be supplied to select a candidate, using paths relative to the protected installation. Candidate operations validate the rest of the installation and OIDC key separation without activating the files.

Inspection returns a SHA-256 fingerprint of the certificate DER, `notBefore`, `notAfter`, `expiresInSeconds`, `keyBits`, file references, `usable`, and one of these statuses:

| Status | Meaning |
| --- | --- |
| `valid` | Currently usable and expires more than 30 days from now. |
| `expiring` | Currently usable and expires within 30 days. |
| `notYetValid` | Validity has not started; `usable` is false. |
| `expired` | Validity has ended; `usable` is false. |

An expired or future certificate remains inspectable/exportable if its structure, key match, and key usage are valid. Inspection exits successfully with this status; monitoring must check `usable` and the remaining lifetime, not only the exit code. Invalid material fails without a partial report or export. The export contains only one public `CERTIFICATE` block, never the private key or installation secrets. This is an on-disk snapshot, not proof of what running replicas have loaded. There is no background notification or automatic certificate renewal.

## Coordinated manual rollover

1. Inspect the current signer and record its fingerprint, issuer, SP registrations, and restart procedure. Take a consistent protected backup as described below. Prepare a new matching key/certificate pair under new filenames. Obtain certificates through the deployment's approved procedure; the CLI does not generate or issue them.
2. Inspect the candidate and require `usable: true`, a suitable remaining lifetime, and the intended fingerprint. Export its public certificate and deliver it to each SP through the trusted configuration channel. Never distribute the private key.
3. Where an SP supports multiple IdP signing certificates, make it trust both the current and candidate certificates before activation. Check its actual trust configuration. MemberID metadata publishes only the signer loaded by the running process; it does not prepublish candidates or manage overlapping keys. Node-SAML's explicitly configured certificate array is one supported consumer mechanism; this is not a claim about all SP defaults. See the [Node-SAML certificate policy](https://github.com/node-saml/node-saml/tree/v5.2.0#configuration-option-idpcert).
4. Stop concurrent configuration work. Activate using the inspected current fingerprint and a new backup filename:

   ```sh
   memberid saml signing activate --directory ./installation \
     --key-file saml-next-key.pem --certificate-file saml-next.pem \
     --expected-sha256 CURRENT_CERTIFICATE_SHA256 \
     --backup-file memberid-before-saml-rotation.json
   ```

   The command locks `.saml-signing.lock`, rechecks the current fingerprint, validates the candidate including its current validity, and saves the previous `memberid.json` byte for byte without overwriting an existing backup. It then replaces `memberid.json` with validated configuration referencing the candidate. It preserves unrelated settings and all key/certificate files. The output reports the selected certificate and `restartRequired: true`. A stale fingerprint, competing lock, unusable candidate, or unavailable/new-backup conflict fails without switching configuration.
5. Restart every process that loads this installation, including authentication, management and console processes as applicable. Running processes retain their loaded signer until restart. For a single authentication process, new logins are unavailable during stop/start; plan a maintenance window that covers restart and verification. For an SP that cannot trust both certificates, pause new SAML logins, drain pending responses, update SP trust, then restart and verify within the same window. Do not promise uninterrupted service for that configuration.
6. Verify each replica's live metadata certificate fingerprint against the candidate, then complete a new SAML login in each affected SP. Verify the existing Member still reaches the same application account. A successful inspection or process start alone does not establish SP interoperability.
7. Retain old SP trust until all old replicas have stopped signing and all assertions they could have issued have expired, allowing for the SP's accepted clock skew and actual queue/delivery delays. MemberID assertions have at most two minutes of validity, but that alone is not a complete SP trust-removal schedule. Retain protected old private material only for an explicitly bounded rollback window, provided it is still usable and not compromised. Remove old SP trust after verification; confirm an old-key signature is rejected. Key compromise requires coordinated removal of compromised trust rather than ordinary overlap.

No key files are overwritten or deleted by activation. The exclusive lock serializes these commands; manual configuration/key edits must use the same maintenance boundary. A crashed process can leave a lock, temporary file, or backup. A backup's existence does not prove activation succeeded. After an uncertain result, inspect on-disk configuration and live metadata before retrying; remove a stale lock only after verifying no operator command is running. This is a synced configuration-file replacement with a separate recovery copy, not a database/filesystem crash transaction or a distributed rollout coordinator.

## Failed rollover and recovery

If candidate validation fails, keep the current server running and correct the candidate in new files. If the new signer starts but an SP rejects it, first check the SP's configured trust and expected issuer. To return to an uncompromised, still-valid previous signer, use the same `activate` command with the retained old filenames, the currently configured new fingerprint, and a different backup filename, then restart and verify. This explicit rollback changes the signer only; it does not restore or discard current identity data.

An expired active signer can be inspected and replaced with a valid candidate using this workflow. Activation cannot make an expired signer usable. If the active material/configuration is missing or corrupt and inspection cannot establish the expected signer, stop affected processes and recover a verified protected configuration/key set manually. Verify it before restarting. Do not bypass validation or reuse unrelated TLS/OIDC keys to recover service.

For backup/restore, quiesce authentication and administrative/configuration writers, capture a PostgreSQL backup and the entire protected installation as one consistent recovery set, and preserve the issuer and SP trust configuration. Include the SAML key/certificate, OIDC key set, protocol/provider secrets, and identity/NameID tables. The activation command's JSON backup alone is not an installation backup. Keep the backup set encrypted/access-controlled and record its certificate fingerprint separately from private material.

Rehearse restoration into a new isolated database and protected directory, preserving the installation being recovered from. Use the same MemberID version/schema, restore the database and matching files, configure the restored database connection, and inspect certificate validity and fingerprint. Verify metadata and complete an SP login with the original NameID. The SP must trust the restored certificate; restoring files cannot update downstream trust or renew an expired certificate. A point-in-time database restore can also restore old sessions/grants or lose later revocations, so isolate the recovered installation and reconcile authorization state before exposing it. This procedure establishes recovery of the current schema; it is not a historical schema upgrade workflow.

## Acceptance

The [packaged independent-consumer fixture](saml-interop.md) rehearses candidate inspection/export, invalid-candidate rejection, SP trust overlap, explicit restart, acceptance of an old in-flight response, stable NameID/OIDC keys, failure from a missed SP trust update, explicit rollback, rejection after old trust removal, and restoration of a consistent database/configuration backup into a new isolated destination. Unit checks cover expiry reporting/replacement, malformed or unsupported material, wrong key usage, OIDC key reuse, stale fingerprints, backup preservation, and concurrent activation.

No system HTTPS CA or browser trust is changed. The fixture does not establish general SAML certification, production multi-replica continuity, or every SP's certificate-refresh behavior.
