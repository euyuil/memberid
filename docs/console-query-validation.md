# Console authorization query validation

Console resource requests authenticate the opaque cookie at entry and resolve
current administrator authority in the operation service. This removes the
duplicate administrator lookup without retaining a role or permission snapshot.
Provider configuration keeps its pre-verification admission check and its
authoritative check in the save transaction. Member detail reuses its resolved
Member when reading bindings; the standalone bindings query still checks that
the Member exists in the requested organization.

## Reproduce the profile

From the repository root, with the documented Go toolchain and Docker:

```sh
MEMBERID_TEST_QUERY_PROFILE=1 sh scripts/test-integration.sh
```

The script uses the same pinned PostgreSQL 18.6 image as the integration suite,
preloads its bundled `pg_stat_statements` module, and runs only
`TestConsoleQueryProfile`, without the race detector. It removes its owned
container afterward. No extension is added to an installation's database and
the production service does not depend on this module.

The fixture creates its own database, synthetic identities and administrators,
logs in through the real OIDC callback, and calls the console over loopback HTTP.
External providers are stubbed. Each repeated operation has five warmup requests
and 100 sequential measured requests. Grant, revoke and Provider creation are
measured once to preserve their state transitions. The two ordinary organizations
have eligible backup administrators, so the administrator-preservation checks run.

Statistics are scoped to that test database. Counts include explicit session
renewal, authorization, response queries, mutation statements, advisory-lock
queries and audit insertion. They exclude the profiling queries themselves and
`BEGIN`, `COMMIT`, and `ROLLBACK`. These are SQL call counts, not an accounting of
database-internal constraint checks or physical network packets. The profile
fails if an operation exceeds its recorded SQL budget; timing has no pass/fail
threshold. The ordinary race-enabled integration suite remains a separate check:

```sh
sh scripts/test-integration.sh
```

## Observed query counts

The same profiling fixture was run against baseline `b9f92d6` and the optimization
on 2026-11-15. Successful paths produced the following SQL calls per request:

| Operation | Before | After |
| --- | ---: | ---: |
| Session view | 2 | 2 |
| Organization list or detail | 4 | 3 |
| All-organization Member directory | 4 | 3 |
| Organization Member directory | 6 | 5 |
| Member detail, including bindings and administrator IDs | 7 | 5 |
| Provider directory | 5 | 4 |
| Management history | 4 | 3 |
| Create organization or Member | 7 | 6 |
| Update organization | 9 | 8 |
| Update Member | 12 | 11 |
| Grant administrator | 12 | 11 |
| Revoke administrator | 11 | 10 |
| Create Feishu Provider with credential verification | 10 | 9 |

These totals include the recorded audit names and previous-value reads introduced
in the baseline. They preserve that behavior while removing the duplicate
administrator lookup.

The profile also emits HTTP p50 and p95 durations. These small local samples are
not a production capacity benchmark. The initial measurements showed substantial
variation even in the unchanged session view, so they do not establish a reliable
latency improvement percentage. Query-count reductions are the verified result;
latency and throughput depend on workload, data size, database placement and
contention.

## Authorization regression coverage

Integration checks cover invalidated administrator assignments, Members,
organizations, source factors/bindings, grants, SSO sessions and console expiry
through resource reads and writes as well as the session view. They retain
`401 sign_in_required` for lost management identity and `403 forbidden` for a
current administrator lacking resource permission. A request-body fixture revokes
the assignment after cookie resolution and before the mutation service starts;
the mutation and its success audit are rejected.

Existing tests cover direct service calls, organization isolation, combined
scope/action requirements, last-administrator protection, provider revocation
during external verification, and completion of an already admitted bounded
operation. Member-detail tests distinguish a missing Member from an existing
Member with no bindings and reject forged organization ownership. This work does
not change the JWT profile, role storage, permission definitions, session
lifetimes, or self-service binding workflow.
