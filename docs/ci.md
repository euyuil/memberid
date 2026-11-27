# Continuous integration

| Event | Verification | Outcome |
| --- | --- | --- |
| Pull request | Repository security and PR checks, including any selected integration tests | Both GitHub Actions checks must pass to merge. |
| Push to main or a stabilization branch | Package, check the file hashes, run the Linux image, and record its digest | A SHA snapshot becomes available for verification. |
| Nightly or requested full run | Windows and Linux build and package checks, race tests, isolated PostgreSQL integration, packaged SAML interoperability, and upgrade and recovery rehearsal | A successful run records the tested commit and registry digest. |
| RC or stable publication | Verify the full run for the selected commit and digest | An accepted RC can be promoted using the same evidence. |

## Pull request timing

Aim for 1–2 minutes of checks for ordinary code changes and tens of seconds for Markdown-only documentation. Compare the elapsed time to the last required check, since the two jobs run in parallel. Runner queue time can add to the time an author waits.

In the November 27 rollout, the previous PostgreSQL job took six minutes on PR #194. PR #198 completed the new Linux job in 88 seconds, including a focused PostgreSQL run. These are observations from individual runs. [Previous checks](https://github.com/euyuil/memberid/actions/runs/45930838965) and [tiered checks](https://github.com/euyuil/memberid/actions/runs/45938780471).

The PR job selects checks from the complete change set, including removed paths. Documentation runs the title, metadata, and secret checks. Adding a code file to the same PR also selects the Linux build and unit tests. Schema and recovery changes select database upgrade cases. Go changes in identity, management, console and OIDC packages select isolation and refresh-token regressions. Maintain these path and test mappings together in `scripts/pr_checks.py`.

## Nightly failures and release verification

Full CI is scheduled for 03:17 Beijing time (19:17 UTC on the previous day). Use GitHub Actions notifications for failed runs. Open the failed job and note the selected SHA and digest before investigating. Fix reproducible regressions on a normal PR. For a transient runner failure, rerun the failed jobs for that snapshot.

To run the nightly path immediately, choose **Actions → Full CI → Run workflow** on `main`. An empty source selects the main commit for that run. To verify an older snapshot, enter its SHA build `RUN_ID/ATTEMPT`. To recheck a published candidate, enter its RC tag. The workflow pulls the image by digest and compares its executable byte-for-byte with the Linux package used for acceptance.

A release preview reports whether matching full evidence exists. Confirming publication dispatches missing verification and waits. A failed run blocks the selected publication. Find the recorded attempt in the release's `fullValidation` field and compare its successful final job with the release commit and digest. New commits and republished images with different digests need their own evidence.

CI uses disposable test systems. China selects stable releases at its agreed maintenance window. Global rollout remains an independent operator decision. See [versioned releases](releases.md) for publication and rollout policy.
