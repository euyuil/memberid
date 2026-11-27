# Versioned releases

Daily PRs land on `main` through squash merge. CI tests and publishes a SHA image. That build receipt identifies a snapshot. A maintainer decides when to cut a release candidate, publish a stable version directly, or promote an accepted candidate. Git tags, GitHub Releases, and GHCR release tags use the same version, such as `0.1.0-rc.1` or `0.1.0`.

## Version selection

Write PR titles as `type(scope)!: description` in English. The scope and breaking marker are optional. Explain a breaking change and the consumer migration in the PR. CI checks the PR title, and the release planner reads squash commits since the most recent stable release.

| Example title | Effect |
| --- | --- |
| `fix(console): preserve the login return path` | Patch. Performance improvements and behavior reverts also default to patch. |
| `feat(oidc): add an optional claim` | Minor. |
| `fix(api)!: remove the obsolete binding field` | Major after 1.0, minor during 0.x. A breaking marker applies to every type. |
| `docs: clarify the upgrade procedure` | Maintenance. Types `docs`, `ci`, `test`, `build`, `chore`, `style`, and `refactor` alone do not advance a stable version. Classify user-visible fixes by their effect. |

Use the highest impact across the selected changes. The initial target is `0.1.0`. Explicitly select **Declare the first stable public API** to target `1.0.0` during bootstrap or 0.x. Keep that selection for further candidates of 1.0. Compare changes with the contract of the last stable release, including when fixing an RC.

For example, after `1.4.2`, a fix gives `1.4.3-rc.1`. A further compatible fix gives `1.4.3-rc.2`. A necessary breaking fix instead gives `2.0.0-rc.1`. Only the current RC in the open series can be promoted. Previous tags remain available. A stable target with an open RC goes through promotion.

## Preview and publish

1. Open **Actions → Release → Run workflow** on `main`. Choose `rc` or `stable` and copy `RUN_ID/ATTEMPT` from the selected CI image publication summary. The run must be a successful push in this repository. CI retains the small image receipt under the repository's artifact retention policy. For an expired receipt, rerun CI and select its new successful attempt and digest for acceptance.
2. Enter the stable source version tags verified for a rolling upgrade, separated by spaces. An empty list means rolling compatibility is unverified. The workflow reads the target schema from the selected source. The source and target schema must also match for a rolling deployment.
3. Leave **Confirm version** empty and run the workflow. Review the proposed version, commit, image digest, schema and compatibility list in the summary. To publish, run it again with the same inputs and enter the exact proposed version. A changed proposal needs a new confirmation. Preview also reports whether matching full validation exists. Before any version tag is written, Release checks the successful Full CI attempt for the selected commit and image digest. It dispatches that suite on demand and waits if no matching result exists. Failed, skipped or mismatched results block publication.
4. For an accepted RC, choose `promote` and enter its exact tag as the source. Leave the compatibility and declaration inputs at their defaults. Preview and confirm the stable version. Promotion copies the accepted digest, commit, and compatibility data even when `main` has advanced, and reuses the verified RC's full validation attempt. Each new release records that attempt under `fullValidation`.

The workflow serializes release operations. It copies the original registry manifest by digest, verifies the alias, and creates the matching GitHub Release and Git tag. Each release starts with a JSON record of the version, source, commit, image digest, schema and explicitly supported rolling sources, followed by the commit summaries. RCs are GitHub prereleases. Publication uses the repository's Actions token. Keep version tags under this workflow's control. If publication is interrupted, repeat the same inputs and confirmation. A conflicting existing tag stops publication.

Normally a new candidate is built on `main`. If unrelated changes have landed during acceptance, branch `release/X.Y` from that series' RC and apply the reviewed fix via PR. Its push CI supplies the same image receipt. Bring the fix back to `main` as an equivalent patch. The planner checks for missing stable fixes across the two histories.

Run the release tests with Python 3.10+ and Git:

```sh
python3 -B -m unittest discover -s scripts -p test_release.py
```

## Rollback and database compatibility

MemberID supports forward database migrations only. A release's `rollingFrom` list records verified upgrades **from** the listed versions **to** that release. Switching back to an older image requires separate verification, even when both versions use the same schema. Check that the older version can use the current configuration, read and update records written by the newer version, and still enforce recorded credential revocations.

If the older executable requires an earlier schema, restore the pre-upgrade recovery set to a new database and installation directory. Use the matching executable, configuration, keys, and any affected consumer configuration. The restored database contains data as of the backup. Keep the upgraded database intact for reconciliation. Review subsequent access changes, including revocations, and apply them to the recovered installation before reopening traffic. Follow the [database recovery procedure](database-upgrades.md#recover-an-unusable-deployment).
