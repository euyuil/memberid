# Contributing

## Setup

Use Git, Go 1.27.4, a POSIX shell, and Gitleaks 8.30.1. On Windows, Git Bash provides the shell. Reuse a persistent Go installation or the official Go toolchain mechanism; do not install toolchains in temporary directories.

From the repository root, enable the versioned hooks:

```sh
git config --local core.hooksPath .githooks
```

Inspect any existing hooks configuration before changing it. The hooks require Gitleaks on Git's PATH and reject whitespace errors, detected secrets, and known coding-agent attribution patterns. They do not modify the staged content.

## Checks

```sh
sh scripts/check.sh
go test -race ./...
gitleaks git --redact --no-banner --no-color
git diff --check
```

The check script disables parent Go workspaces, checks formatting, runs vet and tests, and builds `dist/memberid` (`memberid.exe` on Windows). Builds use `-trimpath -buildvcs=false` to omit local paths and implicit VCS metadata. The race detector requires a supported C toolchain; CI runs it on Linux.

The first executable only serves process health. See [the implementation plan](docs/implementation-plan.md) for the remaining identity and OIDC work.

## Pull requests

Create a focused purpose-named branch from current `main`. Submit one independently reviewable outcome with its tests and documentation. Wait for CI and resolve blocking review findings before squash merging. Start dependent work from the updated `main`; do not accumulate completed PRs.

CI runs the build and tests on Linux and Windows, Linux race tests, and full-history secret scanning. The security job checks the pinned Gitleaks archive checksum before execution. Workflow dependencies are pinned to reviewed revisions.

Before committing, inspect the full staged diff and verify the configured human author and committer. Run the staged secret scan; do not bypass hooks. Before publication, review public text, Git metadata, configuration, examples, and build output for private information. Automated secret scanning does not establish that all sensitive information has been removed.

## Licensing

The project license remains undecided. Review exact dependency and bundled-material licenses before adoption, record the outcome in [the component inventory](docs/third-party-components.md), and retain required notices.
