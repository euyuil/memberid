# MemberID distribution

MemberID is a self-hosted OpenID Connect provider with independent Member identities for each organization.

Verify the files with `sha256sum --check SHA256SUMS`. `BUILDINFO` identifies the selected version, target, and Go toolchain. Run `./memberid version` on Linux or `.\memberid.exe version` in Windows PowerShell. Keep the `third_party/` notices with the executable.

Follow [distribution and deployment](docs/distribution.md) for native or container operation, and [operator setup](docs/operations.md) to initialize an empty PostgreSQL database, protect installation material, register clients, and configure an authentication provider. Existing databases and configuration are never initialized or replaced automatically.

The Linux package includes a Dockerfile that copies this exact executable into a minimal container. Mount protected configuration and a maintained CA trust bundle when deploying it. The distribution contains no installation secrets, database, authentication bypass, or external provider credentials.

MemberID's project license remains undecided. The included third-party notices describe their respective components; they do not assign a license to MemberID. Creating this directory or image does not publish a release.
