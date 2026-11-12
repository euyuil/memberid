# Distribution and deployment

MemberID runs as one executable with PostgreSQL and protected installation configuration. Its public OIDC process and private management process use the same executable. Consumers integrate through OIDC and the documented management API; they do not need a source checkout or a special application build.

## Build a local distribution

Use the Go version in `go.mod`, a POSIX shell, and the standard `cp`, `find`, `sort`, `xargs`, and `sha256sum` tools. Git Bash supplies these tools on Windows. Run from a clean, reviewed checkout after the [contributor checks](../CONTRIBUTING.md):

```sh
mkdir -p dist
sh scripts/package.sh dev-example dist/memberid-example
(cd dist/memberid-example && sha256sum --check SHA256SUMS)
```

The selected version appears in `memberid version` and `BUILDINFO`; it is an explicit build label, not a claim that a tagged release was published. Packaging currently supports `linux/amd64` and `windows/amd64`. It uses the current Go target by default; set `GOOS=linux GOARCH=amd64` before invoking the script when cross-building the Linux package from Windows. Use a different new output directory for each target or version.

The script disables parent workspaces and cgo, uses the existing module lockfile without updates, trims filesystem paths, and disables implicit VCS metadata. It copies only the executable, build information, public documentation, and reviewed third-party notices. The Linux package also includes its container recipe. No source tree, Git history, installation keys, database, cache, or local runtime directory is copied. `SHA256SUMS` covers every package file except the checksum file itself. It detects file changes; it is not an artifact signature or proof of origin.

The destination must not exist and its parent must already exist. Failed builds may leave an incomplete directory; inspect it and choose another new destination. The script never removes an existing directory or overwrites an earlier distribution. Packaging does not create Git tags, publish releases, or push images. MemberID's project license remains undecided.

## Run natively

Keep the entire `third_party/` directory with the executable. On Linux, run `./memberid`; on Windows PowerShell, use `.\memberid.exe`. The commands below assume the executable is on the operator's PATH.

Follow [operator setup](operations.md) to initialize an explicitly selected empty database and protected installation directory, register clients, and enable at least one [phone](phone-authentication.md) or [DingTalk](dingtalk.md) authentication provider. Then start the public process:

```sh
memberid serve --directory .local/memberid --listen 127.0.0.1:8080
```

Keep `MEMBERID_DATABASE_URL` and optional provider credentials in protected service-manager configuration. Use a dedicated database/application role and validate database TLS according to the deployment's PostgreSQL configuration. The executable does not supply PostgreSQL or initialize its schema during startup.

For production, configure an exact HTTPS issuer and place a TLS proxy in front of the HTTP listener. The proxy must preserve that public origin and avoid logging credentials, codes, cookies, or form bodies. For same-machine local development, explicitly select `http://127.0.0.1:8080` and `--allow-loopback-http` during configuration initialization. Local HTTP does not establish production TLS acceptance.

## Build the container from the Linux package

```sh
docker build --tag memberid:local dist/memberid-example
docker run --rm --read-only --network none --cap-drop ALL \
  --security-opt no-new-privileges memberid:local version
```

Use a Linux package for this command. The build context is the completed distribution directory, with an allowlist for its executable, notices, build information, and Docker recipe. The Dockerfile performs no compilation or network download: it copies the exact packaged Linux executable into Docker's [minimal scratch filesystem](https://docs.docker.com/build/building/base-images/#create-a-minimal-base-image-using-scratch). CI compares the copied executable byte-for-byte with the native package.

The image runs as numeric UID/GID `65532:65532`, has no shell or package manager, and exposes only the public port in its metadata. The executable is `/usr/local/bin/memberid`; `BUILDINFO` and notices live under `/usr/share/memberid/`. It includes no operating-system libraries, CA bundle, timezone database, database server, or writable application state. PostgreSQL owns persisted identity and authentication state; configuration stays in an explicit external mount.

## Container configuration and trust

Mount the protected installation at `/etc/memberid` read-only and give the runtime UID read access without making the directory public. Use a dedicated operator account or a narrowly scoped group/ACL. The image's default user is intentionally unable to initialize or rotate read-only configuration; perform operator commands using the native executable or an explicitly authorized operator container with appropriate ownership and a writable configuration mount.

A maintained PEM CA trust bundle is required for outbound HTTPS and any database TLS that uses system trust. Supply it from the deployment's managed trust store; include the public roots needed for the enabled providers and any required private database roots. Mount it read-only at `/etc/memberid-ca.pem` and set `SSL_CERT_FILE` to that path. The application uses [Go's normal certificate verification](https://pkg.go.dev/crypto/x509#SystemCertPool), with no insecure fallback. Missing or insufficient trust makes certificate verification fail. The operator owns CA updates and must restart processes after changing the bundle. The image does not redistribute the host trust store.

For example, after preparing the database, provider, client, and installation, set `MEMBERID_INSTALLATION_DIRECTORY`, `MEMBERID_CA_BUNDLE`, and `MEMBERID_ENV_FILE` to protected absolute host paths. The environment file supplies `MEMBERID_DATABASE_URL` and the chosen provider settings. Create a private Docker network for the database and trusted callers, then run:

```sh
docker run --name memberid-login --read-only --cap-drop ALL \
  --security-opt no-new-privileges --network memberid-private \
  --publish 127.0.0.1:8080:8080 \
  --mount "type=bind,source=$MEMBERID_INSTALLATION_DIRECTORY,target=/etc/memberid,readonly" \
  --mount "type=bind,source=$MEMBERID_CA_BUNDLE,target=/etc/memberid-ca.pem,readonly" \
  --env-file "$MEMBERID_ENV_FILE" --env SSL_CERT_FILE=/etc/memberid-ca.pem \
  memberid:local
```

The default command is `serve --directory /etc/memberid --listen 0.0.0.0:8080`. The published host address is loopback for a same-machine browser or TLS proxy. A container's loopback address refers to its own network namespace, so its database connection must use an address reachable through the chosen private network. Do not put database credentials or provider secrets in image build arguments, labels, Dockerfiles, or the distribution directory.

For a separate management container, reuse the same image and mounts but override the command with `serve-management --directory /etc/memberid --listen 0.0.0.0:8081 --allow-private-listen`. Give it a distinct container name and keep it on the trusted network without a published host port or public proxy route. Its bearer credential remains separate from OIDC login. See [management access](management-api.md) for authority and network requirements.

## Lifecycle and verification

Both processes handle termination signals and close their listeners and database resources. The authentication process also stops its cleanup and directory synchronization workers. Use the service manager or container runtime for restart policy, resource limits, and secret injection. A read-only filesystem and dropped Linux capabilities are supported; no writable runtime volume is required by the serving processes.

`/healthz` reports public process availability, not database, provider, or full login readiness. The management `/healthz` requires its management credential. Verify discovery, JWKS, the expected issuer, an actual login, and the consuming application's behavior after deployment. Preserve the issuer and Member identifiers when account associations must remain stable.

Back up the dedicated PostgreSQL database and protected installation material together. File configuration changes require coordinated process restarts. Signing-key rollover must retain verification keys for still-valid tokens; [management credential rotation](operations.md#rotate-the-management-credential) has its own restart boundary. Existing schema versions are refused without an automatic migration or reset. Preserve the old database and configuration when evaluating a new installation; do not treat deployment or rollback as authorization to replace data.

The package and container checks establish the artifact's build and startup boundaries. They do not by themselves establish live SMS/DingTalk authorization, GitLab compatibility, OIDC certification, or any downstream application's acceptance.
