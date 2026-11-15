# Local development with Docker Compose

Use Docker Compose with Linux containers, a POSIX shell, OpenSSL with `req -addext` support, and Python 3. On Windows use Git Bash with Docker Desktop and restrict the checkout's `.local` directory ACL to your account before setup. Keep local state on a filesystem where you can protect its credentials.

| Local address | Service |
| --- | --- |
| `https://auth.memberid.localhost:19000` | OIDC issuer and sign-in, proxied to `auth:8080` |
| `https://admin.memberid.localhost:19000` | Administration console and OIDC callback, proxied to `console:8082` |
| `http://management:8081` | Private integration API on the Compose network, enabled by the `integration` profile |

Caddy publishes TCP port 19000 on host loopback for the persistent preview. PostgreSQL and the three MemberID listeners are only available through their respective Compose networks. On the host, browsers that resolve `.localhost` names to loopback can use both URLs without hosts-file entries. On the Compose HTTP network, Caddy has both hostnames as network aliases so the console can use the same issuer URL as the browser.

For external deployments, see [production hostnames](console.md#production-hostnames).

## First-time setup

Create the shared development CA once per developer account:

```sh
python3 dev/tls.py init
```

The script creates `~/.local/share/memberid/dev-ca/` with the private key `root-ca-key.pem` and the public certificate `root-ca.pem`. Keep the directory at mode `0700` and the key at `0600` on POSIX filesystems. On Windows, restrict the directory ACL to the developer account. Keep this material outside checkouts and container mounts.

Import the public root certificate once into the trust store used by the development browser. On macOS, use Keychain Access to add it to the login keychain and set trust for SSL. On Windows, import it into the current user's Trusted Root Certification Authorities store. The CA certificate contains DNS name constraints for `.memberid.localhost` and excludes IP addresses. A user-level trust entry applies to that user. Verify the name constraints in each target verifier before relying on them.

Run from the repository root to create the persistent preview. For feature work, follow [temporary feature deployments](#temporary-feature-deployments).

```sh
sh dev/setup.sh
```

Setup issues a separate server key and 90-day certificate under the shared root, builds the local image with the pinned Go and Node versions, generates the installation configuration and console client, and initializes a new PostgreSQL volume with `org_system/root`. Each server certificate has the exact admin and auth hostnames for that environment. Caddy mounts its server certificate and key. The console mounts a copy of the public root to verify the OIDC issuer.

The Compose project, installation configuration, credentials, and environment TLS files live under the ignored `.local/compose/` directory. Keep that directory and its matching PostgreSQL volume together. Setup requires a new state directory. If it stops partway through, inspect the generated configuration and Compose state before retrying. The Docker build excludes the local state.

## Start the stack

From the repository root, define this helper in Git Bash or a POSIX shell. The environment settings preserve Linux paths in container command arguments when using Git Bash on Windows.

```sh
dc() {
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' \
    docker compose --env-file .local/compose/compose.env "$@"
}
dc up -d --wait
dc ps
```

Open the admin URL and choose **Sign in with MemberID**. Enter organization ID `org_system`, username `root`, and the password saved by setup in `.local/compose/bootstrap/initial-root-password`. The password file is available only to the operator through the protected local state and is outside the runtime mounts. Remove it once the password is stored securely. To rotate a lost password, use `dc run --rm --no-deps -T auth setup reset-password` and save the new password from the terminal.

No external providers are enabled by default. For phone sign-in, add `MEMBERID_PHONE_ENABLED=true` and the protected test provider settings from [phone verification](phone-authentication.md) to `auth.env`. Configure a development application and enable its adapter for [DingTalk](dingtalk.md) or [Feishu](feishu.md). After editing `auth.env`, run `dc up -d --wait auth` to apply the new environment. The installation directory inside the container is `/etc/memberid`.

For a basic HTTPS check using the generated CA directly:

```sh
curl --fail --cacert .local/compose/tls/ca.pem \
  https://auth.memberid.localhost:19000/.well-known/openid-configuration
curl --fail --cacert .local/compose/tls/ca.pem \
  https://admin.memberid.localhost:19000/
```

To update a deployment to the code in its checkout, rebuild the local image with `dc build auth`, then apply it with `dc up -d --wait`. If the integration service is running, include `--profile integration` when applying the new image. Keep the persistent preview's installation directory and database volume across updates. Agents update the preview version only when explicitly asked by a human.

When changing the port of an existing installation, set `MEMBERID_LOCAL_HTTPS_PORT` in `.local/compose/compose.env` and update the issuer, console origin, and corresponding client redirect URIs in `.local/compose/installation/` together. Update any connected clients' issuer settings and external identity providers' registered callbacks before using the new URLs. Sign in again at the new issuer.

## Temporary feature deployments

Deploy each feature in an isolated local environment for validation. From the feature checkout root, choose an unused environment name and a free HTTPS port from 19001 through 19009:

```sh
sh dev/setup.sh --name review --port 19001
dc up -d --wait
```

This prints the two URLs and configures `https://auth-review.memberid.localhost:19001` as the OIDC issuer and `https://admin-review.memberid.localhost:19001` as the console origin. Use those addresses for that checkout's sign-in, callbacks, and HTTPS checks. Names can contain lowercase ASCII letters, digits, and internal hyphens, up to 57 characters. Choose a free port and a distinct name for every concurrently running environment. The separate hostnames keep the browser's authentication cookies isolated.

Each setup has a separate Compose project, PostgreSQL volume, installation directory, and server key. The environments share the developer's CA. Configure a development provider and administrator for the fixture, and run `dc` from the checkout you want to operate.

When feature work is complete, run these commands from its checkout to remove the temporary containers, networks, database volume, and local image:

```sh
project=$(sed -n 's/^MEMBERID_LOCAL_PROJECT=//p' .local/compose/compose.env)
dc --profile integration down --volumes --remove-orphans
docker image rm "memberid:$project"
```

Delete that checkout's `.local/compose/` directory, including its generated credentials and server key. Confirm its HTTPS port is no longer listening. Keep the shared CA and its trust entry for the other environments. If the fixture used a separate root from an older setup, remove that fixture's specific trust entry.

## Local TLS and CA changes

Run these commands from the checkout of a running environment to check its certificate or renew it under the configured shared CA:

```sh
python3 dev/tls.py check
python3 dev/tls.py renew
```

The check verifies the live certificate, chain, and hostname for both HTTPS origins. Renewal issues a new server key and certificate, validates both hostnames, and saves the previous `server.pem`, `server-key.pem`, and `ca.pem` in a protected `previous-tls-*` directory under `.local/compose/`. It then recreates `proxy` and `console` so their file mounts pick up the new files. If recreation or the live TLS check fails, the script restores the three files and recreates both services again. The printed backup enables manual recovery after an interruption. Restore the three files together and run `dc up -d --no-deps --force-recreate --wait proxy console`.

Renew before the server certificate expires. The CA has a five-year lifetime. Rotate it through an explicit trust change before it expires. The script fails if the CA key and certificate are missing or inconsistent, or the CA expires before the new leaf. CA initialization, issuance, and renewal leave host trust to the operator.

To adopt or change the shared CA, start on a free temporary port from 19001 through 19009. Using the affected browser, including the Codex in-app browser when relevant, start at the admin URL, follow the redirect to the auth URL, sign in with a development identity, and confirm the console callback succeeds. Renew the leaf, verify that the served fingerprint changed, and repeat sign-in with the existing root trust. On a certificate warning, record the failing hostname and browser error. OpenSSL and `curl --cacert` checks supplement the browser check.

After the temporary checks pass, use `renew` for an authorized cutover of the running 19000 preview. The same command can adopt the shared CA on an existing installation created by the previous setup script. Preserve the issuer URL, console origin, installation directory, and database. Retain the previous TLS materials through browser verification. Report the result of the browser check separately from the script's live TLS check.

## Private integration API

Enable the optional service when testing backend integrations:

```sh
dc --profile integration up -d --wait
dc --profile integration ps
```

A trusted caller on the project's internal `data` network can use `http://management:8081`. Use the [management credential](management-api.md#run-and-authenticate) from the protected local installation. The console uses its own OIDC-backed session API. Port 8081 has no host mapping or Caddy route.

Run `dc --profile integration stop management` to return to the usual two-process workflow. Run `dc --profile integration down` to stop the entire stack and keep the database volume and local installation files for the next startup.
