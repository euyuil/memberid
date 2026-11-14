# Local development with Docker Compose

Use Docker Compose with Linux containers, a POSIX shell, OpenSSL with `req -addext` support, and Python 3. On Windows use Git Bash with Docker Desktop. Keep the project checkout and local state on a filesystem where you can restrict access to your account.

| Local address | Service |
| --- | --- |
| `https://auth.memberid.localhost:19000` | OIDC issuer and sign-in, proxied to `auth:8080` |
| `https://admin.memberid.localhost:19000` | Administration console and OIDC callback, proxied to `console:8082` |
| `http://management:8081` | Private integration API on the Compose network, enabled by the `integration` profile |

Caddy publishes TCP port 19000 on host loopback for the persistent preview. PostgreSQL and the three MemberID listeners are only available through their respective Compose networks. On the host, browsers that resolve `.localhost` names to loopback can use both URLs without hosts-file entries. On the Compose HTTP network, Caddy has both hostnames as network aliases so the console can use the same issuer URL as the browser.

For external deployments, see [production hostnames](console.md#production-hostnames).

## First-time setup

Run from the repository root to create the persistent local development preview. For feature work, use a [temporary deployment](#temporary-feature-deployments).

```sh
sh dev/setup.sh
```

Setup builds a local image with the pinned Go and Node versions, generates the installation configuration and console client, and initializes a new PostgreSQL volume. It uses a unique Compose project per setup. Configuration, credentials, the development CA certificate, and the server key are under the ignored `.local/compose/` directory. Keep that directory and its matching PostgreSQL volume together. Setup refuses an existing directory. If setup stops partway, inspect the generated configuration and the project's Compose state before retrying with a fresh directory. The Docker build excludes the local state.

Trust only the public certificate at `.local/compose/tls/ca.pem` in the user or browser trust store used for local development. On macOS, use Keychain Access and set trust for SSL. On Windows, import the certificate into the current user's Trusted Root Certification Authorities store, or use:

```sh
certutil -user -addstore Root .local/compose/tls/ca.pem
```

The console container trusts that certificate through a read-only mount. Remove the host trust entry when retiring this local installation. The generated certificate covers both hostnames and is valid for one year. Keep TLS verification enabled.

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

The default `.local/compose/auth.env` enables the DingTalk adapter with no application registered. Configure a development identity provider before trying to sign in. For phone sign-in, add `MEMBERID_PHONE_ENABLED=true` and the protected test provider settings from [phone verification](phone-authentication.md) to `auth.env`. For DingTalk or Feishu, use a development application that accepts the configured HTTPS callback. Follow the relevant [DingTalk](dingtalk.md) or [Feishu](feishu.md) setup guide.

After editing `auth.env`, run `dc up -d --wait auth` to apply the new environment. Use phone or DingTalk to provision the first platform administrator as described in [the bootstrap guide](administration.md#bootstrap-and-recovery). Then you can manage organization providers in the console. Run the bootstrap commands through `dc run --rm --no-deps auth`. For example, use `dc run --rm --no-deps auth member create --organization org_system --name "Local administrator"` to create the Member record. The installation directory inside the container is `/etc/memberid`.

Open the admin URL, start sign-in, authenticate at the auth URL, and confirm the browser returns to the admin URL with the administrator session. For a basic HTTPS check using the generated CA directly:

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

Each setup has a separate Compose project, PostgreSQL volume, installation directory, and local CA. Use the public CA certificate from that setup and configure its development provider and administrator as needed. Run `dc` from the checkout you want to operate.

When feature work is complete, run these commands from its checkout to remove the temporary containers, networks, database volume, and local image:

```sh
project=$(sed -n 's/^MEMBERID_LOCAL_PROJECT=//p' .local/compose/compose.env)
dc --profile integration down --volumes --remove-orphans
docker image rm "memberid:$project"
```

Remove any trust-store entry added for the temporary CA, then delete that checkout's `.local/compose/` directory, including its generated credentials and configuration. Confirm its HTTPS port is no longer listening.

## Private integration API

Enable the optional service when testing backend integrations:

```sh
dc --profile integration up -d --wait
dc --profile integration ps
```

A trusted caller on the project's internal `data` network can use `http://management:8081`. Use the [management credential](management-api.md#run-and-authenticate) from the protected local installation. The console uses its own OIDC-backed session API. Port 8081 has no host mapping or Caddy route.

Run `dc --profile integration stop management` to return to the usual two-process workflow. Run `dc --profile integration down` to stop the entire stack and keep the database volume and local installation files for the next startup.
