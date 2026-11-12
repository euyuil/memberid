# GitLab interoperability

GitLab can use MemberID through its standard OpenID Connect OmniAuth provider. No GitLab plugin, MemberID-specific callback, private renewal endpoint, or modified GitLab executable is required. This guide uses the confidential Authorization Code profile with PKCE S256. See the [supported OIDC profile](oidc.md) for token and session limits.

## Configure a client

Deploy MemberID using a reviewed [distribution](distribution.md), a dedicated database, protected configuration, and an enabled authentication provider. Use an HTTPS issuer that both the browser and GitLab can reach and validate. GitLab must also reach Discovery, JWKS, the token endpoint, and UserInfo. A container's loopback address is not the host or another container's loopback address.

Register the exact GitLab callback as a confidential Member client:

```sh
umask 077
memberid client add --directory .local/memberid \
  --id gitlab --redirect https://git.example.org/users/auth/openid_connect/callback \
  > .local/gitlab-client.json
```

Protect the generated `client_secret`, transfer it to GitLab's secret management, and restart MemberID after updating file-backed client policy. This example does not request `offline_access` or enable refresh for GitLab. GitLab owns the lifetime of its local application session; an OIDC login does not grant GitLab project permissions.

Configure GitLab's normal `gitlab.rb` provider settings, replacing the example origins and supplying the secret from a protected file:

```ruby
gitlab_rails['omniauth_enabled'] = true
gitlab_rails['omniauth_providers'] = [{
  name: 'openid_connect',
  label: 'MemberID',
  args: {
    name: 'openid_connect',
    scope: ['openid', 'profile'],
    response_type: 'code',
    issuer: 'https://identity.example.org',
    discovery: true,
    client_auth_method: 'basic',
    uid_field: 'sub',
    pkce: true,
    client_options: {
      identifier: 'gitlab',
      secret: File.read('/etc/gitlab/memberid-client-secret').strip,
      redirect_uri: 'https://git.example.org/users/auth/openid_connect/callback'
    }
  }
}]
```

Apply the configuration using GitLab's supported reconfiguration procedure. This uses `client_secret_basic`, the authentication method supported by MemberID, and preserves GitLab's external configuration names. Consult [GitLab's OIDC documentation](https://docs.gitlab.com/administration/auth/oidc/) for additional GitLab-specific options.

## Associate the intended GitLab account

MemberID does not invent an email address or merge Members by contact attributes. Its current profile accepts the standard `email` scope but issues no email claims without a verified email source. Use an existing GitLab account with an explicitly associated `openid_connect` identity whose external UID is the intended Member's `sub`. An authenticated user can use GitLab's account connection flow; an authorized GitLab administrator can provision the association through GitLab's supported administration interfaces. Confirm the intended person and organization before connecting accounts.

Do not enable email-based automatic linking as a substitute for this association. GitLab's new-user provisioning requirements are distinct from OIDC authentication. The test below creates a synthetic existing GitLab account and explicitly associates its external UID before signing in; it does not demonstrate just-in-time creation of an account from missing email claims.

Keep the issuer and Member subject stable. GitLab's configured provider identity must continue to refer to the same issuer. Separate organization Members have distinct subjects even when they share a phone factor; associate them deliberately with the appropriate application accounts. Do not repoint an existing provider name at a different issuer and assume its UID associations remain safe.

## Reproduce the isolated check

The opt-in `internal/interop` test uses a complete packaged Linux amd64 executable, its checksum, and the package's normal Docker recipe. It runs an unmodified GitLab CE image pinned to `19.5.5-ce.0`, Linux amd64 manifest `sha256:5f97f753bb3b990271c26670aa3f49fe5adf9c752ea783bf4b2c86d76b27ba4d`. The fixture does not add test handlers to MemberID, inject login sessions into its database, or rebuild a special provider binary.

Prerequisites are the repository Go toolchain, Docker with Linux amd64 containers, a local Docker daemon that can bind-mount this checkout, and free loopback ports `18080` and `18111`. Allow at least 6 GiB of memory and 3 CPUs for GitLab in addition to the other processes, several GiB for the image, and several minutes for first startup. Run only one fixture at a time on the machine. The test starts its own temporary PostgreSQL server; it does not accept an existing database URL.

From the repository root in a POSIX shell:

```sh
mkdir -p dist
GOOS=linux GOARCH=amd64 sh scripts/package.sh interop-example dist/interop-example
(cd dist/interop-example && sha256sum --check SHA256SUMS)
MEMBERID_INTEROP_PACKAGE="$(pwd)/dist/interop-example" \
  go test -tags=interop -run '^TestGitLab$' -v -count=1 -timeout=45m ./internal/interop
```

On Windows, build the Linux package with Git Bash, then run the test from native PowerShell with the host Go toolchain:

```powershell
$env:MEMBERID_INTEROP_PACKAGE = (Resolve-Path 'dist/interop-example').Path
go test -tags=interop -run '^TestGitLab$' -v -count=1 -timeout=45m ./internal/interop
```

The coordinator must run on the Docker host because it reaches the published loopback ports. It cross-compiles a separate Linux fixture executable with cgo disabled. If the host does not run the compiler, compile that helper separately with `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -tags=interop -trimpath -buildvcs=false -o .local/gitlab-fixture-linux ./internal/interop` and set `MEMBERID_INTEROP_FIXTURE` to its absolute host path. A separately compiled host coordinator can be run with the same environment; Go test executable arguments use `-test.run`, `-test.v`, and `-test.timeout`.

All accounts and credentials are synthetic. A separate CONNECT/TLS fixture accepts only the configured SMS provider host and test phone. MemberID uses its ordinary HTTPS SMS adapter, with test-only proxy and CA environment settings. No real SMS is sent. Phone verification creates a factor through the public login form; the ordinary operator CLI explicitly binds it to the pre-created Member. The test then consents, completes GitLab's code callback, and checks GitLab's own authenticated `/api/v4/user` response. It first verifies that an empty browser receives 401, and checks GitLab's authorization request for PKCE S256, state, and nonce.

The fixture shares a Docker network namespace so the same `https://127.0.0.1:18080` issuer works for the browser and GitLab's back-channel requests. A separate TLS reverse proxy fronts the ordinary MemberID HTTP listener. Its one-hour test certificate is restricted to loopback; the automatic client trusts that certificate explicitly, and GitLab imports its public certificate through the normal writable `/etc/gitlab/trusted-certs` directory before reconfiguration. GitLab's Discovery library requires this HTTPS entry. No certificate-verification bypass is configured. Only the two browser-facing ports are published, both on `127.0.0.1`. The disposable PostgreSQL trust configuration is confined to that fixture. MemberID serves as UID 65532 with read-only configuration and filesystem, dropped capabilities, and its normal packaged executable. GitLab itself uses the explicit local HTTP callback exception at `http://127.0.0.1:18111`; this is not a production deployment or public-CA verification.

### Browser inspection and cleanup

Set `MEMBERID_INTEROP_HOLD=true` before running to retain a successful fixture for up to 20 minutes. Wait for the `Manual browser check ready` message. Before navigating to MemberID, configure the test browser to trust only the public `issuer.pem` from that exact owned fixture directory, using its normal certificate trust mechanism. The coordinator does not modify the host trust store. Remove that exact temporary certificate after inspection; never import the test private key, disable TLS verification, or bypass a browser warning. Then open `http://127.0.0.1:18111/users/sign_in` in a fresh browser context, choose **MemberID**, and use synthetic phone `19900000001`. After requesting a code, read the current code from `sms.json` in the reported owned `.local/gitlab-interop-*` directory. Complete verification, select **Example member** in **Example organization**, consent, and continue. Confirm GitLab displays **MemberID Test** (`memberid-test`) and its authenticated account page. Create an empty `manual.done` file in that exact reported directory after inspection; the coordinator then cleans up.

Do not publish fixture files, code values, cookies, client secrets, or raw logs. Docker containers and the configuration volume carry a per-run `memberid.interop` ownership label. Cleanup checks ownership before removing them and removes only the unique image tag created for that run. Successful runs remove their owned local directory; failed runs retain local diagnostic files. A forcibly terminated coordinator may leave resources: inspect the recorded `owner` value and labels before removing only that run's containers, volumes, image, and directory. Do not use global Docker pruning.

CI compiles the optional checks on Linux and Windows. It does not run the resource-intensive GitLab deployment or inspect a browser. Those are separate opt-in acceptance steps.

## Recorded acceptance and limits

The isolated automated flow on 2026-11-12 UTC used GitLab CE 19.5.5 and MemberID build label `dev-0be86f3` from source revision `0be86f3a3bc5f3e03de732f4260addc284351949`, built with Go 1.27.4 for Linux amd64 with cgo disabled. The packaged executable SHA-256 was `d30212206833a5b02ba46f0f10cfdcd217389b78a2985e9203d75c43b49f8c7c`. The coordinator ran natively on Windows against local Linux containers.

GitLab's actual OIDC client validated HTTPS Discovery, emitted a PKCE S256 authorization request, completed the ordinary phone verification and explicit Member-binding flow, redeemed the authorization code, and established its linked `memberid-test` account session. Its `/api/v4/user` endpoint changed from unauthenticated 401 to authenticated 200 for that account. This used the normal packaged MemberID executable, with no provider-specific GitLab modifications or certificate-verification bypass.

Independent browser acceptance is pending. The browser reached GitLab's MemberID button and the HTTPS issuer, then stopped at the test certificate trust warning. That observation is not a successful interactive browser login. The automated client and GitLab both explicitly trusted the dedicated fixture certificate; the host browser requires its own trust setup or user handling before inspection can finish.

This check does not establish OpenID certification, full OIDC conformance, every GitLab version, production HTTPS deployment, email-based provisioning, live SMS delivery, real DingTalk authorization, GitLab refresh behavior, or global logout. Refresh rotation, replay, session limits, revocation, and key rollover have separate MemberID HTTP/database regression tests. Each consuming application still needs its own integration and authorization acceptance.
