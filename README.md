# MemberID

A self-hosted OpenID Connect provider with independent member identities for each organization.

MemberID is under development. It provides PostgreSQL identity storage, an OIDC Authorization Code profile with PKCE, optional phone, DingTalk, and Feishu authentication, and a shared organization administration console. Platform administrators belong to the reserved `org_system` organization; organization administrators manage their own Members. See the documented limitations before deployment.

## Development

Use Go 1.27.4 and Node.js 26.13.1 LTS, and follow [CONTRIBUTING.md](CONTRIBUTING.md) for setup, checks, and the PR workflow.

```sh
go run ./cmd/memberid version
go run ./cmd/memberid serve --listen 127.0.0.1:8080
```

`GET http://127.0.0.1:8080/healthz` reports process availability only.

See [operator setup](docs/operations.md), [administration console setup](docs/console.md), the [OIDC profile](docs/oidc.md), the [identity model](docs/identity-model.md), and [third-party component review](docs/third-party-components.md). The project's license has not been selected.
