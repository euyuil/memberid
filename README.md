# MemberID

A self-hosted OpenID Connect provider with independent member identities for each organization.

MemberID is under development. It provides PostgreSQL identity storage, an OIDC Authorization Code profile with PKCE, optional phone and DingTalk authentication, and explicit administrator assignments with operator bootstrap. Platform administrators belong to the reserved `org_system` organization; organization administrators manage their own Members. See the documented limitations before deployment.

## Development

Use Go 1.27.4 and follow [CONTRIBUTING.md](CONTRIBUTING.md) for setup, checks, and the PR workflow.

```sh
go run ./cmd/memberid version
go run ./cmd/memberid serve --listen 127.0.0.1:8080
```

`GET http://127.0.0.1:8080/healthz` reports process availability only.

See [operator setup](docs/operations.md), [administrator setup](docs/administration.md), the [OIDC profile](docs/oidc.md), the [identity model](docs/identity-model.md), and [third-party component review](docs/third-party-components.md). The project's license has not been selected.
