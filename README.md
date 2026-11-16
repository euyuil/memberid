# MemberID

A self-hosted OpenID Connect provider with independent member identities for each organization.

MemberID is under development. It provides PostgreSQL identity storage, OIDC Authorization Code with PKCE, an optional SAML 2.0 Identity Provider, and a shared administration console. Member sign-in supports organization-scoped passwords and optional phone, DingTalk, and Feishu authentication. [First-time setup](docs/administration.md#first-time-setup) provisions the initial platform administrator and writes its generated password to a protected file.

## Development

Use Go 1.27.4 and Node.js 26.13.1 LTS, and follow [CONTRIBUTING.md](CONTRIBUTING.md) for setup, checks, and the PR workflow.

```sh
go run ./cmd/memberid version
go run ./cmd/memberid serve --listen 127.0.0.1:8080
```

`GET http://127.0.0.1:8080/healthz` reports process availability only.

See [operator setup](docs/operations.md), [database upgrades and recovery](docs/database-upgrades.md), [administration console setup](docs/console.md), the [OIDC profile](docs/oidc.md), the optional [SAML IdP profile](docs/saml.md), the [identity model](docs/identity-model.md), and [third-party component review](docs/third-party-components.md). The project's license has not been selected.
