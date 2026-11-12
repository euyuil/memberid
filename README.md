# MemberID

A self-hosted OpenID Connect provider with independent member identities for each organization.

MemberID is under development. The current executable provides PostgreSQL identity storage, operator commands, process health, and version information. Authentication and OIDC endpoints are not available yet; this is not a production identity provider.

## Development

Use Go 1.27.4 and follow [CONTRIBUTING.md](CONTRIBUTING.md) for setup, checks, and the PR workflow.

```sh
go run ./cmd/memberid version
go run ./cmd/memberid serve --listen 127.0.0.1:8080
```

`GET http://127.0.0.1:8080/healthz` reports process availability only.

See [operator setup](docs/operations.md), the [identity model](docs/identity-model.md), the [implementation plan](docs/implementation-plan.md) and [third-party component review](docs/third-party-components.md). The project's license has not been selected.
