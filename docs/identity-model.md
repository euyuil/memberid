# Identity records

An organization owns its Members. Each Member has a stable identifier that is independent of display names, contact attributes, and authentication-factor changes. A person who participates in two organizations has two Members. There is no global User record.

## Identifiers

Organization, Member, and authentication-factor identifiers use the `org_`, `mbr_`, and `af_` prefixes followed by a fixed-width opaque encoding of a UUIDv7. Clients retain the complete identifier and do not derive identity from its timestamp, prefix, or contact data. Ordinary OIDC subjects identify Members within an issuer.

The sole reserved exception is `org_system`, created by database initialization for platform administrator identities. It has no `kind` field, cannot be disabled, and is never a default destination for customers or unaffiliated people. Every Member still belongs to one organization. A Member must have an explicit administrator assignment and current eligibility to manage MemberID; belonging to `org_system` alone grants no privileges. See [administration access and bootstrap](console.md).

## Factors and explicit relationships

A factor is uniquely identified by its type, provider namespace, and provider subject. Recording verified factor evidence does not create a Member or a binding.

A binding explicitly joins a factor to a Member in an organization. Database constraints enforce matching organization ownership and factor type. A Member can bind one phone factor, one DingTalk factor, and one Feishu factor per configured Feishu application. A factor can bind to at most one Member per organization. A phone factor can explicitly bind to different Members in different organizations. An external factor is restricted to the organization whose configured application owns its namespace. Keys are local to an application even when two applications represent the same upstream tenant.

Revocation retains the relationship and its uniqueness constraints. Repeating an active binding is idempotent; a revoked slot cannot be silently replaced or reactivated. Factor management that changes these relationships requires a separately authorized operation and fresh verification when authentication is involved.

MemberID supports phone, [DingTalk](dingtalk.md), and [Feishu](feishu.md) authentication. DingTalk admission requires current verified corporation membership and may create an independent Member without SMS in ordinary organizations. In `org_system`, admission additionally requires an existing explicit binding or the operator's one-use approval for an existing Member. Provisioning a record or calling a storage operation is not a successful login.

## Eligibility evidence

Manual blocking and external departure are independent Member block sources. Clearing one does not clear the other. Organization and factor status remain separate from Member state. Protocol issuance evaluates the complete current eligibility context; a stored binding alone grants no login or application permission.

Confirmed DingTalk or Feishu application revocation makes that source ineligible. Other bindings, including phone, continue to use their own eligibility rules. Unknown provider failures preserve the last observation. Authorization recovery does not remove independent Member blocks or binding revocations. See [application authorization synchronization](dingtalk.md#synchronize-application-authorization).

## Persistence and initialization

MemberID uses a dedicated PostgreSQL database. Schema initialization is an explicit transaction, serialized against concurrent initialization. It refuses a database containing existing user relations. Normal store startup checks the schema version and never applies DDL.

The initial schema and its tests are scoped to new installations. No data migration is performed. Tests create uniquely named databases on a separately configured disposable PostgreSQL server and remove only the databases they created.
