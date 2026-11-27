# Identity records

An organization owns its Members. Each Member has a stable identifier that is independent of display names, contact attributes, and authentication-factor changes. A person who participates in two organizations has two Members. There is no global User record.

[Administrator-managed email](member-email.md) is a separate, revisioned attribute. It is not a verified authentication factor or account-binding key. Matching addresses never merge Members; equal addresses in different organizations remain separate identities.

## Identifiers

Treat each ID as an opaque, case-sensitive string. Store, compare, and return the complete value, including its prefix. Ordinary OIDC clients identify an account by `(iss, sub)`, where `sub` is the Member ID. See [OIDC account identification](oidc.md#login-and-independent-subjects).

| Record | ID format |
| --- | --- |
| Organization | `org_` + 27 characters |
| Member | `mbr_` + 27 characters |
| Authentication factor | `af_` + 27 characters |

Each suffix encodes a UUIDv7 using the alphabet `0123456789bcdfghjkmnpqrstvwxz`. Each installation generates its own system organization and bootstrap Member IDs. The permanent organization login name `system` resolves to the enabled system organization. The permanent password username `root` in that organization belongs exclusively to its bootstrap Member. Schema-only initialization reserves the name without provisioning a Member. Other organizations may use the same username. Management authority requires an explicit assignment. Use `memberid setup identities` to read the generated IDs. See [first-time setup](administration.md#first-time-setup) and the [legacy identity cutover](database-upgrades.md#system-organization-and-root-cutover).

MemberID allocates organization and Member IDs for both standalone create endpoints. Atomic enrollment also allocates both IDs and returns them in an immutable receipt. See [management creation and enrollment](management-api.md#organization-and-member-id-allocation).

## Factors and explicit relationships

A factor is uniquely identified by its type, provider namespace, and provider subject. Recording verified factor evidence does not create a Member or a binding.

A binding explicitly joins a factor to a Member in an organization. Database constraints enforce matching organization ownership and factor type. A Member can bind one phone factor, one DingTalk factor, and one Feishu factor per configured Feishu application. A factor can bind to at most one Member per organization. A phone factor can explicitly bind to different Members in different organizations. An external factor is restricted to the organization whose configured application owns its namespace. Keys are local to an application even when two applications represent the same upstream tenant.

Revocation retains the relationship and its uniqueness constraints. Repeating an active binding is idempotent; a revoked slot cannot be silently replaced or reactivated. Factor management that changes these relationships requires a separately authorized operation and fresh verification when authentication is involved.

MemberID supports phone, [DingTalk](dingtalk.md), and [Feishu](feishu.md) authentication. DingTalk admission requires current verified corporation membership and may create an independent Member without SMS in ordinary organizations. In the system organization, admission additionally requires an existing explicit binding or the operator's one-use approval for an existing Member. Provisioning a record or calling a storage operation is not a successful login.

## Eligibility evidence

Manual blocking and external departure are independent Member block sources. Clearing one does not clear the other. Organization and factor status remain separate from Member state. Protocol issuance evaluates the complete current eligibility context; a stored binding alone grants no login or application permission.

Confirmed DingTalk or Feishu application revocation makes that source ineligible. Other bindings, including phone, continue to use their own eligibility rules. Unknown provider failures preserve the last observation. Authorization recovery does not remove independent Member blocks or binding revocations. See [application authorization synchronization](dingtalk.md#synchronize-application-authorization).

## Persistence and initialization

MemberID uses a dedicated PostgreSQL database. Schema initialization is an explicit transaction, serialized against concurrent initialization. It refuses a database containing existing user relations. Normal store startup checks the schema version and never applies DDL.

Fresh installations and explicit forward upgrades from schema 26 are supported. [Upgrade and recovery acceptance](database-upgrades.md) verifies populated installations; reverse migration and earlier demo schemas are unsupported. Tests create uniquely named databases on a separately configured disposable PostgreSQL server and remove only the databases they created.
