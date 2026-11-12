# Identity records

An organization owns its Members. Each Member has a stable identifier that is independent of display names, contact attributes, and authentication-factor changes. A person who participates in two organizations has two Members. There is no global User record.

## Identifiers

Organization, Member, and authentication-factor identifiers use the `org_`, `mbr_`, and `af_` prefixes followed by a fixed-width opaque encoding of a UUIDv7. Clients retain the complete identifier and do not derive identity from its timestamp, prefix, or contact data. OIDC subjects will identify Members within an issuer.

## Factors and explicit relationships

A factor is uniquely identified by its type, provider namespace, and provider subject. Recording verified factor evidence does not create a Member or a binding.

A binding explicitly joins a factor to a Member in an organization. Database constraints enforce matching organization ownership and factor type. Each Member has at most one factor of a given type, and a factor can bind to at most one Member per organization. The same factor can explicitly bind to different Members in different organizations.

Revocation retains the relationship and its uniqueness constraints. Repeating an active binding is idempotent; a revoked slot cannot be silently replaced or reactivated. Factor management that changes these relationships requires a separately authorized operation and fresh verification when authentication is involved.

The store contains phone and DingTalk factor types, but this step does not implement either authentication provider. Provisioning a record or calling a storage operation is not a successful login.

## Eligibility evidence

Manual blocking and external departure are independent Member block sources. Clearing one does not clear the other. Organization and factor status remain separate from Member state. Protocol issuance must evaluate the complete current eligibility context when authentication is implemented; a stored binding alone grants no login or application permission.

## Persistence and initialization

MemberID uses a dedicated PostgreSQL database. Schema initialization is an explicit transaction, serialized against concurrent initialization. It refuses a database containing existing user relations. Normal store startup checks the schema version and never applies DDL.

The initial schema and its tests are scoped to new installations. No data migration is performed. Tests create uniquely named databases on a separately configured disposable PostgreSQL server and remove only the databases they created.
