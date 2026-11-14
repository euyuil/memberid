# Member roles

This document records the agreed Member role definitions. Scope modeling is the next design discussion; the action catalog follows it. This document does not define their representation, evaluation rules, or APIs. The [administration console](console.md#first-version-access-model) documents the operations available in the current implementation.

## Members and administrator assignments

A Member is an organization-owned user identity. Every Member belongs to exactly one organization, including Members of the reserved system organization, `org_system`. The same natural person may have independent Members in different organizations; there is no global User account.

Administrator authority is an explicit assignment to a particular Member. Creating a Member, joining an organization, or sharing a phone number or other authentication factor with an administrator does not grant administrator authority. Removing an assignment preserves the Member's identity and historical attribution.

Ordinary membership is the baseline. An administrator remains a Member and receives additional management authority through an assignment. For role display, an ordinary member is a Member with no administrator assignment; ordinary membership does not require a separate assignment record.

## Role definitions

| Role | Eligible organization | Responsibility |
| --- | --- | --- |
| Platform administrator | System organization only | Administers MemberID across the installation, including the system organization, all ordinary organizations, and their Members. |
| Organization administrator | Ordinary organizations only | Administers MemberID identity management for the Member's own organization and its Members. |
| Ordinary member | System or ordinary organization | Has no administrative authority. Account self-service depends on the supported functionality and its own authentication requirements. |

These responsibilities establish the distinction between the roles. The precise resource coverage and permitted operations will be defined in the subsequent scope and action designs. A role description does not make an unimplemented operation available or exempt an administrator from identity and lifecycle constraints.

Platform and organization administrator roles belong to MemberID management. They do not grant administrator status, business roles, or resource permissions in consuming applications. Those applications retain their own authorization decisions, and MemberID does not add its management roles to their identity claims.

## System organization

### Ordinary members are allowed

The system organization can contain Members without administrator assignments. This supports provisioning and revocation without conflating identity with privilege:

1. An operator explicitly creates a system Member.
2. The Member establishes an eligible authentication binding through the documented verification and binding process.
3. An explicit administrator assignment makes that Member a platform administrator.
4. If the assignment is later removed, subject to the existing availability safeguards, the Member remains in the system organization without administrative authority.

System organization membership alone never grants management access. An ordinary system Member cannot access the administration console as an administrator.

Allowing ordinary system Members does not open system organization registration or automatic admission. The system organization remains reserved for explicitly provisioned platform-management identities; it is not a default organization for customers, unaffiliated people, or the operator's entire workforce. Existing [system admission and bootstrap requirements](administration.md#bootstrap-and-recovery) continue to apply.

### No organization administrator role

The first role model does not allow the organization administrator role in the system organization. Platform administrators manage that organization directly.

Its Member identities and authentication configuration underpin platform administration. A separate role that could manage all of those resources would also control important parts of platform administrator access. A more limited system-organization administration role would require its own responsibilities and restrictions, which are not part of this model.

## Eligibility and identity lifecycle

An administrator assignment does not establish authentication or make an otherwise ineligible Member eligible. Exercising management authority still requires valid authentication and the applicable current organization, Member, factor, binding, and session checks.

Administrator removal and manual identity changes remain subject to the [last-available-administrator safeguards](administration.md#availability-and-audit). External departure and confirmed provider revocation remain authoritative even when they leave no available administrator. Retaining a Member record or an assignment does not preserve usable management access after its eligibility is lost.

## Current implementation and further design

The current implementation stores administrator assignments separately from Members. An assigned administrator in `org_system` is a platform administrator; an assigned administrator in an ordinary organization administers that organization. Members without an assignment have no management authority. There is no generic role-definition or role-assignment API.

The [console access matrix](console.md#first-version-access-model) describes current behavior. It is not an agreed action catalog or a decision about the future scope model. Trusted CLI operations and the installation-wide credential of the [private management API](management-api.md) retain their existing, separate access contracts; they are not additional Member roles.

The remaining design sequence is:

1. Define scopes and how a role's authority applies to resources.
2. Define actions, the role-to-action mapping, and authorization checks.

This role decision introduces no scope schema, action identifiers, custom-role mechanism, permission-policy language, new credential type, or application-authorization service. It does not change the existing OIDC profile, database schema, or runtime behavior.
