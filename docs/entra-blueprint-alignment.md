# Microsoft Entra Agent ID Blueprint Alignment

Agent DID now includes an **Agent Identity Blueprint** alignment profile. The profile mirrors the operational shape of Microsoft Entra Agent ID blueprints while keeping the Agent DID core model vendor-neutral, W3C DID-first, and interoperable with A2A, ACP, and ANP.

## Conceptual model

A blueprint is a reusable template and policy container for many child agent identities. It carries shared publisher metadata, sign-in audience, identifier URIs, app roles, optional claims, group membership claim settings, token encryption references, credentials, required resource access, inheritable permissions, sponsors, owners, and lifecycle policy actions.

A child Agent ID record remains the identity authority for an agent because its `agent.did` is still the primary identifier. A child may reference `blueprint_id` at the top level or in `extensions.blueprint_id`. The control plane copies shared metadata into `extensions.blueprint.inherited_metadata` unless the child explicitly supplies an override in its Agent ID record.

## Autonomous agent flow

In autonomous flow, an agent authenticates as itself. In Microsoft Entra terms this resembles an application permission flow by a service principal. In Agent DID terms:

1. The blueprint declares required resource access visible during admin review.
2. The tenant provisions a tenant-local blueprint principal.
3. The blueprint credential maps to an OAuth/OIDC client authentication method or a DID verification method.
4. A child agent receives only permissions allowed by `inheritable_permissions`, plus any direct agent grants.
5. Effective permission preview merges inherited grants, direct grants, and explicit deny or revocation state.

The DID remains the portable subject; OAuth client IDs, app IDs, and local principal IDs are bindings and compatibility metadata.

## On-behalf-of user flow

In on-behalf-of (OBO) flow, a child agent acts with delegated user context. The Agent ID record continues to describe delegated mode under `authorization`. The blueprint can declare the delegated scopes that an administrator reviews, but the child agent must preserve user identity chain metadata and attenuation rules. Agent DID intentionally keeps these protocol requirements in the Agent ID record rather than making them Microsoft-specific.

## Agent user-account flow

Some deployments assign an agent a local user-like account for legacy systems. Agent DID models this as a governance and binding decision, not as the core identity. The blueprint can sponsor lifecycle accountability and credential rotation, while the child Agent ID record still references its DID and protocol bindings. This keeps legacy account use auditable without making account identity the root of trust.

## DID mapping

Blueprint fields map to DID and Agent ID as follows:

- `blueprint_id` identifies the reusable template and policy container.
- `agent.did` identifies each child agent identity.
- Blueprint credentials can reference DID verification methods such as `did:web:example.com#key-1`.
- OAuth/OIDC client IDs, app IDs, and service-principal IDs are recorded as bindings to a tenant-local blueprint principal.
- A2A, ACP, and ANP endpoints remain in the Agent ID record `bindings` section.

## Blueprint credentials and token flows

Blueprint credentials are intentionally provider-neutral:

- **Federated identity credentials** map to OIDC federation, workload identity federation, or DID-auth challenge exchange.
- **Key credentials / certificates** map to DID verification methods, JWT client assertions, mTLS, or certificate-bound access tokens.
- **Password credentials** are allowed for development only. The API emits a production warning whenever they are used.
- **Managed identity metadata** can describe provider-specific managed identity bindings without adding a hard dependency on Microsoft Entra.
- Expiration, rotation status, and `last_rotated_at` make credential lifecycle auditable regardless of provider.

## Where Agent DID intentionally differs from Microsoft Entra

Agent DID does not require Microsoft Entra, Microsoft Graph, app registrations, or service principals. Microsoft-compatible fields are an alignment profile layered on a DID-first protocol. Non-Microsoft identity providers can use `extension_fields` on blueprints and credentials to store issuer, audience, federation, or local principal metadata.

Agent DID also keeps child identity lifecycle explicit. Disabling a blueprint blocks child identities by setting the blueprint disabled state and disabling child records in the control plane, while the DID document and external protocol bindings remain portable and independently resolvable.

## Compatibility notes for existing Agent ID records

Existing records remain valid because `blueprint_id` is optional. Migration can be incremental:

1. Create a blueprint that captures common publisher, credential, permission, owner, and sponsor metadata.
2. Update existing Agent ID records to add `blueprint_id` at the top level or under `extensions.blueprint_id`.
3. The control plane will populate inherited blueprint metadata in `extensions.blueprint.inherited_metadata` on the next upsert.
4. Direct child-specific overrides remain in the child Agent ID record.
5. Records without a blueprint continue to behave as standalone DID-first Agent ID records.
