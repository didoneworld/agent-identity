# Agent ID Protocol Draft

## Purpose

The Agent ID Protocol defines a versioned, protocol-neutral agent identity envelope built on W3C Decentralized Identifiers (DIDs).

It is intended to be published and reused across organizations, runtimes, and interoperability protocols.
It also declares how an identified agent is authorized and governed once it starts acting beyond a simple synchronous request cycle.

## Non-Goals

- It does not define agent messaging.
- It does not replace A2A, ACP, or ANP.
- It does not define a new decentralized identifier format when W3C DID already exists.

## Core Principles

- W3C DID as identity foundation
- Protocol neutrality
- Distinct agent identity even during delegated operation
- Explicit delegated authority
- Auditability and lifecycle governance
- Explicit versioning
- Extensibility
- Backward-compatible evolution where feasible

## Core Record

```yaml
agent_id_protocol_version: "0.2.0"
agent:
  did: did:<method>:<method-specific-id>
  display_name: <human-readable-name>
  owner: <team-or-organization>
  role: <primary-role>
  environment: <environment>
  version: <version>
  status: <active|disabled|quarantine>
  trust_level: <internal|curated|external>
  capabilities:
    - <capability>
authorization:
  mode: <autonomous|delegated|hybrid>
  subject_context: <first_party|on_behalf_of_user|on_behalf_of_team|multi_party>
  delegation_proof_formats:
    - <oauth_token_exchange|oidc_identity_assertion|verifiable_credentials|biscuits|macaroons>
  scope_reference: <uri-or-policy-id>
  expires_at: <rfc3339-timestamp-or-null>
  max_delegation_depth: <integer>
  attenuation_required: <true|false>
  human_approval_required: <true|false>
governance:
  provisioning: <manual|scim|dynamic_client_registration|internal_iam>
  audit_endpoint: <uri-or-null>
  status_endpoint: <uri-or-null>
  deprovisioning_endpoint: <uri-or-null>
  identity_chain_preserved: <true|false>
```

The authorization block exists because a DID alone is not enough to explain whether an agent is operating for itself, on behalf of a user, or on behalf of a team. Consumers must not infer delegated authority from the transport binding alone.

The governance block exists because long-running and asynchronous agents need explicit lifecycle and audit controls. A revoked or quarantined agent should be removable across connected systems without relying on out-of-band documentation.

## DID Method Guidance

Choose the DID method based on deployment and trust model.

- `did:web`: best default for organizations publishing agent identities over HTTPS with ordinary web infrastructure.
- `did:key`: good for local, ephemeral, offline, or lightweight agents where simple self-certifying identity is enough.
- `did:ion`, `did:cheqd`, or other method-specific options: only when the ecosystem or compliance model explicitly requires them.

Selection rules:
- Prefer `did:web` for public, organization-managed agent identities.
- Prefer `did:key` for development, private lab, or temporary agent identities.
- Do not require one DID method in the Agent ID protocol core.
- Record method-specific operational assumptions outside the core identity schema.

## Binding Model

Bindings are optional attachments to the DID-backed core record.

```yaml
bindings:
  a2a:
    endpoint_url: https://example.com/a2a
    agent_card_name: <agent-card-name>
  acp:
    endpoint_url: https://example.com/acp
  anp:
    did: did:<method>:<method-specific-id>
    endpoint_url: https://example.com/anp/message
```

Bindings do not replace authorization semantics. For example, an A2A endpoint may be present for both an autonomous first-party agent and a delegated cross-domain agent. The authorization block is the source of truth for that distinction.

## Authorization Model

- `mode=autonomous` means the agent acts with its own directly assigned authority.
- `mode=delegated` means the agent acts on behalf of another subject and must preserve that subject context in logs and downstream proofs.
- `mode=hybrid` means the agent can switch between first-party and delegated operation and must make that boundary explicit.
- `max_delegation_depth` constrains recursive delegation to sub-agents.
- `attenuation_required=true` means any sub-delegation must narrow scope rather than copy the full parent authority.
- `human_approval_required=true` signals that some actions require escalation to a human-controlled approval flow.

The protocol intentionally allows multiple delegated proof models, including OAuth token exchange, OpenID identity assertions, and verifiable credentials, because different trust domains will choose different implementations.

Recommended validation rules:
- `mode=autonomous` should use `subject_context=first_party`.
- `mode=delegated` should not use `subject_context=first_party`.
- delegated records should declare a non-null `scope_reference`.
- delegated and hybrid records should preserve identity chains for downstream auditability.

## Governance Model

- `provisioning` records how the agent identity enters the control plane.
- `audit_endpoint` exposes where decision and identity-chain evidence can be retrieved.
- `status_endpoint` exposes live lifecycle state beyond the published static record.
- `deprovisioning_endpoint` supports emergency removal for compromised or retired long-running agents.
- `identity_chain_preserved=true` means the deployment commits to retaining the original identity context across downstream calls when delegation occurs.

## Evolution Model

- Every record declares `agent_id_protocol_version`.
- Consumers should ignore unknown extension fields.
- Binding blocks may expand independently of core identity fields.
- Future identity protocols may be mapped alongside DID, but DID is the default identity foundation.
