# Agent ID Protocol

A standalone, publishable agent identity protocol built on W3C Decentralized Identifiers (DIDs).

## Scope

This repository defines:
- the Agent ID protocol draft
- the core DID-backed agent record
- authorization and governance metadata for agent operation
- protocol binding examples for A2A, ACP, and ANP
- publication and compatibility guidance

This repository does not define agent messaging. It is intended to work alongside interoperability protocols such as A2A, ACP, and ANP.

## Layout

- `docs/agent-id-spec.md`: protocol draft
- `docs/openid-alignment.md`: rationale for the authorization and governance additions
- `docs/compatibility.md`: evolution and compatibility rules
- `schemas/agent-id-record.yaml`: core record example
- `schemas/json/agent-id-record.schema.json`: JSON Schema for validation
- `examples/a2a-agent-card.json`: A2A binding example
- `templates/publish-checklist.md`: publication checklist

## Container Validation

The repository includes a minimal validation image:

```bash
docker build -t agent-id-protocol:local .
docker run --rm agent-id-protocol:local
```

The image runs `scripts/validate.sh`, which executes the repository validation tests.

## Identity Foundation

The protocol uses W3C DID as the identity foundation.

## Security Model

The protocol now treats agent identity, delegated authority, and governance as separate concerns:
- DIDs identify the agent.
- Authorization metadata describes whether the agent acts autonomously or on behalf of users or teams.
- Governance metadata exposes lifecycle, audit, and deprovisioning controls needed for long-running agents.

## Recommended DID Methods

- `did:web` for public organization-managed agent identities
- `did:key` for local, ephemeral, or lightweight agent identities

## Example DID Methods

- `examples/did-methods/did-web-agent.yaml` for organization-managed public identities
- `examples/did-methods/did-key-agent.yaml` for local or ephemeral identities
