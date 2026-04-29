# Agent ID Protocol

A standalone, publishable agent identity protocol built on W3C Decentralized Identifiers (DIDs).

## Scope

This repository defines:
- the Agent ID protocol draft
- the core DID-backed agent record
- protocol binding examples for A2A, ACP, and ANP
- publication and compatibility guidance

This repository does not define agent messaging. It is intended to work alongside interoperability protocols such as A2A, ACP, and ANP.

## Layout

- `docs/agent-id-spec.md`: protocol draft
- `docs/compatibility.md`: evolution and compatibility rules
- `schemas/agent-id-record.yaml`: core record example
- `examples/a2a-agent-card.json`: A2A binding example
- `templates/publish-checklist.md`: publication checklist

## Identity Foundation

The protocol uses W3C DID as the identity foundation.

## Recommended DID Methods

- `did:web` for public organization-managed agent identities
- `did:key` for local, ephemeral, or lightweight agent identities
