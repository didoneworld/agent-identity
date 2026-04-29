# Compatibility And Evolution

## Versioning

- Every Agent ID record declares `agent_id_protocol_version`.
- Minor additions should be backward compatible.
- Breaking changes should require a new major version.
- Version `0.2.0` adds required `authorization` and `governance` blocks to support delegated authority, auditability, and lifecycle management.

## Consumer Rules

- Consumers should ignore unknown extension fields.
- Consumers should validate required DID and binding fields only for the bindings they implement.
- Consumers should not treat interoperability protocol identifiers as the primary identity.
- Consumers should treat the `authorization` block as authoritative for whether the agent acts autonomously, on behalf of a user, on behalf of a team, or in a hybrid mode.
- Consumers should not assume an agent may recursively delegate unless the record explicitly permits it.
- Consumers should preserve the identity context promised by `governance.identity_chain_preserved` when emitting audit logs or translating tokens across domains.
- Producers should avoid publishing semantically inconsistent combinations such as `mode=delegated` with `subject_context=first_party`.

## Binding Independence

- A2A, ACP, and ANP bindings may evolve independently of the core DID-backed record.
- Multiple bindings may coexist on one record.
- Bindings may be omitted entirely.
- Binding presence does not imply any specific authorization model.


## Pinned Release Consumers

Consumers should prefer pinning a released version such as `v0.2.0` when integrating the protocol in production systems.
