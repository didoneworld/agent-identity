# Contributing

## Scope

This repository defines the Agent ID protocol, not agent messaging protocols.
Changes should preserve that boundary.

## Contribution Rules

- Keep W3C DID as the identity foundation unless the spec explicitly evolves.
- Keep protocol bindings separate from core identity fields.
- Prefer backward-compatible changes for minor revisions.
- Document any breaking change in `docs/compatibility.md`.
- Include example record updates when schema changes.

## Versioning

- `0.x` means the protocol is still evolving.
- Minor version bumps may add backward-compatible fields.
- Major version bumps are required for incompatible schema changes.
