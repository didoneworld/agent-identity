# OpenID Alignment Notes

This revision strengthens the draft using the October 2025 OpenID Foundation paper *Identity Management for Agentic AI*.

## What Changed

- Agents remain identifiable as agents even when they act on behalf of a user or team.
- Delegated authority is explicit instead of implied by the binding or transport.
- Records can express whether recursive delegation is allowed and how deep it may go.
- Audit and lifecycle endpoints are part of the record so long-running agents can be monitored and deprovisioned consistently.

## Why These Changes Matter

The OpenID paper emphasizes several issues that the original draft did not model well enough:
- agents should not impersonate users; they should present delegated authority while remaining distinct
- long-running agents need durable identity plus operational deprovisioning
- multi-hop agent networks need scope attenuation controls
- audit trails must preserve the original identity context across domains

## Design Choice

The protocol still keeps DID as the identity root and stays neutral on transport protocols such as A2A, ACP, ANP, and MCP. The new fields do not prescribe OAuth, OpenID Connect, or verifiable credential flows, but they let publishers declare which proof models and governance controls their deployment relies on.
