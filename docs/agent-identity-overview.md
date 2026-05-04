# Agent Identity Overview

Welcome to the Agent Identity documentation. Agent Identity is an open source, vendor-agnostic agent identity and access management (IAM) platform built around modern identity standards including W3C Decentralized Identifiers (DID), OpenID Connect (OIDC), SAML, and SCIM.

## What is Agent Identity?

Agent Identity provides a control plane for managing **autonomous agents** in enterprise environments. It addresses the emerging challenge of securing and managing AI agents that need to access resources, authenticate to services, and operate with varying degrees of autonomy.

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                    Agent Identity Architecture                   │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │   AI    │    │   API   │    │   Web   │    │  Admin  │  │
│  │ Agents  │───▶│   API   │───▶│   UI    │───▶│ Console │  │
│  └──────────┘    └────┬────┘    └──────────┘    └──────────┘  │
│                         │                                     │
│                    ┌────▼────┐                             │
│                    │  Core   │                             │
│                    │ Service │                             │
│                    └────┬────┘                             │
│                         │                                     │
│    ┌──────────┐    ┌────▼────┐    ┌──────────┐              │
│    │  OIDC   │    │  DID    │    │   SQL   │              │
│    │ Provider│◀───│ Registry│◀───│ Database│              │
│    └─────────┘    └─────────┘    └─────────┘              │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

## Key Concepts

### Agent ID Records

An **Agent ID Record** is a structured document that identifies an autonomous agent and captures its authorization, governance, and lifecycle metadata:

```json
{
  "agent": {
    "did": "did:web:agent.example.com/ai-assistant-prod",
    "name": "Production AI Assistant"
  },
  "authorization": {
    "mode": "autonomous",
    "on_behalf_of": [],
    "delegated_by": []
  },
  "governance": {
    "status": "active",
    "owner": "org:didoneworld",
    "sponsor": "security@didoneworld.com"
  },
  "capabilities": {
    "features": ["chat", "filesystem", "code_execution"],
    "limits": {"daily_requests": 10000}
  }
}
```

### Decentralized Identifiers (DID)

DIDs provide a **vendor-neutral** identity foundation. Unlike traditional usernames or API keys, DIDs are:

- **Self-sovereign**: Agents own their identity without depending on a central authority
- **Portable**: Move between platforms without losing identity
- **Verifiable**: Cryptographically prove control without contacting an issuer

### Lifecycle Management

Agent Identity supports complete **lifecycle management** for agent populations:

| State | Description | Allowed Operations |
|-------|------------|----------------|
| `draft` | Initial creation, not yet active | update, submit_review |
| `pending_review` | Awaiting approval | approve, reject |
| `active` | Fully operational | use, suspend, rotate |
| `suspended` | Temporary pause | resume, deprovision |
| `quarantined` | Restricted for investigation | release, deprovision |
| `deprovisioned` | Permanent removal | archive, restore |
| `archived` | Retained for auditing | none (read-only) |

### Agent Identity Blueprints

**Blueprints** are reusable templates that capture organizational policy for fleets of similar agents:

- Credential policies and rotation schedules
- Required permissions and scope
- Owner and sponsor assignments
- Lifecycle automation rules

## Why Agent Identity?

### Problem: Unmanaged AI Agents

Enterprise AI adoption creates new identity challenges:

| Challenge | Traditional IAM | Agent Identity |
|-----------|-----------------|----------------|
| Agent provisioning | Not designed for | First-class support |
| Credential rotation | Manual | Automated policies |
| Autonomous operation | Not supported | Explicit modes |
| Fleet management | N/A | Blueprint templates |
| Audit compliance | Basic | Full lifecycle events |

### Solution: Agent Identity

Agent Identity provides:

1. **Vendor-neutral foundation** - Built on open standards (DID, OIDC, SAML, SCIM)
2. **Blueprint-driven fleets** - Policy templates for multiple agents
3. **Lifecycle automation** - Governance gates, rotation, renewal, quarantine
4. **Entra alignment** - Optional Microsoft Entra Agent ID compatibility

## Quick Links

| Content Type | Description |
|-------------|-------------|
| [Quick Start](./how-to-guide.md) | Get started in 5 minutes |
| [Lifecycle Management](./lifecycle-management.md) | Learn lifecycle states and transitions |
| [Blueprint Guide](./entra-blueprint-alignment.md) | Configure blueprints |
| [API Reference](./product-documentation.md) | Complete API documentation |
| [Protocol Spec](./agent-id-spec.md) | Agent ID record format |

## Next Steps

- **Try it out**: Follow the [Quick Start Guide](./how-to-guide.md)
- **Learn concepts**: Read [Lifecycle Management](./lifecycle-management.md)
- **Integrate**: Explore the [API Reference](./product-documentation.md)
