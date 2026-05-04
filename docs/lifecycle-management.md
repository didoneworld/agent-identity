# Agent DID Lifecycle Management

Agent DID lifecycle management adds a vendor-neutral, DID-first control plane for individual Agent ID records and blueprint-created fleets. Microsoft Entra Agent ID blueprint concepts are supported only as an optional compatibility alignment profile; lifecycle behavior remains expressed in portable Agent DID policy, audit, and webhook records.

## Lifecycle states

Agent identities use strict states: `draft`, `pending_review`, `approved`, `active`, `suspended`, `quarantined`, `credentials_expired`, `pending_rotation`, `pending_renewal`, `deprovisioning`, `deprovisioned`, `archived`, and `deleted`.

Blueprints use strict states: `draft`, `active`, `disabled`, `deprecated`, `quarantined`, `deprovisioning`, `deprovisioned`, `archived`, and `deleted`.

Invalid transitions fail with `409 Conflict`. Every successful transition writes an immutable lifecycle audit event with previous state, new state, actor, reason, ticket, policy, correlation, idempotency, evidence hash, and metadata.

## Transition diagram

```text
Agent: draft -> pending_review -> approved -> active
Agent: active -> suspended -> active
Agent: active -> quarantined -> suspended|active|deprovisioning
Agent: active -> pending_rotation|pending_renewal -> active
Agent: active|suspended|quarantined -> deprovisioning -> deprovisioned -> archived -> deleted

Blueprint: draft -> active -> disabled -> active
Blueprint: active -> deprecated|quarantined|deprovisioning|archived
Blueprint: disabled|deprecated|quarantined -> deprovisioning -> deprovisioned -> archived -> deleted
```

## Lifecycle APIs

Agent endpoints accept `reason`, `ticket_id`, `requested_by`, `approved_by`, `effective_at`, `expires_at`, `force`, `dry_run`, `idempotency_key`, and metadata:

- `POST /v1/agent-records/{agent_id}/submit-review`
- `POST /v1/agent-records/{agent_id}/approve`
- `POST /v1/agent-records/{agent_id}/activate`
- `POST /v1/agent-records/{agent_id}/suspend`
- `POST /v1/agent-records/{agent_id}/resume`
- `POST /v1/agent-records/{agent_id}/quarantine`
- `POST /v1/agent-records/{agent_id}/renew`
- `POST /v1/agent-records/{agent_id}/rotate-credentials`
- `POST /v1/agent-records/{agent_id}/deprovision`
- `POST /v1/agent-records/{agent_id}/archive`
- `DELETE /v1/agent-records/{agent_id}`

Blueprint endpoints provide activation, disable/enable, deprecation, quarantine, child deprovisioning cascade, archive, and delete operations.

## Lifecycle policies

Policies can suspend inactive agents, require renewal, quarantine high-risk agents, rotate credentials, deprovision when sponsors leave, disable child agents when blueprints are disabled, and enforce activation gates. Policy fields include lifetime, inactivity, rotation and renewal windows, approval requirements, two-person approval, sponsor/owner requirements, production hardening, and auto-remediation toggles.

## Activation gates

Activation validates DID resolvability, verification methods, active credentials, permission consent, inherited permissions, sponsor and owner presence, governance endpoint, audit logging, public terms/privacy/support URLs, production credential hygiene, risk threshold, and absence of active quarantine or revocation. The API returns a structured report with `passed`, `failed`, `warnings`, `blocking_issues`, and `recommended_actions`.

## Credential lifecycle

Credentials support `issue`, `activate`, `rotate`, `revoke`, `expire`, `recover`, and `archive`. Rotation supports dry-run previews, overlapping old/new credentials during a grace period, `retiring` status for old credentials, revocation after grace expiry, validation of the new credential, and audit events.

## Sponsor and owner lifecycle

Sponsors and owners can be added, removed, transferred, and attested. Production agents require an active sponsor. Production blueprints require at least one owner and one sponsor. Sponsor removal triggers policy evaluation and can suspend or deprovision identities. Transfers and attestations are audited.

## Permission lifecycle

Permissions can be requested, approved, denied, granted, revoked, expired, inherited, overridden, and calculated into effective permissions. Privileged permissions require approval. Expired permissions are excluded from effective permissions. Revoked inherited permissions cascade to children. Every permission change emits an audit event.

## Renewal workflow

Renewal requests include sponsor attestation, owner approval, policy validation, permission review, credential review, risk review, final approval, and a new expiration date. Renewal is required before agent, blueprint, credential, sponsor attestation, or privileged permission expiration.

## Quarantine workflow

Quarantined agents cannot authenticate, cannot receive new grants, and should have sessions revoked where possible. Credentials remain stored but unusable. Administrators can inspect, acknowledge findings, remediate, resume, suspend, or deprovision. Unresolved critical risk can trigger permanent deprovisioning.

## Deprovisioning workflow

Safe deprovisioning runs staged steps: `mark_deprovisioning`, `revoke_tokens`, `revoke_credentials`, `revoke_permissions`, `remove_fga_tuples`, `notify_webhooks`, `disable_agent_record`, `tombstone_public_metadata`, `archive_audit_records`, and `mark_deprovisioned`. Reports include completed and failed steps, retryable failures, irreversible steps, idempotency key, webhook notifications, and audit event IDs. Blueprint deprovisioning can cascade to child identities.

## Audit model

Lifecycle events are immutable and queryable:

- `GET /v1/audit/lifecycle-events`
- `GET /v1/agent-records/{agent_id}/lifecycle-events`
- `GET /v1/blueprints/{blueprint_id}/lifecycle-events`

## Webhook events

Supported events include `agent.created`, `agent.pending_review`, `agent.approved`, `agent.activated`, `agent.suspended`, `agent.quarantined`, `agent.renewal_due`, `agent.credentials_rotation_due`, `agent.credentials_rotated`, `agent.deprovisioning_started`, `agent.deprovisioned`, `blueprint.disabled`, `blueprint.deprovisioning_started`, and `blueprint.children_deprovisioned`. Delivery records include signing secret references, retry policy, status, replay support, and dead-letter status.

## Backward compatibility and migration

Existing Agent ID records without lifecycle state are interpreted as `active` when enabled and valid, `suspended` when disabled, and `archived`/`deprovisioned` when previously deprovisioned. This preserves current records while enabling explicit lifecycle fields on update.

## Operational runbooks

- **Activation:** submit review, approve, run validation, fix blocking issues, activate.
- **Credential rotation:** dry-run rotation, validate new credential, overlap old/new credentials, revoke old credential after grace period.
- **Sponsor departure:** remove sponsor, evaluate policy, transfer sponsorship or suspend/deprovision.
- **Critical risk:** create finding, quarantine, revoke sessions, remediate, resume or deprovision.
- **Deprovisioning:** dry-run, execute staged deprovisioning with idempotency key, retry failures, archive audit evidence.

## Examples

See `examples/lifecycle/` and JSON schemas in `schemas/json/` for policy, renewal, quarantine, deprovisioning, credential, permission, audit, and webhook payloads.
