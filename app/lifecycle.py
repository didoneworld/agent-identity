from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db_models import AgentRecord, LifecycleAuditEvent, LifecycleWebhookDelivery, utc_now

AGENT_LIFECYCLE_STATES = {
    "draft", "pending_review", "approved", "active", "suspended", "quarantined",
    "credentials_expired", "pending_rotation", "pending_renewal", "deprovisioning",
    "deprovisioned", "archived", "deleted",
}
BLUEPRINT_LIFECYCLE_STATES = {
    "draft", "active", "disabled", "deprecated", "quarantined", "deprovisioning",
    "deprovisioned", "archived", "deleted",
}

AGENT_TRANSITIONS = {
    "draft": {"pending_review", "approved", "active", "archived", "deleted"},
    "pending_review": {"approved", "draft", "quarantined", "archived", "deleted"},
    "approved": {"active", "pending_review", "archived", "deleted"},
    "active": {"suspended", "quarantined", "credentials_expired", "pending_rotation", "pending_renewal", "deprovisioning", "archived"},
    "suspended": {"active", "quarantined", "pending_renewal", "deprovisioning", "archived"},
    "quarantined": {"suspended", "active", "deprovisioning", "archived"},
    "credentials_expired": {"pending_rotation", "pending_renewal", "suspended", "deprovisioning"},
    "pending_rotation": {"active", "suspended", "quarantined", "deprovisioning"},
    "pending_renewal": {"active", "suspended", "quarantined", "deprovisioning"},
    "deprovisioning": {"deprovisioned", "suspended"},
    "deprovisioned": {"archived"},
    "archived": {"deleted"},
    "deleted": set(),
}

BLUEPRINT_TRANSITIONS = {
    "draft": {"active", "archived", "deleted"},
    "active": {"disabled", "deprecated", "quarantined", "deprovisioning", "archived"},
    "disabled": {"active", "deprecated", "deprovisioning", "archived"},
    "deprecated": {"disabled", "deprovisioning", "archived"},
    "quarantined": {"disabled", "active", "deprovisioning"},
    "deprovisioning": {"deprovisioned", "disabled"},
    "deprovisioned": {"archived"},
    "archived": {"deleted"},
    "deleted": set(),
}

AGENT_ACTION_TARGETS = {
    "submit-review": "pending_review", "approve": "approved", "activate": "active",
    "suspend": "suspended", "resume": "active", "quarantine": "quarantined",
    "renew": "pending_renewal", "rotate-credentials": "pending_rotation",
    "deprovision": "deprovisioning", "archive": "archived", "delete": "deleted",
}
BLUEPRINT_ACTION_TARGETS = {
    "activate": "active", "disable": "disabled", "enable": "active", "deprecate": "deprecated",
    "quarantine": "quarantined", "deprovision-children": "deprovisioning", "archive": "archived", "delete": "deleted",
}
DEPROVISIONING_STEPS = [
    "mark_deprovisioning", "revoke_tokens", "revoke_credentials", "revoke_permissions",
    "remove_fga_tuples", "notify_webhooks", "disable_agent_record", "tombstone_public_metadata",
    "archive_audit_records", "mark_deprovisioned",
]
IRREVERSIBLE_STEPS = ["revoke_tokens", "revoke_credentials", "tombstone_public_metadata"]


def _stable_hash(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def agent_lifecycle_state(record: AgentRecord) -> str:
    lifecycle = (record.record_json or {}).get("lifecycle") or {}
    state = lifecycle.get("state")
    if state in AGENT_LIFECYCLE_STATES:
        return state
    if record.deprovisioned_at is not None or record.status in {"deprovisioned", "archived"}:
        return "archived" if record.status == "archived" else "deprovisioned"
    if record.status in {"disabled", "suspended"}:
        return "suspended"
    return "active"


def set_agent_lifecycle_state(record: AgentRecord, state: str) -> None:
    payload = dict(record.record_json or {})
    lifecycle = dict(payload.get("lifecycle") or {})
    lifecycle["state"] = state
    lifecycle["updated_at"] = utc_now().isoformat()
    payload["lifecycle"] = lifecycle
    if "agent" in payload:
        payload["agent"] = dict(payload["agent"])
        payload["agent"]["lifecycle_state"] = state
        if state in {"active", "approved", "pending_review", "draft", "pending_rotation", "pending_renewal"}:
            payload["agent"].setdefault("status", "enabled")
        elif state in {"suspended", "quarantined", "credentials_expired", "deprovisioning", "deprovisioned", "archived", "deleted"}:
            payload["agent"]["status"] = "disabled"
    record.record_json = payload
    record.status = "enabled" if state == "active" else "disabled" if state in {"suspended", "quarantined", "deprovisioning", "deprovisioned", "archived", "deleted"} else record.status
    record.updated_at = utc_now()
    if state in {"deprovisioned", "archived", "deleted"} and record.deprovisioned_at is None:
        record.deprovisioned_at = utc_now()


def validate_transition(subject_type: str, previous: str, new: str, force: bool = False) -> None:
    transitions = AGENT_TRANSITIONS if subject_type == "agent" else BLUEPRINT_TRANSITIONS
    if previous == new:
        return
    if new not in transitions.get(previous, set()) and not force:
        raise ValueError(f"invalid {subject_type} lifecycle transition: {previous} -> {new}")


def validation_report_for_record(record: AgentRecord, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = policy or {}
    payload = record.record_json or {}
    agent = payload.get("agent") or {}
    authz = payload.get("authorization") or {}
    governance = payload.get("governance") or {}
    extensions = payload.get("extensions") or {}
    lifecycle = payload.get("lifecycle") or extensions.get("lifecycle") or {}
    risk = lifecycle.get("risk") or extensions.get("risk") or {}
    owners = lifecycle.get("owners") or extensions.get("owners") or agent.get("owners") or []
    sponsors = lifecycle.get("sponsors") or extensions.get("sponsors") or agent.get("sponsors") or []
    credentials = lifecycle.get("credentials") or extensions.get("credentials") or authz.get("credentials") or []
    permissions = lifecycle.get("permissions") or extensions.get("permissions") or authz.get("permissions") or []
    blocking: list[str] = []
    warnings: list[str] = []
    actions: list[str] = []
    now = utc_now()

    def require(ok: bool, code: str, action: str) -> None:
        if not ok:
            blocking.append(code)
            actions.append(action)

    require(str(agent.get("did") or record.did).startswith("did:"), "did_document_unresolvable", "Publish a resolvable DID document.")
    vms = lifecycle.get("verification_methods") or agent.get("verification_methods") or payload.get("verificationMethod") or []
    require(bool(vms) or record.did.startswith("did:key:"), "verification_methods_missing", "Add usable DID verification methods.")
    active_credentials = []
    for cred in credentials if isinstance(credentials, list) else []:
        expires = cred.get("expires_at") or cred.get("expiresAt")
        expired = False
        if expires:
            try:
                expired = datetime.fromisoformat(expires.replace("Z", "+00:00")) <= now
            except ValueError:
                warnings.append("credential_expiration_unparseable")
        if cred.get("status", "active") in {"active", "activated", "issued"} and not expired:
            active_credentials.append(cred)
    require(bool(active_credentials), "active_credentials_missing", "Issue or activate a non-expired credential.")
    consented = [p for p in permissions if isinstance(p, dict) and p.get("status") in {"approved", "granted", "active", "consented"}]
    require(bool(consented) or not permissions, "required_permission_consent_missing", "Collect consent for required permissions.")
    inherited_invalid = [p for p in permissions if isinstance(p, dict) and p.get("source") == "inherited" and p.get("status") in {"revoked", "expired", "denied"}]
    require(not inherited_invalid, "invalid_inherited_permissions", "Remove or re-approve invalid inherited permissions.")
    require(bool(sponsors), "sponsor_missing", "Assign an active sponsor.")
    require(bool(owners), "owner_missing", "Assign an active owner.")
    support_url = governance.get("support_url") or lifecycle.get("support_url") or extensions.get("support_url")
    terms_url = governance.get("terms_url") or lifecycle.get("terms_url") or extensions.get("terms_url")
    privacy_url = governance.get("privacy_url") or lifecycle.get("privacy_url") or extensions.get("privacy_url")
    require(bool(governance.get("audit_endpoint") or governance.get("governance_endpoint") or support_url), "governance_endpoint_unreachable", "Configure a reachable governance endpoint.")
    require(bool(lifecycle.get("audit_logging_enabled", True)), "audit_logging_disabled", "Enable immutable lifecycle audit logging.")
    public_or_multi = agent.get("visibility") == "public" or agent.get("tenant_mode") == "multitenant" or record.environment == "production"
    if public_or_multi:
        require(bool(terms_url and privacy_url and support_url), "public_urls_missing", "Provide terms, privacy, and support URLs.")
    dev_cred = any(c.get("development_only") or c.get("environment") == "development" for c in active_credentials)
    require(not (record.environment == "production" and dev_cred), "development_credentials_in_production", "Rotate to production credentials.")
    threshold = policy.get("risk_threshold", lifecycle.get("risk_threshold", 80))
    require(int(risk.get("score", 0)) < int(threshold), "risk_score_too_high", "Remediate risk findings before activation.")
    require(agent_lifecycle_state(record) != "quarantined" and not lifecycle.get("active_revocation"), "active_quarantine_or_revocation", "Release quarantine and clear revocations.")
    return {
        "passed": len(blocking) == 0,
        "failed": blocking,
        "warnings": warnings,
        "blocking_issues": blocking,
        "recommended_actions": actions,
    }


@dataclass
class LifecycleRequestData:
    reason: str | None = None
    ticket_id: str | None = None
    requested_by: str | None = None
    approved_by: str | None = None
    effective_at: datetime | None = None
    expires_at: datetime | None = None
    force: bool = False
    dry_run: bool = False
    idempotency_key: str | None = None
    metadata: dict[str, Any] | None = None


class LifecycleServiceMixin:
    def _lifecycle_audit(self, db: Session, *, organization_id: str, event_type: str, subject_type: str,
                         subject_id: str, actor_label: str, previous_state: str | None = None,
                         new_state: str | None = None, request: LifecycleRequestData | None = None,
                         metadata: dict[str, Any] | None = None, agent_record_id: str | None = None) -> LifecycleAuditEvent:
        evidence = {
            "event_type": event_type, "subject_type": subject_type, "subject_id": subject_id,
            "previous_state": previous_state, "new_state": new_state, "metadata": metadata or {},
        }
        event = LifecycleAuditEvent(
            id=str(uuid4()), organization_id=organization_id, agent_record_id=agent_record_id,
            event_type=event_type, subject_type=subject_type, subject_id=subject_id,
            previous_state=previous_state, new_state=new_state, actor_type="user", actor_id=actor_label,
            requested_by=(request.requested_by if request else None) or actor_label,
            approved_by=request.approved_by if request else None, reason=request.reason if request else None,
            ticket_id=request.ticket_id if request else None, policy_id=(request.metadata or {}).get("policy_id") if request and request.metadata else None,
            correlation_id=(request.metadata or {}).get("correlation_id") if request and request.metadata else None,
            idempotency_key=request.idempotency_key if request else None, evidence_hash=_stable_hash(evidence),
            metadata_json=metadata or {}, created_at=utc_now(),
        )
        db.add(event)
        return event

    def transition_agent_lifecycle(self, db: Session, organization_id: str, actor_label: str, record_id: str,
                                   action: str, request: LifecycleRequestData) -> tuple[AgentRecord, dict[str, Any]]:
        record = self.get_record_by_id(db, organization_id, record_id)
        if record is None:
            raise KeyError("agent record not found")
        previous = agent_lifecycle_state(record)
        target = AGENT_ACTION_TARGETS[action]
        report = validation_report_for_record(record, (request.metadata or {}).get("policy", {})) if action == "activate" else {"passed": True, "failed": [], "warnings": [], "blocking_issues": [], "recommended_actions": []}
        if action == "activate" and not report["passed"] and not request.force:
            raise PermissionError(json.dumps({"message": "activation validation gates failed", "validation_report": report}))
        validate_transition("agent", previous, target, request.force)
        if request.dry_run:
            return record, {"dry_run": True, "previous_state": previous, "new_state": target, "validation_report": report}
        set_agent_lifecycle_state(record, target)
        event = self._lifecycle_audit(db, organization_id=organization_id, event_type=f"agent.{target}", subject_type="agent", subject_id=record.id, actor_label=actor_label, previous_state=previous, new_state=target, request=request, metadata={"action": action, "validation_report": report}, agent_record_id=record.id)
        self._audit(db, organization_id=organization_id, actor_label=actor_label, action=f"lifecycle_{action}", agent_record_id=record.id, reason=request.reason, metadata={"previous_state": previous, "new_state": target, "lifecycle_event_id": event.id})
        db.commit(); db.refresh(record)
        return record, {"dry_run": False, "previous_state": previous, "new_state": target, "validation_report": report, "audit_event_id": event.id}

    def build_deprovisioning_report(self, subject_id: str, requested_by: str, dry_run: bool, failed_step: str | None = None) -> dict[str, Any]:
        completed = [] if dry_run else [s for s in DEPROVISIONING_STEPS if s != failed_step]
        failed = [] if failed_step is None else [failed_step]
        return {"agent_id": subject_id, "started_at": utc_now().isoformat(), "completed_at": None if dry_run or failed else utc_now().isoformat(), "requested_by": requested_by, "status": "dry_run" if dry_run else "partial_failure" if failed else "completed", "completed_steps": completed, "failed_steps": failed, "retryable_failures": failed, "irreversible_steps": IRREVERSIBLE_STEPS, "audit_event_ids": []}

    def list_lifecycle_audit_events(self, db: Session, organization_id: str, subject_type: str | None = None, subject_id: str | None = None) -> list[LifecycleAuditEvent]:
        stmt = select(LifecycleAuditEvent).where(LifecycleAuditEvent.organization_id == organization_id).order_by(LifecycleAuditEvent.created_at)
        if subject_type:
            stmt = stmt.where(LifecycleAuditEvent.subject_type == subject_type)
        if subject_id:
            stmt = stmt.where(LifecycleAuditEvent.subject_id == subject_id)
        return list(db.scalars(stmt))


def sign_webhook_payload(secret: str, payload: dict[str, Any]) -> str:
    return hmac.new(secret.encode(), json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()
