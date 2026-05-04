from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class AgentLifecycleAction(StrEnum):
    SUBMIT_REVIEW = "submit-review"
    APPROVE = "approve"
    ACTIVATE = "activate"
    SUSPEND = "suspend"
    RESUME = "resume"
    QUARANTINE = "quarantine"
    RENEW = "renew"
    ROTATE_CREDENTIALS = "rotate-credentials"
    DEPROVISION = "deprovision"
    ARCHIVE = "archive"


class BlueprintLifecycleAction(StrEnum):
    ACTIVATE = "activate"
    DISABLE = "disable"
    ENABLE = "enable"
    DEPRECATE = "deprecate"
    QUARANTINE = "quarantine"
    DEPROVISION_CHILDREN = "deprovision-children"
    ARCHIVE = "archive"


@dataclass(slots=True)
class LifecycleRequest:
    reason: str | None = None
    ticket_id: str | None = None
    requested_by: str | None = None
    approved_by: str | None = None
    effective_at: str | datetime | None = None
    expires_at: str | datetime | None = None
    force: bool = False
    dry_run: bool = False
    idempotency_key: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        for key in ("effective_at", "expires_at"):
            value = payload.get(key)
            if isinstance(value, datetime):
                payload[key] = value.isoformat()
        return {key: value for key, value in payload.items() if value is not None and value != {}}


@dataclass(slots=True)
class ValidationReport:
    passed: bool
    failed: list[str]
    warnings: list[str]
    blocking_issues: list[str]
    recommended_actions: list[str]

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ValidationReport":
        return cls(
            passed=payload["passed"],
            failed=list(payload.get("failed", [])),
            warnings=list(payload.get("warnings", [])),
            blocking_issues=list(payload.get("blocking_issues", [])),
            recommended_actions=list(payload.get("recommended_actions", [])),
        )


@dataclass(slots=True)
class LifecycleTransition:
    subject_type: str
    subject_id: str
    previous_state: str | None
    new_state: str | None
    dry_run: bool = False
    validation_report: ValidationReport | None = None
    audit_event_id: str | None = None
    deprovisioning_report: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "LifecycleTransition":
        report = payload.get("validation_report")
        return cls(
            subject_type=payload["subject_type"],
            subject_id=payload["subject_id"],
            previous_state=payload.get("previous_state"),
            new_state=payload.get("new_state"),
            dry_run=payload.get("dry_run", False),
            validation_report=ValidationReport.from_dict(report) if isinstance(report, dict) else None,
            audit_event_id=payload.get("audit_event_id"),
            deprovisioning_report=payload.get("deprovisioning_report"),
            raw=payload,
        )


@dataclass(slots=True)
class AgentRecord:
    id: str
    did: str
    display_name: str
    status: str
    lifecycle_state: str
    record: dict[str, Any]
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AgentRecord":
        return cls(
            id=payload["id"],
            did=payload["did"],
            display_name=payload["display_name"],
            status=payload["status"],
            lifecycle_state=payload.get("lifecycle_state", "active"),
            record=payload.get("record", {}),
            raw=payload,
        )


@dataclass(slots=True)
class Blueprint:
    id: str
    organization_id: str
    lifecycle_state: str
    metadata: dict[str, Any]
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Blueprint":
        return cls(
            id=payload["id"],
            organization_id=payload["organization_id"],
            lifecycle_state=payload["lifecycle_state"],
            metadata=payload.get("metadata", {}),
            raw=payload,
        )


@dataclass(slots=True)
class LifecycleAuditEvent:
    event_id: str
    event_type: str
    subject_type: str
    subject_id: str
    previous_state: str | None
    new_state: str | None
    evidence_hash: str
    timestamp: str
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "LifecycleAuditEvent":
        return cls(
            event_id=payload["event_id"],
            event_type=payload["event_type"],
            subject_type=payload["subject_type"],
            subject_id=payload["subject_id"],
            previous_state=payload.get("previous_state"),
            new_state=payload.get("new_state"),
            evidence_hash=payload["evidence_hash"],
            timestamp=payload["timestamp"],
            raw=payload,
        )
