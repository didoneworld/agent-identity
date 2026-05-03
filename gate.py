"""
app/approval/gate.py

M-of-N human provisioning approval gate.

Implements WP §3.4 "Scalable Human Governance":
  - Any agent with requiresHumanApproval=True is held in PendingApproval
    state until M-of-N reviewers approve via the CAAS decision-service (port 50055).
  - This module is the bridge between agent-did (identity plane) and
    CAAS (authorization plane).

CAAS decision-service integration:
  The CAAS decision-service at port 50055 implements M-of-N human approval
  via its existing gRPC interface. Until CAAS publishes a stable gRPC contract,
  we talk to it via an HTTP shim that CAAS exposes at /decisions.
  The CAAS REST API is at api-gateway:3001.

Wire in main.py:
    from app.approval.gate import approval_router
    app.include_router(approval_router, prefix="/v1/approvals", tags=["Approvals"])
"""

from __future__ import annotations

import os
import time
import uuid
from enum import Enum
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from app.ssf.emitter import emit_agent_deprovisioned, emit_agent_status_change

approval_router = APIRouter()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _caas_base() -> str:
    return os.environ.get(
        "CAAS_API_GATEWAY_URL", "http://localhost:3001"
    ).rstrip("/")


# ---------------------------------------------------------------------------
# Approval request state (in-memory — replace with DB table)
# ---------------------------------------------------------------------------

class ApprovalState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


_APPROVAL_REQUESTS: dict[str, dict] = {}
# request_id -> {
#   agent_record_id, org_slug, required_approvals (M),
#   approvals: [{"approver_id", "decision", "timestamp", "comment"}],
#   state, created_at, expires_at, caas_decision_id
# }

_APPROVAL_TTL = 86400 * 3   # 3 days default


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ApprovalRequest(BaseModel):
    agent_record_id: str
    org_slug: str
    agent_did: str
    agent_display_name: str
    required_approvals: int = 1             # M in M-of-N
    approval_group_id: str | None = None    # CAAS group to notify
    context: dict[str, Any] = {}           # extra metadata for reviewers
    ttl_seconds: int = _APPROVAL_TTL


class ApprovalDecision(BaseModel):
    approver_id: str
    decision: str                           # "approve" | "reject"
    comment: str | None = None


class ApprovalStatus(BaseModel):
    request_id: str
    state: ApprovalState
    required_approvals: int
    received_approvals: int
    approvals: list[dict]
    created_at: float
    expires_at: float
    caas_decision_id: str | None


# ---------------------------------------------------------------------------
# Core gate functions
# ---------------------------------------------------------------------------

async def create_approval_request(req: ApprovalRequest) -> str:
    """
    Create a pending approval request for a new agent provisioning.
    Returns the request_id. The SCIM POST handler calls this and sets
    the agent record status=PendingApproval until resolved.

    Also creates a corresponding decision in CAAS decision-service
    so CAAS-side reviewers see the request in their queue.
    """
    request_id = str(uuid.uuid4())
    caas_decision_id = await _create_caas_decision(req, request_id)

    _APPROVAL_REQUESTS[request_id] = {
        "agent_record_id": req.agent_record_id,
        "org_slug": req.org_slug,
        "agent_did": req.agent_did,
        "agent_display_name": req.agent_display_name,
        "required_approvals": req.required_approvals,
        "approval_group_id": req.approval_group_id,
        "approvals": [],
        "state": ApprovalState.PENDING,
        "created_at": time.time(),
        "expires_at": time.time() + req.ttl_seconds,
        "caas_decision_id": caas_decision_id,
        "context": req.context,
    }
    return request_id


async def submit_approval_decision(
    request_id: str,
    decision: ApprovalDecision,
) -> ApprovalStatus:
    """
    Record an approver's decision on a pending approval request.
    When the M-of-N threshold is reached, activate the agent record
    and emit an SSF event. On rejection, deprovision immediately.

    Also syncs the decision to CAAS decision-service.
    """
    req = _APPROVAL_REQUESTS.get(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval request not found")

    # Check expiry
    if time.time() > req["expires_at"]:
        req["state"] = ApprovalState.EXPIRED
        raise HTTPException(status_code=410, detail="Approval request has expired")

    if req["state"] != ApprovalState.PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"Request is already {req['state'].value}",
        )

    # Deduplicate — one vote per approver
    existing = {a["approver_id"] for a in req["approvals"]}
    if decision.approver_id in existing:
        raise HTTPException(
            status_code=409, detail="Approver has already voted on this request"
        )

    # Record the vote
    req["approvals"].append({
        "approver_id": decision.approver_id,
        "decision": decision.decision,
        "timestamp": time.time(),
        "comment": decision.comment,
    })

    # Sync to CAAS
    await _sync_decision_to_caas(req.get("caas_decision_id"), decision)

    # Count approvals and rejections
    approve_count = sum(
        1 for a in req["approvals"] if a["decision"] == "approve"
    )
    reject_count = sum(
        1 for a in req["approvals"] if a["decision"] == "reject"
    )

    if decision.decision == "reject":
        # Any rejection = immediate reject (strict policy)
        req["state"] = ApprovalState.REJECTED
        await _on_rejected(req)
    elif approve_count >= req["required_approvals"]:
        req["state"] = ApprovalState.APPROVED
        await _on_approved(req)

    return ApprovalStatus(
        request_id=request_id,
        state=req["state"],
        required_approvals=req["required_approvals"],
        received_approvals=approve_count,
        approvals=req["approvals"],
        created_at=req["created_at"],
        expires_at=req["expires_at"],
        caas_decision_id=req.get("caas_decision_id"),
    )


async def get_approval_status(request_id: str) -> ApprovalStatus:
    req = _APPROVAL_REQUESTS.get(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval request not found")

    # Auto-expire stale requests
    if time.time() > req["expires_at"] and req["state"] == ApprovalState.PENDING:
        req["state"] = ApprovalState.EXPIRED

    return ApprovalStatus(
        request_id=request_id,
        state=req["state"],
        required_approvals=req["required_approvals"],
        received_approvals=sum(
            1 for a in req["approvals"] if a["decision"] == "approve"
        ),
        approvals=req["approvals"],
        created_at=req["created_at"],
        expires_at=req["expires_at"],
        caas_decision_id=req.get("caas_decision_id"),
    )


# ---------------------------------------------------------------------------
# Callbacks on approval/rejection
# ---------------------------------------------------------------------------

async def _on_approved(req: dict) -> None:
    """
    Activate the agent record: set status=Active in DB + emit SSF event.
    TODO: replace stub with real DB update:
        await db.execute(
            "UPDATE agent_records SET status='Active', updated_at=$1 WHERE id=$2",
            datetime.now(timezone.utc), req["agent_record_id"]
        )
    """
    import logging
    logging.getLogger(__name__).info(
        "Agent provisioning APPROVED: record_id=%s did=%s",
        req["agent_record_id"], req["agent_did"],
    )

    # Emit SSF status change event
    await emit_agent_status_change(
        agent_id=req["agent_record_id"],
        agent_did=req["agent_did"],
        old_status="PendingApproval",
        new_status="Active",
        reason="m_of_n_approval_granted",
    )

    # TODO: create CAAS SpiceDB tuples for the newly activated agent
    # (delegationScope → relationship tuples)


async def _on_rejected(req: dict) -> None:
    """
    Deprovision the pending agent record + emit SSF deprovisioned event.
    TODO: DB update:
        await db.execute(
            "UPDATE agent_records SET status='Deprovisioned', updated_at=$1 WHERE id=$2",
            datetime.now(timezone.utc), req["agent_record_id"]
        )
    """
    import logging
    logging.getLogger(__name__).info(
        "Agent provisioning REJECTED: record_id=%s did=%s",
        req["agent_record_id"], req["agent_did"],
    )

    from app.approval.gate import approval_router  # noqa (kept for import clarity)
    await emit_agent_deprovisioned(
        agent_id=req["agent_record_id"],
        agent_did=req["agent_did"],
        organization_slug=req["org_slug"],
        reason="provisioning_rejected",
    )


# ---------------------------------------------------------------------------
# CAAS decision-service bridge
# ---------------------------------------------------------------------------

async def _create_caas_decision(
    req: ApprovalRequest,
    local_request_id: str,
) -> str | None:
    """
    Create a corresponding decision in CAAS decision-service.
    The CAAS api-gateway exposes a /decisions endpoint on port 3001.
    Falls back gracefully if CAAS is unreachable (local-only mode).
    """
    caas_url = f"{_caas_base()}/decisions"
    payload = {
        "external_id": local_request_id,
        "type": "agent_provisioning",
        "title": f"Approve agent: {req.agent_display_name}",
        "description": (
            f"New agent requesting provisioning.\n"
            f"DID: {req.agent_did}\n"
            f"Org: {req.org_slug}\n"
            f"Required approvals: {req.required_approvals}"
        ),
        "required_approvals": req.required_approvals,
        "group_id": req.approval_group_id,
        "metadata": {
            "agent_record_id": req.agent_record_id,
            "agent_did": req.agent_did,
            **req.context,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(caas_url, json=payload)
            if resp.status_code == 201:
                return resp.json().get("decision_id")
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning(
            "CAAS decision-service unreachable (%s) — running in local-only mode",
            exc,
        )
    return None


async def _sync_decision_to_caas(
    caas_decision_id: str | None,
    decision: ApprovalDecision,
) -> None:
    """POST an approval/rejection vote to the CAAS decision already created."""
    if not caas_decision_id:
        return
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(
                f"{_caas_base()}/decisions/{caas_decision_id}/votes",
                json={
                    "approver_id": decision.approver_id,
                    "decision": decision.decision,
                    "comment": decision.comment,
                },
            )
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning("CAAS vote sync failed: %s", exc)


# ---------------------------------------------------------------------------
# REST routes for the approval workflow
# ---------------------------------------------------------------------------

@approval_router.get(
    "/{request_id}",
    summary="Get approval request status",
    response_model=ApprovalStatus,
)
async def get_approval(request_id: str) -> ApprovalStatus:
    return await get_approval_status(request_id)


@approval_router.post(
    "/{request_id}/decisions",
    summary="Submit an approval or rejection decision",
    response_model=ApprovalStatus,
)
async def submit_decision(
    request_id: str,
    body: ApprovalDecision,
) -> ApprovalStatus:
    return await submit_approval_decision(request_id, body)


@approval_router.get(
    "/",
    summary="List pending approval requests (admin only)",
)
async def list_approvals(
    org_slug: str | None = None,
    state: ApprovalState | None = None,
) -> JSONResponse:
    results = []
    for rid, req in _APPROVAL_REQUESTS.items():
        if org_slug and req["org_slug"] != org_slug:
            continue
        if state and req["state"] != state:
            continue
        results.append({
            "request_id": rid,
            "agent_display_name": req["agent_display_name"],
            "agent_did": req["agent_did"],
            "org_slug": req["org_slug"],
            "state": req["state"],
            "required_approvals": req["required_approvals"],
            "received_approvals": sum(
                1 for a in req["approvals"] if a["decision"] == "approve"
            ),
            "created_at": req["created_at"],
            "expires_at": req["expires_at"],
        })
    return JSONResponse(content={"approvals": results, "total": len(results)})
