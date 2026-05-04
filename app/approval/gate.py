"""
app/approval/gate.py  (Phase 2 + AuthZEN wiring)

M-of-N human provisioning approval gate using Agent-Auth's AuthZEN
SDK (via app.authzen.AsyncPEPClient) as the PEP client to CAAS.

Two AuthZEN pre-flight checks:
  1. PROVISION check before creating an approval request
  2. APPROVE/REJECT check before recording each vote

All other M-of-N logic (dedup, threshold, expiry, SSF emission) unchanged.
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from enum import Enum
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.authzen import AgentAction, AgentContext, AgentResource, AgentSubject, AsyncPEPClient
from app.ssf.emitter import emit_agent_deprovisioned, emit_agent_status_change

log = logging.getLogger(__name__)
approval_router = APIRouter()


def _pep() -> AsyncPEPClient:
    return AsyncPEPClient.from_settings()


class ApprovalState(str, Enum):
    PENDING  = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED  = "expired"


_APPROVAL_REQUESTS: dict[str, dict] = {}
_APPROVAL_TTL = 86400 * 3


class ApprovalRequest(BaseModel):
    agent_record_id: str
    org_slug: str
    agent_did: str
    agent_display_name: str
    required_approvals: int = 1
    approval_group_id: str | None = None
    context: dict[str, Any] = {}
    ttl_seconds: int = _APPROVAL_TTL


class ApprovalDecision(BaseModel):
    approver_id: str
    decision: str           # "approve" | "reject"
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
    authzen_allowed: bool | None = None


async def create_approval_request(req: ApprovalRequest) -> str:
    # AuthZEN pre-flight: can this agent DID be provisioned in this org?
    pep = _pep()
    decision = await pep.check_access(
        subject=AgentSubject.from_did(req.agent_did, display_name=req.agent_display_name),
        action=AgentAction.PROVISION,
        resource=AgentResource.organization(req.org_slug),
        context=AgentContext.from_request(org_slug=req.org_slug),
    )

    if decision.denied and not decision.context.get("reason", "").endswith("fail_open"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"CAAS PDP denied provisioning: {decision.context.get('reason', 'policy_deny')}",
        )

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
        "authzen_allowed": decision.allowed,
    }
    return request_id


async def submit_approval_decision(request_id: str, decision: ApprovalDecision) -> ApprovalStatus:
    req = _APPROVAL_REQUESTS.get(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if time.time() > req["expires_at"]:
        req["state"] = ApprovalState.EXPIRED
        raise HTTPException(status_code=410, detail="Approval request has expired")
    if req["state"] != ApprovalState.PENDING:
        raise HTTPException(status_code=409, detail=f"Request is already {req['state'].value}")

    existing = {a["approver_id"] for a in req["approvals"]}
    if decision.approver_id in existing:
        raise HTTPException(status_code=409, detail="Approver has already voted")

    # AuthZEN check: is this approver allowed to approve/reject?
    pep = _pep()
    az_action = AgentAction.APPROVE if decision.decision == "approve" else AgentAction.REJECT
    authzen = await pep.check_access(
        subject=AgentSubject.human(decision.approver_id, req["org_slug"]),
        action=az_action,
        resource=AgentResource.approval_request(request_id),
        context=AgentContext.from_request(org_slug=req["org_slug"]),
    )

    if authzen.denied and not authzen.context.get("reason", "").endswith("fail_open"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"CAAS PDP denied vote: {authzen.context.get('reason', 'policy_deny')}",
        )

    req["approvals"].append({
        "approver_id": decision.approver_id,
        "decision": decision.decision,
        "timestamp": time.time(),
        "comment": decision.comment,
        "authzen_allowed": authzen.allowed,
    })
    await _sync_decision_to_caas(req.get("caas_decision_id"), decision)

    approve_count = sum(1 for a in req["approvals"] if a["decision"] == "approve")

    if decision.decision == "reject":
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
        authzen_allowed=authzen.allowed,
    )


async def get_approval_status(request_id: str) -> ApprovalStatus:
    req = _APPROVAL_REQUESTS.get(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if time.time() > req["expires_at"] and req["state"] == ApprovalState.PENDING:
        req["state"] = ApprovalState.EXPIRED
    return ApprovalStatus(
        request_id=request_id,
        state=req["state"],
        required_approvals=req["required_approvals"],
        received_approvals=sum(1 for a in req["approvals"] if a["decision"] == "approve"),
        approvals=req["approvals"],
        created_at=req["created_at"],
        expires_at=req["expires_at"],
        caas_decision_id=req.get("caas_decision_id"),
        authzen_allowed=req.get("authzen_allowed"),
    )


async def _on_approved(req: dict) -> None:
    log.info("Agent provisioning APPROVED via AuthZEN: %s %s", req["agent_record_id"], req["agent_did"])
    # TODO: UPDATE agent_records SET status='Active' WHERE id=req["agent_record_id"]
    await emit_agent_status_change(
        agent_id=req["agent_record_id"], agent_did=req["agent_did"],
        old_status="PendingApproval", new_status="Active", reason="m_of_n_approval_granted",
    )


async def _on_rejected(req: dict) -> None:
    log.info("Agent provisioning REJECTED via AuthZEN: %s %s", req["agent_record_id"], req["agent_did"])
    # TODO: UPDATE agent_records SET status='Deprovisioned' WHERE id=req["agent_record_id"]
    await emit_agent_deprovisioned(
        agent_id=req["agent_record_id"], agent_did=req["agent_did"],
        organization_slug=req["org_slug"], reason="provisioning_rejected",
    )


async def _create_caas_decision(req: ApprovalRequest, local_request_id: str) -> str | None:
    from app.config import settings
    caas_url = settings.caas_api_gateway_url
    if not caas_url:
        return None
    try:
        async with httpx.AsyncClient(timeout=settings.caas_timeout_seconds) as client:
            resp = await client.post(f"{caas_url}/decisions", json={
                "external_id": local_request_id,
                "type": "agent_provisioning",
                "title": f"Approve agent: {req.agent_display_name}",
                "description": f"DID: {req.agent_did}\nOrg: {req.org_slug}\nRequired: {req.required_approvals}",
                "required_approvals": req.required_approvals,
                "group_id": req.approval_group_id,
                "metadata": {"agent_record_id": req.agent_record_id, "agent_did": req.agent_did, **req.context},
            })
            if resp.status_code == 201:
                return resp.json().get("decision_id")
    except Exception as exc:
        log.warning("CAAS decision-service unreachable — local-only mode: %s", exc)
    return None


async def _sync_decision_to_caas(caas_decision_id: str | None, decision: ApprovalDecision) -> None:
    if not caas_decision_id:
        return
    from app.config import settings
    try:
        async with httpx.AsyncClient(timeout=settings.caas_timeout_seconds) as client:
            await client.post(f"{settings.caas_api_gateway_url}/decisions/{caas_decision_id}/votes", json={
                "approver_id": decision.approver_id, "decision": decision.decision, "comment": decision.comment,
            })
    except Exception as exc:
        log.warning("CAAS vote sync failed: %s", exc)


# Routes
@approval_router.get("/{request_id}", response_model=ApprovalStatus)
async def get_approval(request_id: str) -> ApprovalStatus:
    return await get_approval_status(request_id)

@approval_router.post("/{request_id}/decisions", response_model=ApprovalStatus)
async def submit_decision(request_id: str, body: ApprovalDecision) -> ApprovalStatus:
    return await submit_approval_decision(request_id, body)

@approval_router.get("/")
async def list_approvals(org_slug: str | None = None, state: ApprovalState | None = None) -> JSONResponse:
    results = [
        {"request_id": rid, "agent_display_name": r["agent_display_name"],
         "agent_did": r["agent_did"], "org_slug": r["org_slug"], "state": r["state"],
         "required_approvals": r["required_approvals"],
         "received_approvals": sum(1 for a in r["approvals"] if a["decision"] == "approve"),
         "authzen_allowed": r.get("authzen_allowed")}
        for rid, r in _APPROVAL_REQUESTS.items()
        if (not org_slug or r["org_slug"] == org_slug) and (not state or r["state"] == state)
    ]
    return JSONResponse(content={"approvals": results, "total": len(results)})
