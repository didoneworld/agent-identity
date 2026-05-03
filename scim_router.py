"""
app/routers/scim_router.py

SCIM 2.0 endpoints for the AgenticIdentity resource type.

All endpoints follow RFC 7644 §3:
  GET    /v1/scim/v2/AgenticIdentities              — list (with filter + pagination)
  POST   /v1/scim/v2/AgenticIdentities              — create (triggers approval gate)
  GET    /v1/scim/v2/AgenticIdentities/{id}         — get one
  PUT    /v1/scim/v2/AgenticIdentities/{id}         — full replace
  PATCH  /v1/scim/v2/AgenticIdentities/{id}         — partial update (PatchOp)
  DELETE /v1/scim/v2/AgenticIdentities/{id}         — deprovision → SSF broadcast
  GET    /v1/scim/v2/ServiceProviderConfig          — RFC 7643 §5
  GET    /v1/scim/v2/ResourceTypes                  — RFC 7643 §6
  GET    /v1/scim/v2/Schemas                        — RFC 7643 §7

Wire in app/main.py:
    from app.routers.scim_router import router as scim_router
    app.include_router(scim_router, prefix="/v1/scim/v2", tags=["SCIM"])
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse

from app.scim.schema import (
    SCIM_AGENT_SCHEMA_URN,
    AgenticIdentityCreate,
    AgenticIdentityResponse,
    AgentStatus,
    ScimListResponse,
    ScimPatchRequest,
    scim_error,
)
from app.scim.db import (
    create_agent_record,
    delete_agent_record,
    get_agent_record,
    get_org_id_for_slug,
    list_agent_records,
    update_agent_record,
)
from app.ssf.emitter import emit_agent_deprovisioned, emit_agent_status_change
from app.approval.gate import (
    ApprovalRequest,
    create_approval_request,
)

router = APIRouter()

_SCIM_CONTENT_TYPE = "application/scim+json"


def _base_url() -> str:
    return os.environ.get("BASE_URL", "https://agent-id.openautonomyx.com")


def _scim_response(data: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        content=data,
        status_code=status_code,
        headers={"Content-Type": _SCIM_CONTENT_TYPE},
    )


# ---------------------------------------------------------------------------
# GET /ServiceProviderConfig  (RFC 7643 §5)
# ---------------------------------------------------------------------------

@router.get("/ServiceProviderConfig")
async def service_provider_config() -> JSONResponse:
    base = _base_url()
    return _scim_response({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": f"{base}/docs/scim",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "name": "OAuth Bearer Token",
                "description": "Authentication using the OAuth Bearer Token standard",
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                "type": "oauthbearertoken",
                "primary": True,
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": f"{base}/v1/scim/v2/ServiceProviderConfig",
        },
    })


# ---------------------------------------------------------------------------
# GET /ResourceTypes  (RFC 7643 §6)
# ---------------------------------------------------------------------------

@router.get("/ResourceTypes")
async def resource_types() -> JSONResponse:
    base = _base_url()
    return _scim_response({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 1,
        "Resources": [
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "Agent",
                "name": "Agent",
                "endpoint": "/AgenticIdentities",
                "description": "Agentic AI identity resource (draft-wahl-scim-agent-schema)",
                "schema": SCIM_AGENT_SCHEMA_URN,
                "meta": {
                    "resourceType": "ResourceType",
                    "location": f"{base}/v1/scim/v2/ResourceTypes/Agent",
                },
            }
        ],
    })


# ---------------------------------------------------------------------------
# GET /Schemas  (RFC 7643 §7)
# ---------------------------------------------------------------------------

@router.get("/Schemas")
async def schemas() -> JSONResponse:
    base = _base_url()
    return _scim_response({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 1,
        "Resources": [
            {
                "id": SCIM_AGENT_SCHEMA_URN,
                "name": "Agent",
                "description": "Agentic Identity resource for AI agents (draft-wahl-scim-agent-schema + OIDC-A WP §3.1)",
                "attributes": [
                    {"name": "displayName", "type": "string", "required": True, "mutability": "readWrite"},
                    {"name": "agentDid", "type": "string", "required": True, "mutability": "readOnly"},
                    {"name": "agentModel", "type": "string", "required": False, "mutability": "readWrite"},
                    {"name": "agentProvider", "type": "string", "required": False, "mutability": "readWrite"},
                    {"name": "agentVersion", "type": "string", "required": False, "mutability": "readWrite"},
                    {"name": "agentType", "type": "string", "required": False, "mutability": "readWrite",
                     "canonicalValues": ["autonomous", "delegated", "embedded"]},
                    {"name": "active", "type": "boolean", "required": False, "mutability": "readWrite"},
                    {"name": "status", "type": "string", "required": False, "mutability": "readOnly",
                     "canonicalValues": ["PendingApproval", "Active", "Suspended", "Deprovisioned"]},
                    {"name": "delegationScope", "type": "string", "multiValued": True, "mutability": "readWrite"},
                    {"name": "allowedTools", "type": "string", "multiValued": True, "mutability": "readWrite"},
                    {"name": "requiresHumanApproval", "type": "boolean", "mutability": "readWrite"},
                    {"name": "approvalThreshold", "type": "integer", "mutability": "readWrite"},
                ],
                "meta": {
                    "resourceType": "Schema",
                    "location": f"{base}/v1/scim/v2/Schemas/{SCIM_AGENT_SCHEMA_URN}",
                },
            }
        ],
    })


# ---------------------------------------------------------------------------
# GET /AgenticIdentities  — list with filter + pagination
# ---------------------------------------------------------------------------

@router.get("/AgenticIdentities")
async def list_agentic_identities(
    request: Request,
    filter: str | None = Query(None, alias="filter"),
    startIndex: int = Query(1, ge=1),
    count: int = Query(100, ge=1, le=200),
    # In production: extract org from bearer token claims
    org_slug: str = Query("default"),
) -> JSONResponse:
    org_id = await get_org_id_for_slug(org_slug)
    if not org_id:
        return _scim_response(
            scim_error(404, f"Organization '{org_slug}' not found"),
            status_code=404,
        )

    resources, total = await list_agent_records(
        org_id=org_id,
        filter_str=filter,
        start_index=startIndex,
        count=count,
    )

    base = _base_url()
    return _scim_response(
        ScimListResponse(
            totalResults=total,
            startIndex=startIndex,
            itemsPerPage=len(resources),
            Resources=[r.to_scim_dict(base) for r in resources],
        ).model_dump()
    )


# ---------------------------------------------------------------------------
# POST /AgenticIdentities  — create (triggers M-of-N approval gate)
# ---------------------------------------------------------------------------

@router.post("/AgenticIdentities", status_code=201)
async def create_agentic_identity(
    body: AgenticIdentityCreate,
    request: Request,
) -> JSONResponse:
    """
    SCIM CREATE for a new agent identity.

    Flow:
    1. Validate payload
    2. Persist with status=PendingApproval (if requiresHumanApproval=True)
       or status=Active (if requiresHumanApproval=False)
    3. If approval required → create approval request → link to CAAS decision
    4. Return 201 with location header
    """
    org_id = await get_org_id_for_slug(body.organizationSlug)
    if not org_id:
        return _scim_response(
            scim_error(404, f"Organization '{body.organizationSlug}' not found"),
            status_code=404,
        )

    # Auto-set status based on approval requirement
    if not body.requiresHumanApproval:
        body.status = AgentStatus.ACTIVE

    resource = await create_agent_record(body, org_id)

    # Trigger M-of-N approval gate if required
    if body.requiresHumanApproval:
        approval_req = ApprovalRequest(
            agent_record_id=resource.id,
            org_slug=body.organizationSlug,
            agent_did=body.agentDid,
            agent_display_name=body.displayName,
            required_approvals=body.approvalThreshold,
            approval_group_id=body.approvalGroupId,
            context={
                "agent_model": body.agentModel,
                "agent_provider": body.agentProvider,
                "delegation_scope": body.delegationScope,
            },
        )
        approval_id = await create_approval_request(approval_req)
        # Store approval_id in resource metadata (TODO: persist to DB)
        resource.meta.version = f'W/"{approval_id[:8]}"'

    base = _base_url()
    location = resource.scim_location(base)
    response_body = resource.to_scim_dict(base)

    # Include approval info in response if pending
    if body.requiresHumanApproval:
        response_body["approvalStatus"] = {
            "status": "PendingApproval",
            "approvalsRequired": body.approvalThreshold,
            "approvalEndpoint": f"{base}/v1/approvals",
        }

    return JSONResponse(
        content=response_body,
        status_code=201,
        headers={
            "Content-Type": _SCIM_CONTENT_TYPE,
            "Location": location,
        },
    )


# ---------------------------------------------------------------------------
# GET /AgenticIdentities/{id}
# ---------------------------------------------------------------------------

@router.get("/AgenticIdentities/{record_id}")
async def get_agentic_identity(
    record_id: str,
    org_slug: str = Query("default"),
) -> JSONResponse:
    org_id = await get_org_id_for_slug(org_slug)
    resource = await get_agent_record(record_id, org_id or "")
    if not resource:
        return _scim_response(
            scim_error(404, f"Agent '{record_id}' not found", "noTarget"),
            status_code=404,
        )
    base = _base_url()
    return _scim_response(resource.to_scim_dict(base))


# ---------------------------------------------------------------------------
# PUT /AgenticIdentities/{id}  — full replace
# ---------------------------------------------------------------------------

@router.put("/AgenticIdentities/{record_id}")
async def replace_agentic_identity(
    record_id: str,
    body: AgenticIdentityCreate,
    org_slug: str = Query("default"),
) -> JSONResponse:
    org_id = await get_org_id_for_slug(org_slug)
    if not org_id:
        return _scim_response(scim_error(404, "Organization not found"), 404)

    old = await get_agent_record(record_id, org_id)
    if not old:
        return _scim_response(scim_error(404, f"Agent '{record_id}' not found"), 404)

    updates = body.model_dump()
    resource = await update_agent_record(record_id, org_id, updates)
    if not resource:
        return _scim_response(scim_error(500, "Update failed"), 500)

    base = _base_url()
    return _scim_response(resource.to_scim_dict(base))


# ---------------------------------------------------------------------------
# PATCH /AgenticIdentities/{id}  — partial update (PatchOp)
# ---------------------------------------------------------------------------

@router.patch("/AgenticIdentities/{record_id}")
async def patch_agentic_identity(
    record_id: str,
    body: ScimPatchRequest,
    org_slug: str = Query("default"),
) -> JSONResponse:
    """
    RFC 7644 §3.5.2 PATCH.
    Supports: replace active, replace status, replace delegationScope,
              replace agentModel/agentProvider/agentVersion.
    """
    org_id = await get_org_id_for_slug(org_slug)
    if not org_id:
        return _scim_response(scim_error(404, "Organization not found"), 404)

    old = await get_agent_record(record_id, org_id)
    if not old:
        return _scim_response(scim_error(404, f"Agent '{record_id}' not found"), 404)

    updates: dict = {}
    for op in body.Operations:
        if op.op.lower() not in ("add", "replace", "remove"):
            return _scim_response(
                scim_error(400, f"Unsupported op: {op.op}", "invalidSyntax"), 400
            )
        path = op.path or ""
        value = op.value

        if path == "active":
            updates["active"] = bool(value)
            if not value and old.status == AgentStatus.ACTIVE:
                # Suspension — emit SSF status change
                updates["status"] = AgentStatus.SUSPENDED.value
                await emit_agent_status_change(
                    agent_id=record_id,
                    agent_did=old.agentDid,
                    old_status=AgentStatus.ACTIVE.value,
                    new_status=AgentStatus.SUSPENDED.value,
                    reason="scim_patch_deactivate",
                )
        elif path in ("agentModel", "agentProvider", "agentVersion",
                      "delegationScope", "allowedTools", "displayName"):
            updates[path] = value
        else:
            # Unknown path — RFC 7644 says return 400 for unknown paths on replace
            if op.op.lower() == "replace":
                return _scim_response(
                    scim_error(400, f"Unknown attribute path: {path}", "invalidPath"),
                    400,
                )

    resource = await update_agent_record(record_id, org_id, updates)
    if not resource:
        return _scim_response(scim_error(500, "Patch failed"), 500)

    base = _base_url()
    return _scim_response(resource.to_scim_dict(base))


# ---------------------------------------------------------------------------
# DELETE /AgenticIdentities/{id}  — deprovision + SSF broadcast
# ---------------------------------------------------------------------------

@router.delete("/AgenticIdentities/{record_id}", status_code=204)
async def delete_agentic_identity(
    record_id: str,
    org_slug: str = Query("default"),
) -> JSONResponse:
    """
    SCIM DELETE implementing WP §3.2 de-provisioning:
    1. Fetch the record (need DID for SSF subject)
    2. Set status=Deprovisioned in DB
    3. Emit SSF AGENT_DEPROVISIONED to all registered receivers
       (cross-system broadcast — Phase 2 item 2)
    4. Return 204
    """
    org_id = await get_org_id_for_slug(org_slug)
    if not org_id:
        return _scim_response(scim_error(404, "Organization not found"), 404)

    # Fetch before delete so we have the DID for the SSF subject
    resource = await get_agent_record(record_id, org_id)
    if not resource:
        return _scim_response(
            scim_error(404, f"Agent '{record_id}' not found", "noTarget"),
            status_code=404,
        )

    agent_did = resource.agentDid

    deleted = await delete_agent_record(record_id, org_id)
    if not deleted:
        return _scim_response(scim_error(500, "Delete failed"), 500)

    # Emit SSF AGENT_DEPROVISIONED — the cross-system broadcast (WP §3.2)
    await emit_agent_deprovisioned(
        agent_id=record_id,
        agent_did=agent_did,
        organization_slug=org_slug,
        reason="scim_delete",
    )

    return JSONResponse(content=None, status_code=204)
