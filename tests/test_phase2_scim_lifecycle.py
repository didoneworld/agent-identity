"""
tests/test_phase2_scim_lifecycle.py

Test coverage for Phase 2 — all three items:
  1. SCIM 2.0 AgenticIdentity CRUD + RFC compliance
  2. SCIM DELETE → SSF broadcast chain
  3. M-of-N provisioning approval gate (+ CAAS bridge)

Run with:
    pip install pytest pytest-asyncio httpx fastapi starlette pydantic
    pytest tests/test_phase2_scim_lifecycle.py -v
"""

from __future__ import annotations

import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Item 1a: SCIM Schema
# ---------------------------------------------------------------------------

class TestScimSchema:
    def test_agentic_identity_create_defaults(self):
        from app.scim.schema import AgenticIdentityCreate, AgentStatus
        body = AgenticIdentityCreate(
            displayName="Test Agent",
            agentDid="did:web:example.com:agents:test",
            organizationSlug="test-org",
        )
        assert body.status == AgentStatus.PENDING_APPROVAL
        assert body.requiresHumanApproval is True
        assert body.approvalThreshold == 1
        assert body.active is True

    def test_agentic_identity_response_scim_location(self):
        from app.scim.schema import AgenticIdentityResponse
        r = AgenticIdentityResponse(
            displayName="Agent X",
            agentDid="did:key:z6Mk",
            organizationSlug="org1",
        )
        r.id = "test-id-123"
        loc = r.scim_location("https://example.com")
        assert "AgenticIdentities" in loc
        assert "test-id-123" in loc

    def test_scim_error_shape(self):
        from app.scim.schema import scim_error, SCIM_ERROR_URN
        err = scim_error(404, "Not found", "noTarget")
        assert err["status"] == "404"
        assert err["detail"] == "Not found"
        assert err["scimType"] == "noTarget"
        assert SCIM_ERROR_URN in err["schemas"]

    def test_agent_status_enum_values(self):
        from app.scim.schema import AgentStatus
        assert AgentStatus.PENDING_APPROVAL == "PendingApproval"
        assert AgentStatus.ACTIVE == "Active"
        assert AgentStatus.SUSPENDED == "Suspended"
        assert AgentStatus.DEPROVISIONED == "Deprovisioned"

    def test_scim_list_response_shape(self):
        from app.scim.schema import ScimListResponse, SCIM_LIST_RESPONSE_URN
        resp = ScimListResponse(
            totalResults=2,
            itemsPerPage=2,
            Resources=[{"id": "a"}, {"id": "b"}],
        )
        d = resp.model_dump()
        assert SCIM_LIST_RESPONSE_URN in d["schemas"]
        assert d["totalResults"] == 2


# ---------------------------------------------------------------------------
# Item 1b: SCIM DB layer
# ---------------------------------------------------------------------------

class TestScimDb:
    def test_to_db_row_maps_fields(self):
        from app.scim.schema import AgenticIdentityCreate
        from app.scim.db import _to_db_row
        import json

        body = AgenticIdentityCreate(
            displayName="Agent A",
            agentDid="did:web:example.com:agents:a",
            organizationSlug="org1",
            agentModel="claude-sonnet-4-6",
            agentProvider="anthropic",
            delegationScope=["read:files"],
        )
        row = _to_db_row(body, "org-uuid-123")
        raw = json.loads(row["raw_record"])

        assert row["did"] == "did:web:example.com:agents:a"
        assert row["display_name"] == "Agent A"
        assert row["organization_id"] == "org-uuid-123"
        assert raw["agent_model"] == "claude-sonnet-4-6"
        assert raw["agent_provider"] == "anthropic"
        assert raw["delegation_scope"] == ["read:files"]

    def test_from_db_row_reconstructs_resource(self):
        from app.scim.schema import AgentStatus
        from app.scim.db import _from_db_row
        import json

        row = {
            "id": str(uuid.uuid4()),
            "did": "did:key:z6MkTest",
            "display_name": "Test Agent",
            "record_type": "autonomous",
            "status": "Active",
            "organization_id": "org1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
            "raw_record": json.dumps({
                "organization_slug": "test-org",
                "agent_provider": "openai",
                "delegation_scope": ["write:db"],
                "requires_human_approval": False,
                "approval_threshold": 1,
                "active": True,
            }),
        }
        resource = _from_db_row(row)
        assert resource.agentDid == "did:key:z6MkTest"
        assert resource.status == AgentStatus.ACTIVE
        assert resource.agentProvider == "openai"
        assert "write:db" in resource.delegationScope
        assert resource.requiresHumanApproval is False


# ---------------------------------------------------------------------------
# Item 1c: SCIM router endpoints
# ---------------------------------------------------------------------------

@pytest.fixture
def scim_app():
    from fastapi import FastAPI
    from app.routers.scim_router import router
    app = FastAPI()
    app.include_router(router, prefix="/v1/scim/v2")
    return app


class TestScimRouter:
    def test_service_provider_config(self, scim_app):
        from fastapi.testclient import TestClient
        with TestClient(scim_app) as client:
            resp = client.get("/v1/scim/v2/ServiceProviderConfig")
        assert resp.status_code == 200
        doc = resp.json()
        assert doc["patch"]["supported"] is True
        assert doc["filter"]["supported"] is True

    def test_resource_types(self, scim_app):
        from fastapi.testclient import TestClient
        with TestClient(scim_app) as client:
            resp = client.get("/v1/scim/v2/ResourceTypes")
        assert resp.status_code == 200
        doc = resp.json()
        assert doc["totalResults"] == 1
        assert doc["Resources"][0]["name"] == "Agent"

    def test_schemas_endpoint(self, scim_app):
        from fastapi.testclient import TestClient
        from app.scim.schema import SCIM_AGENT_SCHEMA_URN
        with TestClient(scim_app) as client:
            resp = client.get("/v1/scim/v2/Schemas")
        assert resp.status_code == 200
        doc = resp.json()
        assert doc["Resources"][0]["id"] == SCIM_AGENT_SCHEMA_URN
        # Verify OIDC-A claims are in schema
        attr_names = [a["name"] for a in doc["Resources"][0]["attributes"]]
        assert "agentModel" in attr_names
        assert "agentProvider" in attr_names
        assert "agentVersion" in attr_names

    def test_post_creates_agent_with_approval_pending(self, scim_app):
        from fastapi.testclient import TestClient
        with patch("app.routers.scim_router.get_org_id_for_slug", new=AsyncMock(return_value="org-uuid")), \
             patch("app.routers.scim_router.create_agent_record", new=AsyncMock(
                 return_value=_make_resource(status="PendingApproval")
             )), \
             patch("app.routers.scim_router.create_approval_request", new=AsyncMock(return_value="approval-123")):
            with TestClient(scim_app) as client:
                resp = client.post(
                    "/v1/scim/v2/AgenticIdentities",
                    json={
                        "displayName": "My Agent",
                        "agentDid": "did:web:example.com:agents:x",
                        "organizationSlug": "test-org",
                        "agentModel": "claude-sonnet-4-6",
                        "agentProvider": "anthropic",
                        "requiresHumanApproval": True,
                        "approvalThreshold": 2,
                    },
                )
        assert resp.status_code == 201
        assert "Location" in resp.headers
        body = resp.json()
        assert "approvalStatus" in body
        assert body["approvalStatus"]["status"] == "PendingApproval"
        assert body["approvalStatus"]["approvalsRequired"] == 2

    def test_post_creates_active_agent_without_approval(self, scim_app):
        from fastapi.testclient import TestClient
        with patch("app.routers.scim_router.get_org_id_for_slug", new=AsyncMock(return_value="org-uuid")), \
             patch("app.routers.scim_router.create_agent_record", new=AsyncMock(
                 return_value=_make_resource(status="Active")
             )):
            with TestClient(scim_app) as client:
                resp = client.post(
                    "/v1/scim/v2/AgenticIdentities",
                    json={
                        "displayName": "Auto Agent",
                        "agentDid": "did:key:z6Mk",
                        "organizationSlug": "test-org",
                        "requiresHumanApproval": False,
                    },
                )
        assert resp.status_code == 201
        body = resp.json()
        # No approval status block when approval not required
        assert "approvalStatus" not in body

    def test_delete_triggers_ssf_broadcast(self, scim_app):
        from fastapi.testclient import TestClient
        resource = _make_resource(status="Active")

        with patch("app.routers.scim_router.get_org_id_for_slug", new=AsyncMock(return_value="org-uuid")), \
             patch("app.routers.scim_router.get_agent_record", new=AsyncMock(return_value=resource)), \
             patch("app.routers.scim_router.delete_agent_record", new=AsyncMock(return_value=True)), \
             patch("app.routers.scim_router.emit_agent_deprovisioned", new=AsyncMock()) as mock_ssf:
            with TestClient(scim_app) as client:
                resp = client.delete(
                    f"/v1/scim/v2/AgenticIdentities/{resource.id}",
                    params={"org_slug": "test-org"},
                )

        assert resp.status_code == 204
        mock_ssf.assert_awaited_once()
        call_kwargs = mock_ssf.call_args.kwargs
        assert call_kwargs["agent_id"] == resource.id
        assert call_kwargs["reason"] == "scim_delete"

    def test_delete_not_found_returns_404(self, scim_app):
        from fastapi.testclient import TestClient
        with patch("app.routers.scim_router.get_org_id_for_slug", new=AsyncMock(return_value="org-uuid")), \
             patch("app.routers.scim_router.get_agent_record", new=AsyncMock(return_value=None)):
            with TestClient(scim_app) as client:
                resp = client.delete(
                    "/v1/scim/v2/AgenticIdentities/nonexistent",
                    params={"org_slug": "test-org"},
                )
        assert resp.status_code == 404

    def test_patch_deactivate_emits_ssf_status_change(self, scim_app):
        from fastapi.testclient import TestClient
        resource = _make_resource(status="Active")

        with patch("app.routers.scim_router.get_org_id_for_slug", new=AsyncMock(return_value="org-uuid")), \
             patch("app.routers.scim_router.get_agent_record", new=AsyncMock(return_value=resource)), \
             patch("app.routers.scim_router.update_agent_record", new=AsyncMock(return_value=resource)), \
             patch("app.routers.scim_router.emit_agent_status_change", new=AsyncMock()) as mock_ssf:
            with TestClient(scim_app) as client:
                resp = client.patch(
                    f"/v1/scim/v2/AgenticIdentities/{resource.id}",
                    params={"org_slug": "test-org"},
                    json={
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                        "Operations": [
                            {"op": "replace", "path": "active", "value": False}
                        ],
                    },
                )

        assert resp.status_code == 200
        mock_ssf.assert_awaited_once()
        call_kwargs = mock_ssf.call_args.kwargs
        assert call_kwargs["new_status"] == "Suspended"


# ---------------------------------------------------------------------------
# Item 2: SSF emitter
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestSSFEmitter:
    async def test_register_receiver_creates_entry(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.ssf.emitter import ssf_router, _RECEIVERS

        _RECEIVERS.clear()
        app = FastAPI()
        app.include_router(ssf_router, prefix="/v1/ssf")

        with TestClient(app) as client:
            resp = client.post(
                "/v1/ssf/receivers",
                json={
                    "endpoint_url": "https://receiver.example.com/events",
                    "delivery_mode": "push",
                },
            )
        assert resp.status_code == 201
        body = resp.json()
        assert "receiver_id" in body
        assert "stream_token" in body
        assert body["receiver_id"] in _RECEIVERS

    async def test_emit_deprovisioned_delivers_to_matching_receiver(self):
        from app.ssf.emitter import (
            AGENT_DEPROVISIONED,
            _RECEIVERS,
            emit_agent_deprovisioned,
        )

        _RECEIVERS.clear()
        receiver_id = str(uuid.uuid4())
        _RECEIVERS[receiver_id] = {
            "endpoint_url": "https://recv.example.com/events",
            "event_types": [AGENT_DEPROVISIONED],
            "delivery_mode": "poll",
            "pending_events": [],
        }

        await emit_agent_deprovisioned(
            agent_id="agent-001",
            agent_did="did:web:example.com:agents:001",
            organization_slug="test-org",
            reason="scim_delete",
        )

        assert len(_RECEIVERS[receiver_id]["pending_events"]) == 1
        event = _RECEIVERS[receiver_id]["pending_events"][0]
        assert AGENT_DEPROVISIONED in event["events"]

    async def test_emit_does_not_deliver_to_wrong_event_type(self):
        from app.ssf.emitter import (
            AGENT_DEPROVISIONED,
            CAEP_SESSION_REVOKED,
            _RECEIVERS,
            emit_agent_deprovisioned,
        )

        _RECEIVERS.clear()
        receiver_id = str(uuid.uuid4())
        _RECEIVERS[receiver_id] = {
            "endpoint_url": "https://recv.example.com/events",
            "event_types": [CAEP_SESSION_REVOKED],  # only session events
            "delivery_mode": "poll",
            "pending_events": [],
        }

        await emit_agent_deprovisioned(
            agent_id="agent-002",
            agent_did="did:web:example.com:agents:002",
            organization_slug="test-org",
            reason="scim_delete",
        )

        # Should not deliver — receiver only wants session events
        assert len(_RECEIVERS[receiver_id]["pending_events"]) == 0

    async def test_poll_clears_queue(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.ssf.emitter import ssf_router, _RECEIVERS, AGENT_DEPROVISIONED

        _RECEIVERS.clear()
        receiver_id = str(uuid.uuid4())
        _RECEIVERS[receiver_id] = {
            "endpoint_url": "https://recv.example.com/events",
            "event_types": [AGENT_DEPROVISIONED],
            "delivery_mode": "poll",
            "pending_events": [{"event": "test"}],
        }

        app = FastAPI()
        app.include_router(ssf_router, prefix="/v1/ssf")

        with TestClient(app) as client:
            resp = client.get(f"/v1/ssf/receivers/{receiver_id}/events")

        assert resp.status_code == 200
        assert len(resp.json()["sets"]) == 1
        # Queue cleared after poll
        assert len(_RECEIVERS[receiver_id]["pending_events"]) == 0


# ---------------------------------------------------------------------------
# Item 3: M-of-N approval gate
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestApprovalGate:
    async def test_create_approval_request_stores_state(self):
        from app.approval.gate import (
            ApprovalRequest,
            ApprovalState,
            _APPROVAL_REQUESTS,
            create_approval_request,
        )
        _APPROVAL_REQUESTS.clear()

        with patch("app.approval.gate._create_caas_decision", new=AsyncMock(return_value="caas-123")):
            request_id = await create_approval_request(ApprovalRequest(
                agent_record_id=str(uuid.uuid4()),
                org_slug="test-org",
                agent_did="did:web:example.com:agents:new",
                agent_display_name="New Agent",
                required_approvals=2,
            ))

        assert request_id in _APPROVAL_REQUESTS
        req = _APPROVAL_REQUESTS[request_id]
        assert req["state"] == ApprovalState.PENDING
        assert req["required_approvals"] == 2
        assert req["caas_decision_id"] == "caas-123"

    async def test_single_approval_does_not_activate_when_threshold_2(self):
        from app.approval.gate import (
            ApprovalDecision,
            ApprovalRequest,
            ApprovalState,
            _APPROVAL_REQUESTS,
            create_approval_request,
            submit_approval_decision,
        )
        _APPROVAL_REQUESTS.clear()

        with patch("app.approval.gate._create_caas_decision", new=AsyncMock(return_value=None)), \
             patch("app.approval.gate._sync_decision_to_caas", new=AsyncMock()):
            request_id = await create_approval_request(ApprovalRequest(
                agent_record_id=str(uuid.uuid4()),
                org_slug="test-org",
                agent_did="did:web:example.com:agents:new2",
                agent_display_name="New Agent 2",
                required_approvals=2,
            ))
            status = await submit_approval_decision(
                request_id,
                ApprovalDecision(approver_id="approver-1", decision="approve"),
            )

        # Only 1 of 2 approvals — still pending
        assert status.state == ApprovalState.PENDING
        assert status.received_approvals == 1

    async def test_m_of_n_approval_activates_agent(self):
        from app.approval.gate import (
            ApprovalDecision,
            ApprovalRequest,
            ApprovalState,
            _APPROVAL_REQUESTS,
            create_approval_request,
            submit_approval_decision,
        )
        _APPROVAL_REQUESTS.clear()

        with patch("app.approval.gate._create_caas_decision", new=AsyncMock(return_value=None)), \
             patch("app.approval.gate._sync_decision_to_caas", new=AsyncMock()), \
             patch("app.approval.gate.emit_agent_status_change", new=AsyncMock()) as mock_ssf:
            request_id = await create_approval_request(ApprovalRequest(
                agent_record_id=str(uuid.uuid4()),
                org_slug="test-org",
                agent_did="did:web:example.com:agents:new3",
                agent_display_name="New Agent 3",
                required_approvals=2,
            ))
            await submit_approval_decision(
                request_id,
                ApprovalDecision(approver_id="approver-1", decision="approve"),
            )
            status = await submit_approval_decision(
                request_id,
                ApprovalDecision(approver_id="approver-2", decision="approve"),
            )

        assert status.state == ApprovalState.APPROVED
        assert status.received_approvals == 2
        # SSF status change emitted on approval
        mock_ssf.assert_awaited_once()
        assert mock_ssf.call_args.kwargs["new_status"] == "Active"

    async def test_rejection_immediately_deactivates(self):
        from app.approval.gate import (
            ApprovalDecision,
            ApprovalRequest,
            ApprovalState,
            _APPROVAL_REQUESTS,
            create_approval_request,
            submit_approval_decision,
        )
        _APPROVAL_REQUESTS.clear()

        with patch("app.approval.gate._create_caas_decision", new=AsyncMock(return_value=None)), \
             patch("app.approval.gate._sync_decision_to_caas", new=AsyncMock()), \
             patch("app.approval.gate.emit_agent_deprovisioned", new=AsyncMock()) as mock_deprov:
            request_id = await create_approval_request(ApprovalRequest(
                agent_record_id=str(uuid.uuid4()),
                org_slug="test-org",
                agent_did="did:web:example.com:agents:rejected",
                agent_display_name="Rejected Agent",
                required_approvals=1,
            ))
            status = await submit_approval_decision(
                request_id,
                ApprovalDecision(
                    approver_id="approver-1",
                    decision="reject",
                    comment="Policy violation",
                ),
            )

        assert status.state == ApprovalState.REJECTED
        mock_deprov.assert_awaited_once()
        assert mock_deprov.call_args.kwargs["reason"] == "provisioning_rejected"

    async def test_duplicate_vote_rejected(self):
        from fastapi import HTTPException
        from app.approval.gate import (
            ApprovalDecision,
            ApprovalRequest,
            _APPROVAL_REQUESTS,
            create_approval_request,
            submit_approval_decision,
        )
        _APPROVAL_REQUESTS.clear()

        with patch("app.approval.gate._create_caas_decision", new=AsyncMock(return_value=None)), \
             patch("app.approval.gate._sync_decision_to_caas", new=AsyncMock()):
            request_id = await create_approval_request(ApprovalRequest(
                agent_record_id=str(uuid.uuid4()),
                org_slug="test-org",
                agent_did="did:web:example.com:agents:dup",
                agent_display_name="Dup Agent",
                required_approvals=3,
            ))
            await submit_approval_decision(
                request_id,
                ApprovalDecision(approver_id="approver-1", decision="approve"),
            )
            with pytest.raises(HTTPException) as exc:
                await submit_approval_decision(
                    request_id,
                    ApprovalDecision(approver_id="approver-1", decision="approve"),
                )
        assert exc.value.status_code == 409

    async def test_expired_request_raises_410(self):
        from fastapi import HTTPException
        from app.approval.gate import (
            ApprovalDecision,
            ApprovalRequest,
            ApprovalState,
            _APPROVAL_REQUESTS,
            create_approval_request,
            submit_approval_decision,
        )
        _APPROVAL_REQUESTS.clear()

        with patch("app.approval.gate._create_caas_decision", new=AsyncMock(return_value=None)):
            request_id = await create_approval_request(ApprovalRequest(
                agent_record_id=str(uuid.uuid4()),
                org_slug="test-org",
                agent_did="did:web:example.com:agents:exp",
                agent_display_name="Exp Agent",
                required_approvals=1,
                ttl_seconds=1,
            ))

        # Force expiry
        _APPROVAL_REQUESTS[request_id]["expires_at"] = time.time() - 1

        with pytest.raises(HTTPException) as exc:
            with patch("app.approval.gate._sync_decision_to_caas", new=AsyncMock()):
                await submit_approval_decision(
                    request_id,
                    ApprovalDecision(approver_id="approver-1", decision="approve"),
                )
        assert exc.value.status_code == 410


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_resource(status: str = "Active"):
    from app.scim.schema import AgenticIdentityResponse, AgentStatus
    r = AgenticIdentityResponse(
        displayName="Test Agent",
        agentDid="did:web:example.com:agents:test",
        organizationSlug="test-org",
        status=AgentStatus(status),
    )
    r.id = str(uuid.uuid4())
    return r
