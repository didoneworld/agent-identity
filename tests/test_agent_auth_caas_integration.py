from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.integrations.agent_auth import AgentAuthClient, AuthorizationEvaluationRequest
from app.routers.authorization import get_agent_auth_client, get_caas_client, router


REQUEST_BODY = {
    "subject": {"type": "agent", "id": "did:web:example.com:agents:agent-123", "tenant": "didoneworld"},
    "action": {"name": "tool.invoke"},
    "resource": {"type": "tool", "id": "github.create_pr"},
    "context": {"scopes": ["repo:write"], "risk_score": 0.22},
}


class AllowingAgentAuthClient:
    async def evaluate(self, payload: AuthorizationEvaluationRequest):
        return await AgentAuthClient(base_url="").evaluate(payload)


class MockAgentAuthClient:
    async def evaluate(self, payload: AuthorizationEvaluationRequest):
        return {
            "decision": True,
            "decision_id": "dec_test",
            "reason": None,
            "obligations": [{"type": "audit", "level": "full"}],
            "source": "agent-auth",
            "raw": {"decision": True, "decision_id": "dec_test"},
        }


class RecordingCaaSClient:
    def __init__(self) -> None:
        self.forwarded = []

    async def forward_decision(self, payload):
        self.forwarded.append(payload)
        return True


def build_client(agent_auth, caas=None) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_agent_auth_client] = lambda: agent_auth
    app.dependency_overrides[get_caas_client] = lambda: caas or RecordingCaaSClient()
    return TestClient(app)


def test_evaluate_denies_when_agent_auth_is_not_configured() -> None:
    client = build_client(AgentAuthClient(base_url=""))

    response = client.post("/v1/authorization/evaluate", json=REQUEST_BODY)

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] is False
    assert body["source"] == "agent-did-local"
    assert body["reason"] == "agent-auth service not configured"


def test_evaluate_accepts_agent_auth_style_response_and_forwards_to_caas() -> None:
    caas = RecordingCaaSClient()
    client = build_client(MockAgentAuthClient(), caas=caas)

    response = client.post("/v1/authorization/evaluate", json=REQUEST_BODY)

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] is True
    assert body["decision_id"] == "dec_test"
    assert body["source"] == "agent-auth"
    assert len(caas.forwarded) == 1
    assert caas.forwarded[0].decision is True
    assert caas.forwarded[0].resource["id"] == "github.create_pr"


@pytest.mark.asyncio
async def test_agent_auth_http_client_normalizes_allowed_response() -> None:
    request = AuthorizationEvaluationRequest.model_validate(REQUEST_BODY)

    def handler(http_request: httpx.Request) -> httpx.Response:
        assert http_request.url.path == "/access/v1/evaluation"
        return httpx.Response(200, json={"allowed": True, "id": "authz_1"})

    transport = httpx.MockTransport(handler)

    class TestAgentAuthClient(AgentAuthClient):
        async def evaluate(self, payload: AuthorizationEvaluationRequest):
            headers = {"content-type": "application/json"}
            async with httpx.AsyncClient(transport=transport, timeout=self.timeout_seconds) as client:
                response = await client.post(f"{self.base_url}/access/v1/evaluation", json=payload.model_dump(), headers=headers)
                body = response.json()
            return {
                "decision": bool(body.get("decision", body.get("allowed", False))),
                "decision_id": str(body.get("decision_id") or body.get("id")),
                "source": "agent-auth",
            }

    result = await TestAgentAuthClient(base_url="http://agent-auth.test").evaluate(request)

    assert result["decision"] is True
    assert result["decision_id"] == "authz_1"
