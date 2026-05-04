import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk" / "python"))

import httpx
import pytest

from agentdid_sdk import AgentDidClient, AgentDidError, LifecycleRequest


def _transport(handler):
    return httpx.MockTransport(handler)


def test_sdk_sends_auth_headers_and_lifecycle_payload():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["api_key"] = request.headers.get("X-API-Key")
        seen["payload"] = json.loads(request.content.decode())
        return httpx.Response(
            200,
            json={
                "subject_type": "agent",
                "subject_id": "agent-1",
                "previous_state": "active",
                "new_state": "suspended",
                "dry_run": False,
            },
        )

    with AgentDidClient("https://agentdid.example", api_key="secret", transport=_transport(handler)) as client:
        transition = client.suspend_agent(
            "agent-1",
            reason="inactive",
            ticket_id="SEC-1",
            requested_by="ops@example.com",
        )

    assert seen == {
        "method": "POST",
        "path": "/v1/agent-records/agent-1/suspend",
        "api_key": "secret",
        "payload": {"reason": "inactive", "ticket_id": "SEC-1", "requested_by": "ops@example.com", "force": False, "dry_run": False},
    }
    assert transition.previous_state == "active"
    assert transition.new_state == "suspended"


def test_sdk_supports_dynamic_bearer_auth_and_deprovision_dry_run():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer dynamic-token"
        assert json.loads(request.content.decode())["dry_run"] is True
        return httpx.Response(
            200,
            json={
                "subject_type": "agent",
                "subject_id": "agent-1",
                "previous_state": "active",
                "new_state": "deprovisioning",
                "dry_run": True,
                "deprovisioning_report": {"status": "dry_run", "completed_steps": []},
            },
        )

    client = AgentDidClient("https://agentdid.example", auth_provider=lambda: "dynamic-token", transport=_transport(handler))
    transition = client.deprovision_agent("agent-1", request=LifecycleRequest(reason="preview", dry_run=True))
    client.close()

    assert transition.dry_run is True
    assert transition.deprovisioning_report == {"status": "dry_run", "completed_steps": []}


def test_sdk_normalizes_validation_reports_and_errors():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/validate"):
            return httpx.Response(
                200,
                json={
                    "passed": False,
                    "failed": ["active_credentials_missing"],
                    "warnings": [],
                    "blocking_issues": ["active_credentials_missing"],
                    "recommended_actions": ["Issue a credential."],
                },
            )
        return httpx.Response(409, json={"detail": "invalid transition"})

    with AgentDidClient("https://agentdid.example", transport=_transport(handler)) as client:
        report = client.validate_agent("agent-1")
        assert report.passed is False
        assert report.blocking_issues == ["active_credentials_missing"]
        with pytest.raises(AgentDidError) as exc:
            client.approve_agent("agent-1")

    assert exc.value.status_code == 409
    assert exc.value.detail == {"detail": "invalid transition"}
