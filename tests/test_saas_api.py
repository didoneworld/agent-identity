import copy
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app


def _record() -> dict:
    return {
        "agent_id_protocol_version": "0.2.0",
        "agent": {
            "did": "did:web:agents.didone.world:catalog:planner",
            "display_name": "Planner Agent",
            "owner": "didoneworld",
            "role": "planner",
            "environment": "prod",
            "version": "v1",
            "status": "active",
            "trust_level": "internal",
            "capabilities": ["planning"],
        },
        "authorization": {
            "mode": "delegated",
            "subject_context": "on_behalf_of_user",
            "delegation_proof_formats": ["oauth_token_exchange"],
            "scope_reference": "https://agents.didone.world/policies/planner",
            "expires_at": "2026-12-31T23:59:59Z",
            "max_delegation_depth": 1,
            "attenuation_required": True,
            "human_approval_required": False,
        },
        "governance": {
            "provisioning": "internal_iam",
            "audit_endpoint": "https://agents.didone.world/audit/planner",
            "status_endpoint": "https://agents.didone.world/status/planner",
            "deprovisioning_endpoint": "https://agents.didone.world/deprovision/planner",
            "identity_chain_preserved": True,
        },
        "bindings": {
            "a2a": {
                "endpoint_url": "https://agents.didone.world/a2a/planner",
                "agent_card_name": "PlannerAgent",
            },
            "acp": {"endpoint_url": None},
            "anp": {"did": None, "endpoint_url": None},
        },
        "extensions": {},
    }


def _client(tmp_path: Path) -> TestClient:
    db_path = tmp_path / "test.db"
    return TestClient(create_app(database_url=f"sqlite:///{db_path}"))


def test_health_endpoint(tmp_path: Path):
    with _client(tmp_path) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["service"] == "agent-identity-saas"


def test_bootstrap_requires_single_tenant_initialization(tmp_path: Path):
    with _client(tmp_path) as client:
        payload = {
            "organization_name": "Didone World",
            "organization_slug": "didoneworld",
            "api_key_label": "ops-admin",
        }
        response = client.post("/v1/bootstrap", json=payload)
        assert response.status_code == 201
        assert response.json()["api_key"].startswith("aidp_")

        second = client.post("/v1/bootstrap", json=payload)
        assert second.status_code == 409


def test_authenticated_agent_record_flow(tmp_path: Path):
    with _client(tmp_path) as client:
        bootstrap = client.post(
            "/v1/bootstrap",
            json={
                "organization_name": "Didone World",
                "organization_slug": "didoneworld",
                "api_key_label": "ops-admin",
            },
        )
        api_key = bootstrap.json()["api_key"]
        headers = {"X-API-Key": api_key}

        create_response = client.post("/v1/agent-records", json=_record(), headers=headers)
        assert create_response.status_code == 201
        record_id = create_response.json()["id"]
        assert create_response.json()["did"] == _record()["agent"]["did"]

        list_response = client.get("/v1/agent-records", headers=headers)
        assert list_response.status_code == 200
        assert len(list_response.json()) == 1

        detail_response = client.get(f"/v1/agent-records/{record_id}", headers=headers)
        assert detail_response.status_code == 200

        did_response = client.get(f"/v1/agent-records/by-did/{_record()['agent']['did']}", headers=headers)
        assert did_response.status_code == 200

        deprovision_response = client.post(
            f"/v1/agent-records/{record_id}/deprovision",
            json={"reason": "credential rotation"},
            headers=headers,
        )
        assert deprovision_response.status_code == 200
        assert deprovision_response.json()["status"] == "disabled"

        audit_response = client.get("/v1/audit-events", headers=headers)
        assert audit_response.status_code == 200
        actions = [event["action"] for event in audit_response.json()]
        assert "organization_bootstrapped" in actions
        assert "agent_record_created" in actions
        assert "agent_record_deprovisioned" in actions


def test_invalid_record_is_rejected(tmp_path: Path):
    with _client(tmp_path) as client:
        bootstrap = client.post(
            "/v1/bootstrap",
            json={
                "organization_name": "Didone World",
                "organization_slug": "didoneworld",
                "api_key_label": "ops-admin",
            },
        )
        headers = {"X-API-Key": bootstrap.json()["api_key"]}
        record = copy.deepcopy(_record())
        record["authorization"]["mode"] = "autonomous"

        response = client.post("/v1/agent-records", json=record, headers=headers)
        assert response.status_code == 422


def test_authentication_is_required(tmp_path: Path):
    with _client(tmp_path) as client:
        response = client.get("/v1/agent-records")
        assert response.status_code == 401
