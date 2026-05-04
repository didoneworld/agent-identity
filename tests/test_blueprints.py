from pathlib import Path

from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator
import json

from app.main import create_app


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(database_url=f"sqlite:///{tmp_path / 'blueprint.db'}"))


def _headers(client: TestClient) -> dict[str, str]:
    response = client.post("/v1/bootstrap", json={"organization_name": "Didone World", "organization_slug": "didoneworld", "api_key_label": "ops-admin"})
    return {"X-API-Key": response.json()["api_key"]}


def _blueprint() -> dict:
    return {
        "blueprint_id": "bp-basic-planner",
        "display_name": "Basic Planner Agent Blueprint",
        "description": "Reusable template for planner agents.",
        "publisher": "Didone World",
        "verified_publisher": True,
        "publisher_domain": "didone.world",
        "sign_in_audience": "single_tenant",
        "identifier_uris": ["api://didone.world/agents/planner"],
        "app_roles": [{"value": "Planner.Execute"}],
        "optional_claims": {"access_token": ["did"]},
        "group_membership_claims": [],
        "token_encryption_key_id": None,
        "certification": {"profile": "agent-did-blueprint-v1"},
        "info_urls": {"marketing": "https://didone.world", "support": "https://didone.world/support", "terms_of_service": "https://didone.world/terms", "privacy": "https://didone.world/privacy"},
        "tags": ["did"],
        "status": "active",
        "permissions": {
            "required_resource_access": [{"resource_app_id": "api://content", "scopes": ["content.read"], "app_roles": ["Content.Reader"]}],
            "inheritable_permissions": [{"resource_app_id": "api://content", "scopes": ["content.read"], "app_roles": []}],
            "consent_grants": [],
            "direct_agent_grants": [],
            "denied_permissions": []
        },
        "owners": ["user:owner"],
        "sponsors": ["group:sponsors"],
        "extension_fields": {"alignment_profile": "microsoft-entra-agent-id"}
    }


def _record() -> dict:
    return {
        "agent_id_protocol_version": "0.2.0",
        "agent": {"did": "did:web:agents.didone.world:planner", "display_name": "Planner Agent", "owner": "didoneworld", "role": "planner", "environment": "prod", "version": "v1", "status": "active", "trust_level": "internal", "capabilities": ["planning"]},
        "authorization": {"mode": "delegated", "subject_context": "on_behalf_of_user", "delegation_proof_formats": ["oauth_token_exchange"], "scope_reference": "https://agents.didone.world/policies/planner", "expires_at": "2026-12-31T23:59:59Z", "max_delegation_depth": 1, "attenuation_required": True, "human_approval_required": False},
        "governance": {"provisioning": "internal_iam", "audit_endpoint": "https://agents.didone.world/audit", "status_endpoint": "https://agents.didone.world/status", "deprovisioning_endpoint": "https://agents.didone.world/deprovision", "identity_chain_preserved": True},
        "bindings": {"a2a": {"endpoint_url": "https://agents.didone.world/a2a", "agent_card_name": "PlannerAgent"}, "acp": {"endpoint_url": None}, "anp": {"did": None, "endpoint_url": None}},
        "extensions": {}
    }


def test_blueprint_schema_examples_validate():
    schema = json.loads(Path("schemas/json/agent-identity-blueprint.schema.json").read_text())
    validator = Draft202012Validator(schema)
    for example in ["basic-agent-blueprint.json", "agent-with-inheritable-permissions.json"]:
        validator.validate(json.loads(Path("examples/blueprints", example).read_text()))


def test_blueprint_crud_create_child_disable_and_rotate(tmp_path: Path):
    with _client(tmp_path) as client:
        headers = _headers(client)
        created = client.post("/v1/blueprints", json=_blueprint(), headers=headers)
        assert created.status_code == 201
        assert created.json()["owners"] == ["user:owner"]

        patched = client.patch("/v1/blueprints/bp-basic-planner", json={"display_name": "Planner Blueprint v2"}, headers=headers)
        assert patched.status_code == 200
        assert patched.json()["display_name"] == "Planner Blueprint v2"

        child = client.post("/v1/blueprints/bp-basic-planner/agent-records", json=_record(), headers=headers)
        assert child.status_code == 201
        assert child.json()["record"]["extensions"]["blueprint"]["sponsors"] == ["group:sponsors"]

        children = client.get("/v1/blueprints/bp-basic-planner/agent-records", headers=headers)
        assert len(children.json()) == 1

        effective = client.get("/v1/blueprints/bp-basic-planner/permissions/effective", headers=headers)
        assert effective.status_code == 200
        assert effective.json()["effective_permissions"][0]["scopes"] == ["content.read"]

        credential = client.post("/v1/blueprints/bp-basic-planner/credentials", json={"credential_id": "dev-secret", "credential_type": "password", "display_name": "Development secret", "development_only": True}, headers=headers)
        assert credential.status_code == 201
        assert "production" in credential.json()["production_warning"].lower()

        rotated = client.post("/v1/blueprints/bp-basic-planner/credentials/dev-secret/rotate", headers=headers)
        assert rotated.status_code == 200
        assert rotated.json()["rotation_status"] == "rotated"

        disabled = client.post("/v1/blueprints/bp-basic-planner/disable", headers=headers)
        assert disabled.status_code == 200
        assert disabled.json()["affected_agent_record_ids"] == [child.json()["id"]]
        detail = client.get(f"/v1/agent-records/{child.json()['id']}", headers=headers)
        assert detail.json()["status"] == "disabled"

        principal = client.post("/v1/blueprints/bp-basic-planner/principals", json={"tenant_id": "tenant-1", "principal_id": "spn-1", "app_id": "app-1", "client_id": "client-1"}, headers=headers)
        assert principal.status_code == 201
        deleted_principal = client.delete("/v1/blueprints/bp-basic-planner/principals/spn-1", headers=headers)
        assert deleted_principal.status_code == 200
        assert deleted_principal.json()["deleted_at"] is not None

        audit = client.get("/v1/audit-events", headers=headers).json()
        assert any(event["metadata"].get("sponsors") == ["group:sponsors"] for event in audit)
        assert any(event["actor_label"] == "blueprint-principal:spn-1" for event in audit)


def test_existing_agent_records_remain_backward_compatible(tmp_path: Path):
    with _client(tmp_path) as client:
        headers = _headers(client)
        response = client.post("/v1/agent-records", json=_record(), headers=headers)
        assert response.status_code == 201
        assert response.json()["record"].get("blueprint_id") is None
