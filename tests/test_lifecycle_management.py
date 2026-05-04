from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app
from tests.test_saas_api import _record


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(database_url=f"sqlite:///{tmp_path / 'lifecycle.db'}"))


def _headers(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/v1/bootstrap",
        json={"organization_name": "Did One World", "organization_slug": "didoneworld", "api_key_label": "admin"},
    )
    return {"X-API-Key": response.json()["api_key"]}


def _activation_ready_record() -> dict:
    record = _record()
    record["agent"]["environment"] = "production"
    record["extensions"].update(
        {
            "terms_url": "https://agents.didone.world/terms",
            "privacy_url": "https://agents.didone.world/privacy",
            "support_url": "https://agents.didone.world/support",
        }
    )
    record["extensions"]["lifecycle"] = {
        "state": "approved",
        "verification_methods": ["did:web:agents.didone.world:catalog:planner#key-1"],
        "owners": [{"id": "owner@example.com", "status": "active"}],
        "sponsors": [{"id": "sponsor@example.com", "status": "active"}],
        "credentials": [
            {
                "credential_id": "cred-1",
                "credential_type": "JsonWebKey2020",
                "issuer": "did:web:issuer.example",
                "subject": record["agent"]["did"],
                "status": "active",
                "expires_at": "2027-01-01T00:00:00Z",
            }
        ],
        "permissions": [
            {
                "permission_id": "perm-1",
                "source": "direct",
                "resource_app_id": "resource-app",
                "scopes": ["read"],
                "status": "granted",
                "risk_level": "low",
            }
        ],
        "risk": {"score": 10},
        "audit_logging_enabled": True,
    }
    return record


def test_lifecycle_transition_audits_and_rejects_invalid_transition(tmp_path: Path):
    with _client(tmp_path) as client:
        headers = _headers(client)
        created = client.post("/v1/agent-records", json=_record(), headers=headers).json()

        suspended = client.post(
            f"/v1/agent-records/{created['id']}/suspend",
            json={"reason": "inactive", "requested_by": "ops@example.com"},
            headers=headers,
        )
        assert suspended.status_code == 200
        assert suspended.json()["previous_state"] == "active"
        assert suspended.json()["new_state"] == "suspended"

        invalid = client.post(f"/v1/agent-records/{created['id']}/approve", json={"reason": "bad"}, headers=headers)
        assert invalid.status_code == 409
        assert "invalid agent lifecycle transition" in invalid.json()["detail"]

        audit = client.get(f"/v1/agent-records/{created['id']}/lifecycle-events", headers=headers)
        assert audit.status_code == 200
        assert audit.json()[0]["previous_state"] == "active"
        assert audit.json()[0]["new_state"] == "suspended"
        assert audit.json()[0]["evidence_hash"]


def test_activation_validation_gates_block_until_record_is_ready(tmp_path: Path):
    with _client(tmp_path) as client:
        headers = _headers(client)
        created = client.post("/v1/agent-records", json=_record(), headers=headers).json()
        blocked = client.post(f"/v1/agent-records/{created['id']}/activate", json={"reason": "go live"}, headers=headers)
        assert blocked.status_code == 422
        report = blocked.json()["detail"]["validation_report"]
        assert report["passed"] is False
        assert "active_credentials_missing" in report["blocking_issues"]

        ready = client.post("/v1/agent-records", json=_activation_ready_record(), headers=headers).json()
        activated = client.post(
            f"/v1/agent-records/{ready['id']}/activate",
            json={"reason": "go live", "approved_by": "approver@example.com"},
            headers=headers,
        )
        assert activated.status_code == 200
        assert activated.json()["validation_report"]["passed"] is True


def test_deprovisioning_report_and_blueprint_cascade(tmp_path: Path):
    with _client(tmp_path) as client:
        headers = _headers(client)
        record = _record()
        record["extensions"]["lifecycle"] = {"blueprint_id": "blueprint-1"}
        created = client.post("/v1/agent-records", json=record, headers=headers).json()

        dry_run = client.post(
            f"/v1/agent-records/{created['id']}/deprovision",
            json={"reason": "offboard", "dry_run": True, "idempotency_key": "idem-1"},
            headers=headers,
        )
        assert dry_run.status_code == 200
        assert dry_run.json()["deprovisioning_report"]["status"] == "dry_run"

        activated_blueprint = client.post("/v1/blueprints/blueprint-1/activate", json={"reason": "publish"}, headers=headers)
        assert activated_blueprint.status_code == 200
        disabled = client.post("/v1/blueprints/blueprint-1/disable", json={"reason": "maintenance"}, headers=headers)
        assert disabled.status_code == 200
        refreshed = client.get(f"/v1/agent-records/{created['id']}", headers=headers).json()
        assert refreshed["lifecycle_state"] == "suspended"
