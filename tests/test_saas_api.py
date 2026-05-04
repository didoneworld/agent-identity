import copy
from base64 import b64encode
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


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _saml_assertion(subject: str, email: str, display_name: str) -> str:
    xml = f"""
    <saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
      <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml2:Subject>
          <saml2:NameID>{subject}</saml2:NameID>
        </saml2:Subject>
        <saml2:AttributeStatement>
          <saml2:Attribute Name="email">
            <saml2:AttributeValue>{email}</saml2:AttributeValue>
          </saml2:Attribute>
          <saml2:Attribute Name="displayName">
            <saml2:AttributeValue>{display_name}</saml2:AttributeValue>
          </saml2:Attribute>
        </saml2:AttributeStatement>
      </saml2:Assertion>
    </saml2p:Response>
    """.strip()
    return b64encode(xml.encode("utf-8")).decode("utf-8")


def test_health_endpoint(tmp_path: Path):
    with _client(tmp_path) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["service"] == "agent-identity-saas"
        assert response.json()["schema_revision"] == "20260504_01"


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


def test_api_key_roles_and_lifecycle(tmp_path: Path):
    with _client(tmp_path) as client:
        bootstrap = client.post(
            "/v1/bootstrap",
            json={
                "organization_name": "Didone World",
                "organization_slug": "didoneworld",
                "api_key_label": "ops-admin",
            },
        )
        admin_headers = {"X-API-Key": bootstrap.json()["api_key"]}

        writer_key = client.post(
            "/v1/api-keys",
            json={"label": "writer-bot", "role": "writer"},
            headers=admin_headers,
        )
        assert writer_key.status_code == 201
        writer_headers = {"X-API-Key": writer_key.json()["api_key"]}

        reader_key = client.post(
            "/v1/api-keys",
            json={"label": "reader-bot", "role": "reader"},
            headers=admin_headers,
        )
        assert reader_key.status_code == 201
        reader_headers = {"X-API-Key": reader_key.json()["api_key"]}

        writer_list_keys = client.get("/v1/api-keys", headers=writer_headers)
        assert writer_list_keys.status_code == 403

        reader_write = client.post("/v1/agent-records", json=_record(), headers=reader_headers)
        assert reader_write.status_code == 403

        writer_write = client.post("/v1/agent-records", json=_record(), headers=writer_headers)
        assert writer_write.status_code == 201
        record_id = writer_write.json()["id"]

        reader_read = client.get("/v1/agent-records", headers=reader_headers)
        assert reader_read.status_code == 200
        assert len(reader_read.json()) == 1

        writer_deprovision = client.post(
            f"/v1/agent-records/{record_id}/deprovision",
            json={"reason": "not allowed"},
            headers=writer_headers,
        )
        assert writer_deprovision.status_code == 403

        key_listing = client.get("/v1/api-keys", headers=admin_headers)
        assert key_listing.status_code == 200
        listed_roles = {item["role"] for item in key_listing.json()}
        assert {"admin", "writer", "reader"} <= listed_roles

        revoke = client.post(
            f"/v1/api-keys/{writer_key.json()['id']}/revoke",
            headers=admin_headers,
        )
        assert revoke.status_code == 200
        assert revoke.json()["is_active"] is False

        revoked_use = client.get("/v1/agent-records", headers=writer_headers)
        assert revoked_use.status_code == 401


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


def test_rate_limit_is_enforced(tmp_path: Path):
    db_path = tmp_path / "rate-limit.db"
    with TestClient(
        create_app(
            database_url=f"sqlite:///{db_path}",
            rate_limit_max_requests=2,
            rate_limit_window_seconds=60,
        )
    ) as client:
        first = client.get("/health")
        second = client.get("/health")
        third = client.get("/health")

        assert first.status_code == 200
        assert second.status_code == 200
        assert third.status_code == 429
        assert third.json()["detail"] == "rate limit exceeded"
        assert "X-Request-ID" in third.headers


def test_oidc_sso_and_fga_flow(tmp_path: Path):
    with _client(tmp_path) as client:
        bootstrap = client.post(
            "/v1/bootstrap",
            json={
                "organization_name": "Didone World",
                "organization_slug": "didoneworld",
                "api_key_label": "ops-admin",
            },
        )
        admin_headers = {"X-API-Key": bootstrap.json()["api_key"]}

        provider = client.post(
            "/v1/identity-providers/oidc",
            json={
                "display_name": "Okta Workforce",
                "issuer": "https://id.didone.world",
                "login_url": "https://id.didone.world/oauth2/v1/authorize",
                "callback_url": "https://agent.didone.world/callback",
                "client_id": "agent-identity",
                "client_secret": "secret",
                "metadata": {"userinfo_endpoint": "https://id.didone.world/userinfo"},
                "default_role": "reader",
            },
            headers=admin_headers,
        )
        assert provider.status_code == 201

        start = client.get("/v1/sso/oidc/start/didoneworld")
        assert start.status_code == 200
        assert "response_type=code" in start.json()["authorization_url"]

        record = client.post("/v1/agent-records", json=_record(), headers=admin_headers).json()

        callback = client.post(
            "/v1/sso/oidc/callback/didoneworld",
            json={
                "subject": "user-123",
                "email": "analyst@didone.world",
                "display_name": "Analyst",
                "claims": {"groups": ["security"]},
            },
        )
        assert callback.status_code == 200
        token = callback.json()["access_token"]
        bearer_headers = _bearer(token)

        list_records = client.get("/v1/agent-records", headers=bearer_headers)
        assert list_records.status_code == 200

        detail_before_tuple = client.get(f"/v1/agent-records/{record['id']}", headers=bearer_headers)
        assert detail_before_tuple.status_code == 403

        fga_tuple = client.post(
            "/v1/fga/tuples",
            json={
                "subject": "user-123",
                "relation": "viewer",
                "object_type": "agent_record",
                "object_id": record["id"],
            },
            headers=admin_headers,
        )
        assert fga_tuple.status_code == 201

        detail_after_tuple = client.get(f"/v1/agent-records/{record['id']}", headers=bearer_headers)
        assert detail_after_tuple.status_code == 200

        check = client.post(
            "/v1/fga/check",
            json={
                "subject": "user-123",
                "relation": "viewer",
                "object_type": "agent_record",
                "object_id": record["id"],
            },
            headers=bearer_headers,
        )
        assert check.status_code == 200
        assert check.json()["allowed"] is True


def test_saml_session_can_deprovision_with_owner_tuple(tmp_path: Path):
    with _client(tmp_path) as client:
        bootstrap = client.post(
            "/v1/bootstrap",
            json={
                "organization_name": "Didone World",
                "organization_slug": "didoneworld",
                "api_key_label": "ops-admin",
            },
        )
        admin_headers = {"X-API-Key": bootstrap.json()["api_key"]}
        client.post(
            "/v1/identity-providers/saml",
            json={
                "display_name": "Entra SAML",
                "entity_id": "urn:didoneworld:agent-identity",
                "login_url": "https://login.didone.world/saml",
                "callback_url": "https://agent.didone.world/saml/acs",
                "metadata": {"certificate_thumbprint": "abc123"},
                "default_role": "reader",
            },
            headers=admin_headers,
        )

        record = client.post("/v1/agent-records", json=_record(), headers=admin_headers).json()
        saml_login = client.post(
            "/v1/sso/saml/acs/didoneworld",
            json={
                "saml_response": _saml_assertion("sam-user-1", "saml@didone.world", "Saml User"),
            },
        )
        assert saml_login.status_code == 200
        bearer_headers = _bearer(saml_login.json()["access_token"])

        denied = client.post(
            f"/v1/agent-records/{record['id']}/deprovision",
            json={"reason": "blocked"},
            headers=bearer_headers,
        )
        assert denied.status_code == 403

        tuple_response = client.post(
            "/v1/fga/tuples",
            json={
                "subject": "sam-user-1",
                "relation": "owner",
                "object_type": "agent_record",
                "object_id": record["id"],
            },
            headers=admin_headers,
        )
        assert tuple_response.status_code == 201

        allowed = client.post(
            f"/v1/agent-records/{record['id']}/deprovision",
            json={"reason": "offboarded"},
            headers=bearer_headers,
        )
        assert allowed.status_code == 200
        assert allowed.json()["status"] == "disabled"
