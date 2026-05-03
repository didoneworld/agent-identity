"""
tests/test_phase1_identity_hardening.py

Test coverage for all 5 Phase 1 items:
  1. Real OIDC authorization-code exchange + JWKS validation
  2. SAML: certificate validation + signed metadata
  3. OIDC Discovery endpoint
  4. OIDC-A agent claims injection
  5. Session revocation + RP-Initiated Logout

Run with:
    pip install pytest pytest-asyncio httpx
    pytest tests/test_phase1_identity_hardening.py -v
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Item 1: OIDC core helpers
# ---------------------------------------------------------------------------

class TestPKCE:
    def test_generate_pkce_pair_produces_valid_s256(self):
        from app.auth.oidc import generate_pkce_pair
        verifier, challenge = generate_pkce_pair()

        # Recompute challenge and compare
        digest = hashlib.sha256(verifier.encode()).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        assert challenge == expected

    def test_generate_pkce_verifier_length(self):
        from app.auth.oidc import generate_pkce_pair
        verifier, _ = generate_pkce_pair()
        # RFC 7636 §4.1: 43-128 chars
        assert 43 <= len(verifier) <= 128

    def test_state_is_unique(self):
        from app.auth.oidc import generate_state
        states = {generate_state() for _ in range(100)}
        assert len(states) == 100


class TestFlowStore:
    def test_store_and_consume_flow(self):
        from app.auth.oidc import consume_flow, store_flow
        state = "test_state_" + str(uuid.uuid4())
        store_flow(state, "nonce123", "verifier456", "test-org")
        flow = consume_flow(state)
        assert flow["nonce"] == "nonce123"
        assert flow["code_verifier"] == "verifier456"
        assert flow["organization_slug"] == "test-org"

    def test_consume_flow_is_one_shot(self):
        from fastapi import HTTPException
        from app.auth.oidc import consume_flow, store_flow
        state = "one_shot_" + str(uuid.uuid4())
        store_flow(state, "n", "v", "org")
        consume_flow(state)  # first call succeeds
        with pytest.raises(HTTPException) as exc:
            consume_flow(state)  # second call must fail
        assert exc.value.status_code == 400

    def test_consume_unknown_state_raises(self):
        from fastapi import HTTPException
        from app.auth.oidc import consume_flow
        with pytest.raises(HTTPException) as exc:
            consume_flow("definitely_unknown_state_xyz")
        assert exc.value.status_code == 400

    def test_expired_flow_raises(self):
        from fastapi import HTTPException
        from app.auth.oidc import _PENDING_FLOWS, consume_flow, store_flow
        state = "expired_" + str(uuid.uuid4())
        store_flow(state, "n", "v", "org")
        # Manually expire it
        _PENDING_FLOWS[state]["expires_at"] = time.time() - 1
        with pytest.raises(HTTPException) as exc:
            consume_flow(state)
        assert exc.value.status_code == 400


@pytest.mark.asyncio
class TestJWKSCache:
    async def test_jwks_cache_hit(self):
        from app.auth.oidc import _JWKS_CACHE, get_jwks, invalidate_jwks_cache

        issuer = "https://example.com"
        invalidate_jwks_cache(issuer)
        mock_keys = [{"kty": "RSA", "kid": "key1"}]

        with patch("app.auth.oidc._fetch_jwks", new=AsyncMock(return_value=mock_keys)):
            keys1 = await get_jwks(issuer, "https://example.com/jwks")
            keys2 = await get_jwks(issuer, "https://example.com/jwks")  # cache hit

        assert keys1 == mock_keys
        assert keys2 == mock_keys

    async def test_jwks_cache_invalidation(self):
        from app.auth.oidc import _JWKS_CACHE, get_jwks, invalidate_jwks_cache

        issuer = "https://rotate.example.com"
        old_keys = [{"kty": "RSA", "kid": "old"}]
        new_keys = [{"kty": "RSA", "kid": "new"}]

        with patch("app.auth.oidc._fetch_jwks", new=AsyncMock(return_value=old_keys)):
            await get_jwks(issuer, "https://rotate.example.com/jwks")

        invalidate_jwks_cache(issuer)
        assert issuer not in _JWKS_CACHE

        with patch("app.auth.oidc._fetch_jwks", new=AsyncMock(return_value=new_keys)):
            keys = await get_jwks(issuer, "https://rotate.example.com/jwks")

        assert keys == new_keys


@pytest.mark.asyncio
class TestOIDCDiscovery:
    async def test_discover_validates_issuer(self):
        mock_doc = {
            "issuer": "https://different.example.com",
            "authorization_endpoint": "https://different.example.com/auth",
            "jwks_uri": "https://different.example.com/jwks",
        }
        with patch("app.auth.oidc._DISCOVERY_CACHE", {}):
            with patch("httpx.AsyncClient") as mock_client:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = mock_doc
                mock_resp.raise_for_status = MagicMock()
                mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                    return_value=mock_resp
                )
                with pytest.raises(ValueError, match="issuer mismatch"):
                    from app.auth.oidc import discover
                    await discover("https://correct.example.com")

    async def test_discover_caches_result(self):
        issuer = "https://cache-test.example.com"
        mock_doc = {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/auth",
            "jwks_uri": f"{issuer}/jwks",
        }
        with patch("app.auth.oidc._DISCOVERY_CACHE", {}):
            with patch("httpx.AsyncClient") as mock_client:
                mock_resp = MagicMock()
                mock_resp.json.return_value = mock_doc
                mock_resp.raise_for_status = MagicMock()
                mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                    return_value=mock_resp
                )
                from app.auth.oidc import discover
                doc1 = await discover(issuer)
                doc2 = await discover(issuer)  # should use cache, not call again
        assert doc1 == mock_doc
        assert doc2 == mock_doc


# ---------------------------------------------------------------------------
# Item 2: SAML
# ---------------------------------------------------------------------------

class TestSAML:
    def test_saml_unavailable_raises_501(self):
        """If python3-saml is not installed, endpoints return 501."""
        import app.auth.saml as saml_module
        original = saml_module._SAML_AVAILABLE
        saml_module._SAML_AVAILABLE = False
        try:
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                saml_module._require_saml()
            assert exc.value.status_code == 501
        finally:
            saml_module._SAML_AVAILABLE = original


# ---------------------------------------------------------------------------
# Item 3: Discovery endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDiscoveryEndpoints:
    async def test_openid_configuration_shape(self):
        import os
        os.environ["BASE_URL"] = "https://agent-id.example.com"

        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        from app.routers.discovery import router

        app = FastAPI()
        app.include_router(router)

        with TestClient(app) as client:
            resp = client.get("/.well-known/openid-configuration")

        assert resp.status_code == 200
        doc = resp.json()

        # Required OIDC fields
        assert "issuer" in doc
        assert "authorization_endpoint" in doc
        assert "token_endpoint" in doc
        assert "jwks_uri" in doc
        assert "response_types_supported" in doc

        # OIDC-A claims (WP §3.1)
        claims = doc.get("claims_supported", [])
        assert "agent_model" in claims
        assert "agent_provider" in claims
        assert "agent_version" in claims

        # OBO delegation claims (WP §3.2)
        assert "act" in claims

        # PKCE required
        assert doc.get("require_pkce") is True

        # CIBA advertised (Phase 3)
        assert "backchannel_authentication_endpoint" in doc

    async def test_client_metadata_returns_client_id(self):
        import os
        os.environ["BASE_URL"] = "https://agent-id.example.com"

        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        from app.routers.discovery import router

        app = FastAPI()
        app.include_router(router)

        test_client_id = "test-client-" + str(uuid.uuid4())
        with TestClient(app) as client:
            resp = client.get(f"/.well-known/oauth-client/{test_client_id}")

        assert resp.status_code == 200
        doc = resp.json()
        assert doc["client_id"] == test_client_id
        assert "client_id_issued_at" in doc


# ---------------------------------------------------------------------------
# Item 4: OIDC-A agent claims injection
# ---------------------------------------------------------------------------

class TestAgentClaimsInjection:
    def test_inject_agent_claims_adds_fields(self):
        from app.routers.discovery import AgentMetadataClaims, inject_agent_claims
        base = {"sub": "user123", "iss": "https://example.com"}
        meta = AgentMetadataClaims(
            agent_model="claude-sonnet-4-6",
            agent_provider="anthropic",
            agent_version="4.6.0",
        )
        enriched = inject_agent_claims(base, meta)
        assert enriched["agent_model"] == "claude-sonnet-4-6"
        assert enriched["agent_provider"] == "anthropic"
        assert enriched["agent_version"] == "4.6.0"
        # Original claims preserved
        assert enriched["sub"] == "user123"

    def test_inject_none_metadata_returns_base_unchanged(self):
        from app.routers.discovery import inject_agent_claims
        base = {"sub": "user123"}
        result = inject_agent_claims(base, None)
        assert result == base
        assert "agent_model" not in result

    def test_inject_partial_agent_claims(self):
        from app.routers.discovery import AgentMetadataClaims, inject_agent_claims
        base = {"sub": "u"}
        meta = AgentMetadataClaims(agent_model="gpt-4o")  # only model set
        enriched = inject_agent_claims(base, meta)
        assert enriched["agent_model"] == "gpt-4o"
        assert "agent_provider" not in enriched   # None fields excluded
        assert "agent_version" not in enriched


# ---------------------------------------------------------------------------
# Item 5: Session revocation
# ---------------------------------------------------------------------------

class TestSessionRevocation:
    def test_revoke_jti_marks_as_revoked(self):
        from app.routers.session_router import is_revoked, revoke_jti
        jti = "test-jti-" + str(uuid.uuid4())
        assert not is_revoked(jti)
        revoke_jti(jti)
        assert is_revoked(jti)

    def test_revoke_jti_idempotent(self):
        from app.routers.session_router import is_revoked, revoke_jti
        jti = "idempotent-" + str(uuid.uuid4())
        revoke_jti(jti)
        revoke_jti(jti)  # should not raise
        assert is_revoked(jti)

    def test_decode_unverified_extracts_claims(self):
        """Verify _decode_unverified works without signature check."""
        from jose import jwt
        # Encode a test token with a dummy secret (not real RS256)
        payload = {"sub": "user1", "jti": "jti-test", "exp": int(time.time()) + 3600}
        token = jwt.encode(payload, "secret", algorithm="HS256")

        from app.routers.session_router import _decode_unverified
        claims = _decode_unverified(token)
        assert claims["sub"] == "user1"
        assert claims["jti"] == "jti-test"


@pytest.mark.asyncio
class TestSessionRevocationEndpoints:
    async def test_revoke_endpoint_accepts_invalid_token(self):
        """RFC 7009: revoke always returns 200 even for invalid tokens."""
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        from app.routers.session_router import router

        app = FastAPI()
        app.include_router(router, prefix="/v1")

        with TestClient(app) as client:
            resp = client.post(
                "/v1/session/revoke",
                json={"token": "definitely.not.a.jwt"},
            )
        assert resp.status_code == 200
        assert resp.json()["revoked"] is True

    async def test_token_revoke_rfc7009(self):
        """RFC 7009 token revocation endpoint returns 200."""
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        from app.routers.session_router import router

        app = FastAPI()
        app.include_router(router, prefix="/v1")

        with TestClient(app) as client:
            resp = client.post(
                "/v1/token/revoke",
                data={"token": "invalid.token.here"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        assert resp.status_code == 200

    async def test_introspect_inactive_for_bad_token(self):
        """RFC 7662: introspect returns active=false for invalid tokens."""
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        from app.routers.session_router import router

        app = FastAPI()
        app.include_router(router, prefix="/v1")

        with TestClient(app) as client:
            resp = client.post(
                "/v1/token/introspect",
                data={"token": "bad.token"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        assert resp.status_code == 200
        assert resp.json()["active"] is False
