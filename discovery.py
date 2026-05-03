"""
app/routers/discovery.py

OpenID Connect Discovery endpoint (/.well-known/openid-configuration)
and OIDC-A agent metadata claims injection.

Implements:
  - RFC 8414 / OIDC Core §4 — Authorization Server Metadata
  - OIDC-A §3.1 — agent_model, agent_provider, agent_version claims
    in issued JWTs (WP §3.1, arxiv:2509.25974)
  - Client ID Metadata Document (draft-parecki) at
    /.well-known/oauth-client/{client_id}

Wire in app/main.py:
    from app.routers.discovery import router as discovery_router
    app.include_router(discovery_router)
"""

from __future__ import annotations

import os
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter(tags=["Discovery"])

# ---------------------------------------------------------------------------
# Config (read from env — set in .env / Coolify secrets)
# ---------------------------------------------------------------------------

def _base_url() -> str:
    return os.environ.get("BASE_URL", "https://agent-id.openautonomyx.com").rstrip("/")


# ---------------------------------------------------------------------------
# /.well-known/openid-configuration
# RFC 8414 §2 + OIDC Core §4
# ---------------------------------------------------------------------------

@router.get("/.well-known/openid-configuration", include_in_schema=False)
@router.get("/.well-known/openid-configuration/", include_in_schema=False)
async def openid_configuration() -> JSONResponse:
    """
    OpenID Provider Configuration endpoint.
    Required by any OIDC relying party before it can trust tokens from this server.
    Exposes the OIDC-A claim set (agent_model, agent_provider, agent_version)
    in claims_supported.
    """
    base = _base_url()

    doc = {
        # ---- Core OIDC metadata ----
        "issuer": base,
        "authorization_endpoint": f"{base}/v1/sso/oidc/authorize",
        "token_endpoint": f"{base}/v1/token",
        "userinfo_endpoint": f"{base}/v1/userinfo",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "registration_endpoint": f"{base}/v1/register",
        "end_session_endpoint": f"{base}/v1/session/revoke",
        # ---- Supported features ----
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:token-exchange",  # RFC 8693 (Phase 3)
            "urn:openid:params:grant-type:ciba",                 # CIBA (Phase 3)
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
            "private_key_jwt",
        ],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": [
            "openid", "profile", "email", "offline_access",
            # OIDC-A scope
            "agent_identity",
        ],
        # ---- Claims ----
        # Standard OIDC + OIDC-A agent metadata (WP §3.1)
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "nonce",
            "email", "email_verified", "name", "picture",
            # OIDC-A claims
            "agent_model",
            "agent_provider",
            "agent_version",
            # OBO delegation claims (RFC 8693 / WP §3.2)
            "act",
            "may_act",
            "delegation_chain",
        ],
        "claims_parameter_supported": True,
        # ---- PKCE ----
        "require_pkce": True,
        # ---- CIBA (Phase 3 — advertised now, endpoint added in Phase 3) ----
        "backchannel_authentication_endpoint": f"{base}/v1/bc-authorize",
        "backchannel_token_delivery_modes_supported": ["poll", "ping", "push"],
        "backchannel_authentication_request_signing_alg_values_supported": ["RS256"],
        # ---- Agent DID extension ----
        "did_methods_supported": ["did:web", "did:key"],
        "agent_identity_schema": "https://didoneworld.github.io/agent-did/schemas/agent-id-record.schema.json",
    }

    return JSONResponse(
        content=doc,
        headers={
            "Cache-Control": "public, max-age=3600",
            "Content-Type": "application/json; charset=utf-8",
        },
    )


# ---------------------------------------------------------------------------
# /.well-known/jwks.json
# Serves the public key(s) used to sign JWTs issued by this server.
# The private key is loaded from SECRET_SIGNING_KEY env var (PEM, RS256).
# ---------------------------------------------------------------------------

@router.get("/.well-known/jwks.json", include_in_schema=False)
async def jwks() -> JSONResponse:
    """
    JSON Web Key Set endpoint.
    Relying parties use this to verify the signature on JWTs we issue.
    Key is loaded from SIGNING_KEY_PUBLIC_PEM env var at runtime.
    """
    # In production load from HSM / Infisical / Vault. Here we read from env.
    public_pem = os.environ.get("SIGNING_KEY_PUBLIC_PEM", "")
    if not public_pem:
        # Return empty keyset — server needs SIGNING_KEY_PUBLIC_PEM configured
        return JSONResponse(
            content={"keys": []},
            status_code=200,
            headers={"Cache-Control": "public, max-age=3600"},
        )

    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        import base64, struct

        key_obj = load_pem_public_key(public_pem.encode())
        if isinstance(key_obj, RSAPublicKey):
            pub_numbers = key_obj.public_key().public_numbers() if hasattr(key_obj, 'public_key') else key_obj.public_numbers()

            def _b64(n: int) -> str:
                length = (n.bit_length() + 7) // 8
                return base64.urlsafe_b64encode(
                    n.to_bytes(length, "big")
                ).rstrip(b"=").decode()

            jwk = {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": os.environ.get("SIGNING_KEY_ID", "agent-did-key-1"),
                "n": _b64(pub_numbers.n),
                "e": _b64(pub_numbers.e),
            }
        else:
            return JSONResponse(content={"keys": []})
    except Exception as exc:
        # Log and return empty — don't expose key errors
        import logging
        logging.getLogger(__name__).error("JWKS build error: %s", exc)
        return JSONResponse(content={"keys": []})

    return JSONResponse(
        content={"keys": [jwk]},
        headers={"Cache-Control": "public, max-age=3600"},
    )


# ---------------------------------------------------------------------------
# /.well-known/oauth-client/{client_id}
# OAuth Client ID Metadata Document (draft-parecki)
# Fixes the anonymous-client flaw in Dynamic Client Registration (WP §2.5)
# ---------------------------------------------------------------------------

@router.get(
    "/.well-known/oauth-client/{client_id}",
    summary="OAuth Client ID Metadata Document (draft-parecki)",
    tags=["Discovery"],
)
async def client_metadata(client_id: str, request: Request) -> JSONResponse:
    """
    Serves a verifiable identity document for the given OAuth client_id.
    MCP servers fetch this to validate a client's identity without
    pre-registration, closing the anonymous-client gap.

    In production this is backed by the agent_records DB table.
    Here we return the metadata fields required by the draft spec.
    """
    # TODO: look up client_id in agent_records DB and build from record
    # For now return a well-formed stub that the caller can validate shape against
    base = _base_url()
    doc = {
        # draft-parecki §3
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "client_name": f"Agent {client_id[:8]}",
        "client_uri": f"{base}/v1/agent-records/by-did/{client_id}",
        "logo_uri": None,
        "contacts": [os.environ.get("ADMIN_EMAIL", "admin@openautonomyx.com")],
        "tos_uri": f"{base}/terms",
        "policy_uri": f"{base}/privacy",
        "redirect_uris": [],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
        # OIDC-A extension
        "agent_metadata_uri": f"{base}/v1/agent-records/by-did/{client_id}",
    }
    return JSONResponse(
        content=doc,
        headers={"Cache-Control": "no-store"},
    )


# ---------------------------------------------------------------------------
# OIDC-A claim injection helper
# Called by the token issuance code to enrich JWTs with agent metadata
# ---------------------------------------------------------------------------

class AgentMetadataClaims(BaseModel):
    """
    OIDC-A agent metadata claims (WP §3.1).
    Injected into every JWT issued by this server when the agent record
    has these fields populated.
    """
    agent_model: str | None = None      # e.g. "claude-sonnet-4-6"
    agent_provider: str | None = None   # e.g. "anthropic"
    agent_version: str | None = None    # e.g. "4.6.0"
    agent_did: str | None = None        # e.g. "did:web:agent-id.openautonomyx.com:agents:abc"
    agent_record_id: str | None = None  # internal UUID


def inject_agent_claims(
    base_payload: dict[str, Any],
    agent_metadata: AgentMetadataClaims | None,
) -> dict[str, Any]:
    """
    Add OIDC-A agent claims to a JWT payload dict.
    Only adds non-None fields — keeps tokens lean.
    """
    if agent_metadata is None:
        return base_payload

    enriched = {**base_payload}
    for field, value in agent_metadata.model_dump(exclude_none=True).items():
        enriched[field] = value
    return enriched
