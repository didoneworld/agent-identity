"""
app/routers/oidc_router.py

OIDC SSO routes replacing the old stub callback-based session issuance.

Routes:
  GET  /v1/sso/oidc/start/{organization_slug}
       — build authorization URL with PKCE + nonce, redirect to IdP

  GET  /v1/sso/oidc/callback/{organization_slug}
       — receive authorization code, exchange for tokens,
         validate ID token against JWKS, issue signed bearer session

Wire in app/main.py:
    from app.routers.oidc_router import router as oidc_router
    app.include_router(oidc_router, prefix="/v1/sso/oidc", tags=["SSO – OIDC"])
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse

from app.auth.oidc import (
    OIDCProviderConfig,
    build_authorization_url,
    consume_flow,
    exchange_code_for_tokens,
    extract_user_info,
    fetch_userinfo,
    generate_nonce,
    generate_pkce_pair,
    generate_state,
    store_flow,
    validate_id_token,
)
from app.routers.discovery import AgentMetadataClaims, inject_agent_claims

router = APIRouter()

# ---------------------------------------------------------------------------
# Helpers — replace with real DB lookups from your existing models
# ---------------------------------------------------------------------------

async def _load_oidc_config(organization_slug: str) -> OIDCProviderConfig:
    """
    Load OIDC provider config for the org from the DB.
    Raises 404 if the org or its OIDC provider is not configured.
    Replace the stub below with your real DB query.
    """
    # TODO: replace with:
    #   from app.db import get_db
    #   provider = await db.fetch_one(
    #       "SELECT * FROM identity_providers WHERE org_slug = :slug AND type = 'oidc'",
    #       {"slug": organization_slug}
    #   )
    #   if not provider:
    #       raise HTTPException(404, "OIDC provider not configured for this organization")
    #   return OIDCProviderConfig(**provider)

    # --- stub ---
    base = os.environ.get("BASE_URL", "https://agent-id.openautonomyx.com")
    return OIDCProviderConfig(
        organization_slug=organization_slug,
        issuer=os.environ.get("OIDC_ISSUER", ""),
        client_id=os.environ.get("OIDC_CLIENT_ID", ""),
        client_secret=os.environ.get("OIDC_CLIENT_SECRET", ""),
        redirect_uri=f"{base}/v1/sso/oidc/callback/{organization_slug}",
    )


def _issue_session_token(user_sub: str, org_slug: str, agent_claims: dict) -> str:
    """
    Issue a signed bearer session JWT.
    Replace with your real JWT signing using the server's RSA private key.
    """
    import jose.jwt as _jwt

    private_key = os.environ.get("SIGNING_KEY_PRIVATE_PEM", "")
    if not private_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SIGNING_KEY_PRIVATE_PEM not configured",
        )

    now = int(time.time())
    payload = {
        "iss": os.environ.get("BASE_URL", ""),
        "sub": user_sub,
        "aud": org_slug,
        "iat": now,
        "exp": now + int(os.environ.get("SESSION_TTL_SECONDS", 3600)),
        "jti": str(uuid.uuid4()),
        **agent_claims,
    }

    return _jwt.encode(payload, private_key, algorithm="RS256")


async def _persist_session(
    session_token: str,
    user_sub: str,
    org_slug: str,
    name_id: str | None,
    session_index: str | None,
) -> None:
    """
    Persist session to DB for revocation support.
    Replace with real DB write.
    """
    # TODO: insert into sessions table
    pass


# ---------------------------------------------------------------------------
# GET /v1/sso/oidc/start/{organization_slug}
# ---------------------------------------------------------------------------

@router.get(
    "/start/{organization_slug}",
    summary="Initiate OIDC authorization code flow with PKCE",
    response_class=RedirectResponse,
    status_code=302,
)
async def oidc_start(organization_slug: str) -> RedirectResponse:
    """
    1. Look up OIDC provider config for the org
    2. Generate state, nonce, PKCE pair
    3. Store flow params server-side (keyed on state)
    4. Redirect user to IdP authorization endpoint
    """
    config = await _load_oidc_config(organization_slug)

    if not config.issuer or not config.client_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"OIDC provider not fully configured for org '{organization_slug}'",
        )

    state = generate_state()
    nonce = generate_nonce()
    code_verifier, code_challenge = generate_pkce_pair()

    store_flow(state, nonce, code_verifier, organization_slug)

    authorization_url = await build_authorization_url(
        config=config,
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
    )

    return RedirectResponse(url=authorization_url, status_code=302)


# ---------------------------------------------------------------------------
# GET /v1/sso/oidc/callback/{organization_slug}
# ---------------------------------------------------------------------------

@router.get(
    "/callback/{organization_slug}",
    summary="OIDC callback — exchange code, validate ID token, issue session",
)
async def oidc_callback(
    organization_slug: str,
    code: str = Query(..., description="Authorization code from IdP"),
    state: str = Query(..., description="State parameter for CSRF protection"),
    error: str | None = Query(None),
    error_description: str | None = Query(None),
) -> JSONResponse:
    """
    1. Validate state (CSRF check), retrieve stored nonce + code_verifier
    2. Exchange authorization code for tokens at IdP token endpoint
    3. Validate ID token: signature (JWKS), iss, aud, exp, nonce
    4. Fetch UserInfo endpoint for additional claims
    5. Inject OIDC-A agent metadata claims
    6. Issue signed bearer session JWT
    7. Persist session for revocation support
    """
    # IdP-returned error
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"IdP returned error: {error} — {error_description or ''}",
        )

    # Validate state + retrieve stored flow (one-shot consumption)
    flow = consume_flow(state)
    if flow["organization_slug"] != organization_slug:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="State parameter organization mismatch",
        )

    code_verifier = flow["code_verifier"]
    nonce = flow["nonce"]

    config = await _load_oidc_config(organization_slug)

    # Exchange code → tokens
    token_set = await exchange_code_for_tokens(
        config=config,
        code=code,
        code_verifier=code_verifier,
    )

    # Validate ID token against IdP's JWKS
    id_token_claims = await validate_id_token(
        config=config,
        id_token=token_set.id_token,
        nonce=nonce,
    )

    # Fetch UserInfo for additional claims
    userinfo_raw = await fetch_userinfo(config, token_set.access_token)

    # Merge and extract structured user info
    user_info = extract_user_info(id_token_claims, userinfo_raw)

    # Inject OIDC-A agent metadata claims (from record if agent; empty for human users)
    agent_claims = inject_agent_claims(
        base_payload={},
        agent_metadata=AgentMetadataClaims(
            agent_model=user_info.agent_model,
            agent_provider=user_info.agent_provider,
            agent_version=user_info.agent_version,
        ) if any([user_info.agent_model, user_info.agent_provider]) else None,
    )

    # Issue session
    session_token = _issue_session_token(
        user_sub=user_info.sub,
        org_slug=organization_slug,
        agent_claims=agent_claims,
    )

    # Persist for revocation
    await _persist_session(
        session_token=session_token,
        user_sub=user_info.sub,
        org_slug=organization_slug,
        name_id=None,
        session_index=None,
    )

    # Return token (in prod: set httpOnly cookie or redirect to app with token)
    return JSONResponse(
        content={
            "access_token": session_token,
            "token_type": "Bearer",
            "expires_in": int(os.environ.get("SESSION_TTL_SECONDS", 3600)),
            "sub": user_info.sub,
            "email": user_info.email,
        },
        headers={"Cache-Control": "no-store"},
    )
