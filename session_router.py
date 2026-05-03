"""
app/routers/session_router.py

Session lifecycle management: revocation + RP-Initiated Logout.

Implements:
  - OIDC RP-Initiated Logout 1.0   (end_session_endpoint)
  - Token introspection            (RFC 7662) — so resource servers can check validity
  - Token revocation               (RFC 7009) — client-initiated revoke
  - Shared Signals Framework (SSF) event emission on revocation
    (pre-wires the de-provisioning broadcast needed in Phase 2)

Wire in app/main.py:
    from app.routers.session_router import router as session_router
    app.include_router(session_router, prefix="/v1", tags=["Sessions"])

Endpoints added:
  POST /v1/session/revoke        — revoke a specific session JWT
  POST /v1/token/revoke          — RFC 7009 token revocation
  POST /v1/token/introspect      — RFC 7662 token introspection
  GET  /v1/session/logout        — RP-Initiated Logout redirect
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

router = APIRouter()


# ---------------------------------------------------------------------------
# In-memory revocation store (replace with Redis in prod)
# Stores jti → revoked_at for issued tokens.
# ---------------------------------------------------------------------------

_REVOKED_JTIS: set[str] = set()


def revoke_jti(jti: str) -> None:
    _REVOKED_JTIS.add(jti)


def is_revoked(jti: str) -> bool:
    return jti in _REVOKED_JTIS


# ---------------------------------------------------------------------------
# Token decode helper (no sig verify — just extract claims for routing)
# Full sig verify is in app/auth/oidc.py
# ---------------------------------------------------------------------------

def _decode_unverified(token: str) -> dict[str, Any]:
    """Decode JWT header+payload without verifying signature."""
    from jose import jwt
    return jwt.get_unverified_claims(token)


def _verify_token(token: str) -> dict[str, Any]:
    """
    Verify signature + expiry on a server-issued session token.
    Uses the server's public key from SIGNING_KEY_PUBLIC_PEM.
    """
    from jose import jwt as _jwt, JWTError
    public_key = os.environ.get("SIGNING_KEY_PUBLIC_PEM", "")
    if not public_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SIGNING_KEY_PUBLIC_PEM not configured",
        )
    try:
        claims = _jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=os.environ.get("BASE_URL", ""),
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {exc}",
        )
    jti = claims.get("jti", "")
    if jti and is_revoked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
        )
    return claims


# ---------------------------------------------------------------------------
# Shared Signals Framework (SSF) emitter stub
# Phase 2 wires this to the full CAAS SSF broadcast
# ---------------------------------------------------------------------------

async def _emit_ssf_session_revoked(
    subject_id: str,
    session_id: str,
    reason: str,
) -> None:
    """
    Emit a CAEP SessionRevoked event to registered SSF receivers.
    Phase 2 replaces this stub with real HTTP delivery.
    """
    import logging
    logging.getLogger(__name__).info(
        "SSF SessionRevoked: subject=%s session=%s reason=%s",
        subject_id, session_id, reason,
    )
    # TODO Phase 2: POST to each registered SSF receiver:
    # {
    #   "iss": BASE_URL,
    #   "jti": str(uuid.uuid4()),
    #   "iat": int(time.time()),
    #   "aud": [receiver_url],
    #   "events": {
    #     "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
    #       "subject": {"format": "iss_sub", "iss": BASE_URL, "sub": subject_id},
    #       "initiating_entity": "policy",
    #       "reason_admin": {"en": reason},
    #       "event_timestamp": int(time.time() * 1000),
    #     }
    #   }
    # }


# ---------------------------------------------------------------------------
# POST /v1/session/revoke — revoke by session token
# ---------------------------------------------------------------------------

class RevokeRequest(BaseModel):
    token: str
    reason: str | None = "user_initiated"


@router.post(
    "/session/revoke",
    summary="Revoke a session token (jti-based)",
    status_code=200,
)
async def revoke_session(body: RevokeRequest) -> JSONResponse:
    """
    Validate the token, then add its jti to the revocation set.
    Emits an SSF CAEP SessionRevoked event for downstream propagation.
    """
    try:
        claims = _verify_token(body.token)
    except HTTPException:
        # Even if invalid/expired, accept the revoke call — idempotent
        return JSONResponse(content={"revoked": True})

    jti = claims.get("jti", "")
    sub = claims.get("sub", "")

    if jti:
        revoke_jti(jti)

    # Emit SSF event
    await _emit_ssf_session_revoked(
        subject_id=sub,
        session_id=jti,
        reason=body.reason or "user_initiated",
    )

    # TODO: delete from sessions DB table by jti

    return JSONResponse(content={"revoked": True, "sub": sub})


# ---------------------------------------------------------------------------
# POST /v1/token/revoke — RFC 7009 token revocation endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/token/revoke",
    summary="RFC 7009 token revocation",
    status_code=200,
)
async def token_revoke(
    token: str = Form(...),
    token_type_hint: str = Form(default="access_token"),
) -> JSONResponse:
    """
    RFC 7009 §2.1 token revocation.
    Accepts token + optional hint. Always returns 200 per spec
    (even for unknown tokens — don't leak information).
    """
    try:
        claims = _decode_unverified(token)
        jti = claims.get("jti", "")
        sub = claims.get("sub", "")
        if jti:
            revoke_jti(jti)
        if sub:
            await _emit_ssf_session_revoked(sub, jti, "client_revoked")
    except Exception:
        pass  # RFC 7009: return 200 regardless

    return JSONResponse(content={})


# ---------------------------------------------------------------------------
# POST /v1/token/introspect — RFC 7662 token introspection
# ---------------------------------------------------------------------------

@router.post(
    "/token/introspect",
    summary="RFC 7662 token introspection",
)
async def token_introspect(
    token: str = Form(...),
    token_type_hint: str = Form(default="access_token"),
) -> JSONResponse:
    """
    RFC 7662 §2.1 introspection response.
    Returns active=false for expired, invalid, or revoked tokens.
    Returns full claims for valid tokens.

    In production: require client authentication on this endpoint
    (it reveals token contents to the caller).
    """
    try:
        claims = _verify_token(token)
    except HTTPException:
        return JSONResponse(content={"active": False})

    now = int(time.time())
    exp = claims.get("exp", 0)
    if exp and exp < now:
        return JSONResponse(content={"active": False})

    jti = claims.get("jti", "")
    if jti and is_revoked(jti):
        return JSONResponse(content={"active": False})

    return JSONResponse(content={
        "active": True,
        "sub": claims.get("sub"),
        "iss": claims.get("iss"),
        "aud": claims.get("aud"),
        "exp": claims.get("exp"),
        "iat": claims.get("iat"),
        "jti": jti,
        "token_type": "Bearer",
        # OIDC-A agent claims
        "agent_model": claims.get("agent_model"),
        "agent_provider": claims.get("agent_provider"),
        "agent_version": claims.get("agent_version"),
        "agent_did": claims.get("agent_did"),
    })


# ---------------------------------------------------------------------------
# GET /v1/session/logout — OIDC RP-Initiated Logout 1.0
# ---------------------------------------------------------------------------

@router.get(
    "/session/logout",
    summary="OIDC RP-Initiated Logout",
    response_class=RedirectResponse,
    status_code=302,
)
async def rp_initiated_logout(
    id_token_hint: str | None = Query(None),
    post_logout_redirect_uri: str | None = Query(None),
    state: str | None = Query(None),
) -> RedirectResponse:
    """
    OIDC RP-Initiated Logout 1.0.
    1. Validate id_token_hint if present and revoke the jti
    2. Redirect to post_logout_redirect_uri (if registered) or default page
    3. Emit SSF SessionRevoked event
    """
    sub = ""
    jti = ""

    if id_token_hint:
        try:
            claims = _verify_token(id_token_hint)
            sub = claims.get("sub", "")
            jti = claims.get("jti", "")
            if jti:
                revoke_jti(jti)
            if sub:
                await _emit_ssf_session_revoked(sub, jti, "rp_logout")
        except HTTPException:
            pass  # Expired token — still process the logout

    # Build redirect URL
    base = os.environ.get("BASE_URL", "https://agent-id.openautonomyx.com")
    default_redirect = os.environ.get("POST_LOGOUT_REDIRECT", f"{base}/logged-out")

    target = post_logout_redirect_uri or default_redirect
    # TODO: verify post_logout_redirect_uri is registered for this client
    if state and post_logout_redirect_uri:
        sep = "&" if "?" in target else "?"
        target = f"{target}{sep}state={state}"

    return RedirectResponse(url=target, status_code=302)


# ---------------------------------------------------------------------------
# GET /v1/sessions — list active sessions for the authenticated user
# (requires bearer auth — wire auth dependency from your existing middleware)
# ---------------------------------------------------------------------------

@router.get(
    "/sessions",
    summary="List active sessions for authenticated user",
)
async def list_sessions() -> JSONResponse:
    """
    Returns active (non-revoked, non-expired) sessions for the caller.
    TODO: implement once sessions table exists in DB.
    """
    # TODO: query sessions table WHERE sub = current_user.sub AND jti NOT IN revoked AND exp > now
    return JSONResponse(content={"sessions": [], "note": "implement DB query"})
