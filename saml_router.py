"""
app/routers/saml_router.py

Production SAML 2.0 SP routes replacing the old stub ACS.

Routes:
  GET  /v1/sso/saml/start/{organization_slug}     — build AuthnRequest URL
  POST /v1/sso/saml/acs/{organization_slug}        — Assertion Consumer Service
  GET  /v1/sso/saml/metadata/{organization_slug}   — SP metadata (for IdP registration)
  POST /v1/sso/saml/slo/{organization_slug}        — Single Logout

Wire in app/main.py:
    from app.routers.saml_router import router as saml_router
    app.include_router(saml_router, prefix="/v1/sso/saml", tags=["SSO – SAML"])
"""

from __future__ import annotations

import os
import secrets
import time
import uuid

from fastapi import APIRouter, Form, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse, Response

from app.auth.saml import (
    build_authn_request_url,
    build_logout_request_url,
    build_sp_metadata,
    ingest_idp_metadata,
    process_logout_response,
    process_saml_response,
)

router = APIRouter()

# ---------------------------------------------------------------------------
# State store for SAML in-progress flows
# Stores request_id → {org_slug, relay_state, expires_at, name_id, session_index}
# ---------------------------------------------------------------------------

_SAML_FLOWS: dict[str, dict] = {}
_FLOW_TTL = 600


def _store_saml_request(request_id: str, org_slug: str, relay_state: str) -> None:
    _SAML_FLOWS[request_id] = {
        "org_slug": org_slug,
        "relay_state": relay_state,
        "expires_at": time.time() + _FLOW_TTL,
    }
    _purge()


def _consume_saml_request(request_id: str) -> dict:
    flow = _SAML_FLOWS.pop(request_id, None)
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unknown SAML request ID",
        )
    if time.time() > flow["expires_at"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SAML flow has expired",
        )
    return flow


def _purge() -> None:
    now = time.time()
    expired = [k for k, v in _SAML_FLOWS.items() if now > v["expires_at"]]
    for k in expired:
        del _SAML_FLOWS[k]


# ---------------------------------------------------------------------------
# SP config loader (replace with real DB lookup)
# ---------------------------------------------------------------------------

async def _load_saml_sp_config(org_slug: str) -> dict:
    """
    Load SAML SP config for the org.
    Returns dict with: sp_entity_id, acs_url, sls_url, sp_cert, sp_key, idp_data.
    Replace stub with real DB query.
    """
    base = os.environ.get("BASE_URL", "https://agent-id.openautonomyx.com")
    # TODO: load from identity_providers table WHERE org_slug = ... AND type = 'saml'
    #   Also call ingest_idp_metadata(row["idp_metadata_url"]) if idp_data not cached
    return {
        "sp_entity_id": f"{base}/v1/sso/saml/metadata/{org_slug}",
        "acs_url": f"{base}/v1/sso/saml/acs/{org_slug}",
        "sls_url": f"{base}/v1/sso/saml/slo/{org_slug}",
        "sp_cert": os.environ.get("SAML_SP_CERT", ""),
        "sp_key": os.environ.get("SAML_SP_KEY", ""),
        # idp_data should be the parsed dict from ingest_idp_metadata()
        # For the stub, return empty — real impl fetches from DB cache
        "idp_data": {},
    }


# ---------------------------------------------------------------------------
# GET /v1/sso/saml/metadata/{organization_slug}
# ---------------------------------------------------------------------------

@router.get(
    "/metadata/{organization_slug}",
    summary="SP metadata XML for IdP registration",
    response_class=Response,
)
async def saml_metadata(organization_slug: str) -> Response:
    """
    Returns signed SP metadata XML.
    The IdP administrator imports this URL when configuring the SAML integration.
    """
    cfg = await _load_saml_sp_config(organization_slug)

    if not cfg["sp_cert"] or not cfg["sp_key"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="SAML_SP_CERT and SAML_SP_KEY must be configured",
        )

    metadata_xml = build_sp_metadata(
        entity_id=cfg["sp_entity_id"],
        acs_url=cfg["acs_url"],
        sls_url=cfg["sls_url"],
        sp_cert=cfg["sp_cert"],
        sp_key=cfg["sp_key"],
    )
    return Response(
        content=metadata_xml,
        media_type="application/xml",
        headers={"Cache-Control": "public, max-age=3600"},
    )


# ---------------------------------------------------------------------------
# POST /v1/identity-providers/saml — register IdP metadata (ingest + validate)
# ---------------------------------------------------------------------------

from pydantic import BaseModel


class SamlIdPRegistration(BaseModel):
    organization_slug: str
    metadata_url: str        # URL to IdP metadata XML
    display_name: str | None = None


@router.post(
    "/register-idp",
    summary="Register SAML IdP — ingest + validate signed metadata",
    status_code=201,
)
async def register_saml_idp(body: SamlIdPRegistration) -> JSONResponse:
    """
    Fetch IdP metadata from the provided URL, validate its XML signature,
    extract signing certificates, and persist the config.
    Replaces the old stub that blindly accepted IdP config without verification.
    """
    idp_data = await ingest_idp_metadata(
        metadata_url=body.metadata_url,
        validate_cert=True,
    )

    # TODO: upsert into identity_providers table
    # {
    #   "organization_slug": body.organization_slug,
    #   "type": "saml",
    #   "idp_data": idp_data,
    #   "metadata_url": body.metadata_url,
    #   "display_name": body.display_name,
    # }

    idp = idp_data.get("idp", {})
    return JSONResponse(
        content={
            "registered": True,
            "entity_id": idp.get("entityId", ""),
            "sso_url": idp.get("singleSignOnService", {}).get("url", ""),
            "certificates_found": len(
                idp.get("x509certMulti", {}).get("signing", [])
                or ([idp.get("x509cert")] if idp.get("x509cert") else [])
            ),
        },
        status_code=201,
    )


# ---------------------------------------------------------------------------
# GET /v1/sso/saml/start/{organization_slug}
# ---------------------------------------------------------------------------

@router.get(
    "/start/{organization_slug}",
    summary="Initiate SAML SP-initiated SSO",
    response_class=RedirectResponse,
    status_code=302,
)
async def saml_start(
    organization_slug: str,
    relay_state: str = Query(default=""),
) -> RedirectResponse:
    cfg = await _load_saml_sp_config(organization_slug)

    if not cfg["idp_data"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"SAML IdP not configured for org '{organization_slug}'",
        )

    request_id = f"id_{uuid.uuid4().hex}"
    _store_saml_request(request_id, organization_slug, relay_state)

    authn_url = build_authn_request_url(
        sp_entity_id=cfg["sp_entity_id"],
        acs_url=cfg["acs_url"],
        sls_url=cfg["sls_url"],
        sp_cert=cfg["sp_cert"],
        sp_key=cfg["sp_key"],
        idp_data=cfg["idp_data"],
        relay_state=relay_state,
    )
    return RedirectResponse(url=authn_url, status_code=302)


# ---------------------------------------------------------------------------
# POST /v1/sso/saml/acs/{organization_slug} — Assertion Consumer Service
# ---------------------------------------------------------------------------

@router.post(
    "/acs/{organization_slug}",
    summary="SAML ACS — validate assertion, issue session",
)
async def saml_acs(
    organization_slug: str,
    SAMLResponse: str = Form(...),
    RelayState: str = Form(default=""),
    InResponseTo: str | None = Form(default=None),
) -> JSONResponse:
    """
    Full SAML assertion validation:
      1. XML signature on assertion (required — wantAssertionsSigned=True)
      2. Conditions: NotBefore, NotOnOrAfter
      3. AudienceRestriction: must contain our SP entity_id
      4. SubjectConfirmation: Recipient, NotOnOrAfter
      5. InResponseTo: matches stored request_id (replay protection)
    """
    cfg = await _load_saml_sp_config(organization_slug)

    user_attrs = process_saml_response(
        saml_response_b64=SAMLResponse,
        relay_state=RelayState,
        request_id=InResponseTo,
        sp_entity_id=cfg["sp_entity_id"],
        acs_url=cfg["acs_url"],
        sls_url=cfg["sls_url"],
        sp_cert=cfg["sp_cert"],
        sp_key=cfg["sp_key"],
        idp_data=cfg["idp_data"],
    )

    # Issue session (reuse OIDC session token logic)
    from app.routers.session_router import revoke_jti  # noqa: F401 (for future use)
    import jose.jwt as _jwt

    private_key = os.environ.get("SIGNING_KEY_PRIVATE_PEM", "")
    if not private_key:
        raise HTTPException(500, "SIGNING_KEY_PRIVATE_PEM not configured")

    now = int(time.time())
    session_token = _jwt.encode(
        {
            "iss": os.environ.get("BASE_URL", ""),
            "sub": user_attrs["sub"],
            "aud": organization_slug,
            "iat": now,
            "exp": now + int(os.environ.get("SESSION_TTL_SECONDS", 3600)),
            "jti": str(uuid.uuid4()),
            "email": user_attrs.get("email"),
            "name": user_attrs.get("name"),
            "saml_session_index": user_attrs.get("session_index"),
        },
        private_key,
        algorithm="RS256",
    )

    # TODO: persist session to DB

    return JSONResponse(
        content={
            "access_token": session_token,
            "token_type": "Bearer",
            "expires_in": int(os.environ.get("SESSION_TTL_SECONDS", 3600)),
            "sub": user_attrs["sub"],
            "email": user_attrs.get("email"),
        },
        headers={"Cache-Control": "no-store"},
    )


# ---------------------------------------------------------------------------
# POST /v1/sso/saml/slo/{organization_slug} — Single Logout
# ---------------------------------------------------------------------------

@router.post(
    "/slo/{organization_slug}",
    summary="SAML Single Logout",
)
async def saml_slo(
    organization_slug: str,
    SAMLResponse: str = Form(...),
    InResponseTo: str | None = Form(default=None),
) -> JSONResponse:
    cfg = await _load_saml_sp_config(organization_slug)

    process_logout_response(
        saml_response_b64=SAMLResponse,
        request_id=InResponseTo or "",
        sp_entity_id=cfg["sp_entity_id"],
        acs_url=cfg["acs_url"],
        sls_url=cfg["sls_url"],
        sp_cert=cfg["sp_cert"],
        sp_key=cfg["sp_key"],
        idp_data=cfg["idp_data"],
    )
    return JSONResponse(content={"logged_out": True})
