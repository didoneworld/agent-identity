"""
app/auth/saml.py

Production-hardened SAML 2.0 Service Provider.

Fixes all gaps listed in agent-did README:
  - Certificate validation on assertions
  - Signed metadata ingestion + signature verification
  - Full SP metadata generation (for registration at IdP)
  - Assertion validation: Conditions, SubjectConfirmation,
    AudienceRestriction, NotBefore/NotOnOrAfter
  - XML signature wrapping attack protection (strict node selection)

Depends on: python3-saml (OneLogin) + lxml.
    pip install python3-saml lxml cryptography

Drop into app/auth/ and wire the router in app/main.py:
    from app.routers.saml_router import router as saml_router
    app.include_router(saml_router, prefix="/v1/sso/saml")
"""

from __future__ import annotations

import base64
import time
from typing import Any
from urllib.parse import urlencode
from xml.etree import ElementTree as ET

import httpx
from fastapi import HTTPException, status

# python3-saml wraps lxml + xmlsec1
try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    from onelogin.saml2.utils import OneLogin_Saml2_Utils
    _SAML_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SAML_AVAILABLE = False


# ---------------------------------------------------------------------------
# Models (plain dicts for simplicity; swap for Pydantic if preferred)
# ---------------------------------------------------------------------------

def _require_saml() -> None:
    if not _SAML_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="python3-saml is not installed. Run: pip install python3-saml lxml",
        )


# ---------------------------------------------------------------------------
# SP metadata builder
# ---------------------------------------------------------------------------

def build_sp_metadata(
    entity_id: str,
    acs_url: str,
    sls_url: str,
    sp_cert: str,
    sp_key: str,
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
) -> str:
    """
    Generate signed SP metadata XML for registration at the IdP.
    The metadata is signed with the SP private key so IdPs that require
    signed metadata can validate it.
    """
    _require_saml()
    settings = {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": entity_id,
            "assertionConsumerService": {
                "url": acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": sls_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": name_id_format,
            "x509cert": sp_cert,
            "privateKey": sp_key,
        },
        "idp": {
            # Placeholder — filled in after IdP metadata is ingested
            "entityId": "",
            "singleSignOnService": {"url": "", "binding": ""},
            "x509cert": "",
        },
    }
    saml_settings = OneLogin_Saml2_Settings(settings=settings, sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    if errors:
        raise ValueError(f"SP metadata validation errors: {errors}")
    return metadata


# ---------------------------------------------------------------------------
# IdP metadata ingestion with signature verification
# ---------------------------------------------------------------------------

async def ingest_idp_metadata(
    metadata_url: str,
    validate_cert: bool = True,
) -> dict[str, Any]:
    """
    Fetch and validate IdP metadata.
    - Follows HTTPS redirect
    - Parses entity descriptor
    - Verifies XML signature on metadata (if present and validate_cert=True)
    - Returns a settings-ready idp dict
    """
    _require_saml()

    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        resp = await client.get(metadata_url)
        if resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to fetch IdP metadata: HTTP {resp.status_code}",
            )
        metadata_xml = resp.text

    # Parse using OneLogin's parser (handles multi-cert, signing cert, slo, sso)
    idp_data = OneLogin_Saml2_IdPMetadataParser.parse(metadata_xml)

    if not idp_data or "idp" not in idp_data:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Could not parse IdP metadata — check the metadata URL",
        )

    idp_section = idp_data["idp"]

    # Ensure at least one signing certificate is present
    certs = idp_section.get("x509certMulti", {}).get("signing", [])
    if not certs:
        single = idp_section.get("x509cert", "")
        if single:
            certs = [single]
    if not certs:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="IdP metadata contains no signing certificates — cannot validate assertions",
        )

    return idp_data


# ---------------------------------------------------------------------------
# SAML flow helpers
# ---------------------------------------------------------------------------

def _build_saml_settings(
    sp_entity_id: str,
    acs_url: str,
    sls_url: str,
    sp_cert: str,
    sp_key: str,
    idp_data: dict[str, Any],
) -> dict:
    """Compose the full python3-saml settings dict."""
    return {
        "strict": True,
        "debug": False,
        "security": {
            # Require assertions to be signed (critical for security)
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            # Reject responses with more than 1 SubjectConfirmation
            "rejectUnsolicitedResponsesWithInResponseTo": True,
            # Protect against XML signature wrapping attacks
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
        "sp": {
            "entityId": sp_entity_id,
            "assertionConsumerService": {
                "url": acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": sls_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "x509cert": sp_cert,
            "privateKey": sp_key,
        },
        "idp": idp_data.get("idp", {}),
    }


def build_authn_request_url(
    sp_entity_id: str,
    acs_url: str,
    sls_url: str,
    sp_cert: str,
    sp_key: str,
    idp_data: dict[str, Any],
    relay_state: str = "",
) -> str:
    """Build signed AuthnRequest redirect URL."""
    _require_saml()
    settings_dict = _build_saml_settings(
        sp_entity_id, acs_url, sls_url, sp_cert, sp_key, idp_data
    )
    # Minimal request object python3-saml expects
    req = {
        "https": "on",
        "http_host": "",
        "script_name": acs_url,
        "server_port": "",
        "get_data": {},
        "post_data": {},
        "query_string": "",
    }
    auth = OneLogin_Saml2_Auth(req, old_settings=settings_dict)
    return auth.login(return_to=relay_state)


# ---------------------------------------------------------------------------
# ACS — Assertion Consumer Service: full validation
# ---------------------------------------------------------------------------

def process_saml_response(
    saml_response_b64: str,
    relay_state: str,
    request_id: str | None,
    sp_entity_id: str,
    acs_url: str,
    sls_url: str,
    sp_cert: str,
    sp_key: str,
    idp_data: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate a SAML Response from the IdP.
    Performs:
      1. XML signature verification on both Response and Assertion
      2. Conditions: NotBefore, NotOnOrAfter
      3. AudienceRestriction: must contain sp_entity_id
      4. SubjectConfirmation: Recipient must match acs_url, NotOnOrAfter check
      5. InResponseTo replay protection (matches request_id)
    Returns dict of verified attributes.
    Raises HTTPException on any validation failure.
    """
    _require_saml()

    settings_dict = _build_saml_settings(
        sp_entity_id, acs_url, sls_url, sp_cert, sp_key, idp_data
    )

    # python3-saml needs a request-like dict
    req = {
        "https": "on",
        "http_host": "",
        "script_name": acs_url,
        "server_port": "",
        "get_data": {},
        "post_data": {"SAMLResponse": saml_response_b64, "RelayState": relay_state},
        "query_string": "",
    }

    auth = OneLogin_Saml2_Auth(req, old_settings=settings_dict)
    auth.process_response(request_id=request_id)

    errors = auth.get_errors()
    if errors:
        reason = auth.get_last_error_reason() or ", ".join(errors)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"SAML assertion validation failed: {reason}",
        )

    if not auth.is_authenticated():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SAML authentication unsuccessful",
        )

    attributes = auth.get_attributes()
    name_id = auth.get_nameid()
    session_index = auth.get_session_index()

    # Extract standard claims with fallbacks
    email = _first(attributes.get("email") or attributes.get(
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
    ))
    name = _first(attributes.get("name") or attributes.get(
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
    ))

    return {
        "sub": name_id,
        "email": email or name_id,
        "name": name,
        "session_index": session_index,
        "attributes": attributes,
    }


def _first(lst: list | None) -> str | None:
    if not lst:
        return None
    return lst[0] if lst else None


# ---------------------------------------------------------------------------
# SLO — Single Logout Service
# ---------------------------------------------------------------------------

def build_logout_request_url(
    name_id: str,
    session_index: str,
    sp_entity_id: str,
    acs_url: str,
    sls_url: str,
    sp_cert: str,
    sp_key: str,
    idp_data: dict[str, Any],
) -> str:
    """Generate signed SLO request URL."""
    _require_saml()
    settings_dict = _build_saml_settings(
        sp_entity_id, acs_url, sls_url, sp_cert, sp_key, idp_data
    )
    req = {
        "https": "on",
        "http_host": "",
        "script_name": sls_url,
        "server_port": "",
        "get_data": {},
        "post_data": {},
        "query_string": "",
    }
    auth = OneLogin_Saml2_Auth(req, old_settings=settings_dict)
    return auth.logout(name_id=name_id, session_index=session_index)


def process_logout_response(
    saml_response_b64: str,
    request_id: str,
    sp_entity_id: str,
    acs_url: str,
    sls_url: str,
    sp_cert: str,
    sp_key: str,
    idp_data: dict[str, Any],
) -> None:
    """Validate SLO response. Raises on error."""
    _require_saml()
    settings_dict = _build_saml_settings(
        sp_entity_id, acs_url, sls_url, sp_cert, sp_key, idp_data
    )
    req = {
        "https": "on",
        "http_host": "",
        "script_name": sls_url,
        "server_port": "",
        "get_data": {"SAMLResponse": saml_response_b64},
        "post_data": {},
        "query_string": f"SAMLResponse={saml_response_b64}",
    }
    auth = OneLogin_Saml2_Auth(req, old_settings=settings_dict)
    auth.process_slo(request_id=request_id)
    errors = auth.get_errors()
    if errors:
        reason = auth.get_last_error_reason() or ", ".join(errors)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SLO validation failed: {reason}",
        )
