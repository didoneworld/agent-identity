"""
app/auth/oidc.py

Real OIDC authorization-code exchange with JWKS validation.

Replaces the stub callback-based session issuance that existed before.
Complies with:
  - OAuth 2.1 + PKCE  (WP §2.4 / RFC 7636)
  - OIDC Core 1.0     (ID token validation, nonce, iss, aud, exp)
  - JWKS rotation     (keys fetched and cached with TTL, not baked in)

Drop this file into app/auth/ and wire the router in app/main.py:
    from app.routers.oidc_router import router as oidc_router
    app.include_router(oidc_router, prefix="/v1/sso/oidc")
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, status
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class OIDCProviderConfig(BaseModel):
    organization_slug: str
    issuer: str                     # e.g. "https://accounts.google.com"
    client_id: str
    client_secret: str
    redirect_uri: str               # must match what is registered at IdP
    scopes: list[str] = ["openid", "email", "profile"]
    extra_params: dict[str, str] = {}


class OIDCTokenSet(BaseModel):
    access_token: str
    id_token: str
    refresh_token: str | None = None
    expires_in: int
    token_type: str


class OIDCUserInfo(BaseModel):
    sub: str
    email: str | None = None
    email_verified: bool = False
    name: str | None = None
    picture: str | None = None
    # Agent-specific claims (OIDC-A / WP §3.1)
    agent_model: str | None = None
    agent_provider: str | None = None
    agent_version: str | None = None
    raw: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# JWKS cache  (simple in-process TTL cache — replace with Redis in prod)
# ---------------------------------------------------------------------------

_JWKS_CACHE: dict[str, tuple[float, list[dict]]] = {}   # issuer -> (fetched_at, keys)
_JWKS_TTL_SECONDS = 3600  # re-fetch after 1 hour


async def _fetch_jwks(jwks_uri: str) -> list[dict]:
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(jwks_uri)
        resp.raise_for_status()
        return resp.json()["keys"]


async def get_jwks(issuer: str, jwks_uri: str) -> list[dict]:
    """Return JWKS for issuer, hitting cache first."""
    now = time.time()
    if issuer in _JWKS_CACHE:
        fetched_at, keys = _JWKS_CACHE[issuer]
        if now - fetched_at < _JWKS_TTL_SECONDS:
            return keys
    keys = await _fetch_jwks(jwks_uri)
    _JWKS_CACHE[issuer] = (now, keys)
    return keys


def invalidate_jwks_cache(issuer: str) -> None:
    _JWKS_CACHE.pop(issuer, None)


# ---------------------------------------------------------------------------
# OIDC Discovery
# ---------------------------------------------------------------------------

_DISCOVERY_CACHE: dict[str, tuple[float, dict]] = {}
_DISCOVERY_TTL = 86400  # 24 h


async def discover(issuer: str) -> dict:
    """
    Fetch /.well-known/openid-configuration for the issuer.
    Caches for 24 h (providers rarely change endpoints).
    """
    now = time.time()
    if issuer in _DISCOVERY_CACHE:
        fetched_at, doc = _DISCOVERY_CACHE[issuer]
        if now - fetched_at < _DISCOVERY_TTL:
            return doc

    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        doc = resp.json()

    # Validate issuer matches (OIDC Core §4.3)
    if doc.get("issuer", "").rstrip("/") != issuer.rstrip("/"):
        raise ValueError(
            f"Discovery issuer mismatch: got {doc.get('issuer')!r}, expected {issuer!r}"
        )
    _DISCOVERY_CACHE[issuer] = (now, doc)
    return doc


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------

def generate_pkce_pair() -> tuple[str, str]:
    """
    Return (code_verifier, code_challenge).
    code_challenge = BASE64URL(SHA256(code_verifier)) per RFC 7636 §4.2.
    """
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    import base64
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def generate_state() -> str:
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    return secrets.token_urlsafe(32)


# ---------------------------------------------------------------------------
# Authorization URL builder
# ---------------------------------------------------------------------------

async def build_authorization_url(
    config: OIDCProviderConfig,
    state: str,
    nonce: str,
    code_challenge: str,
) -> str:
    """
    Build the IdP authorization URL with PKCE (S256) and nonce.
    """
    discovery = await discover(config.issuer)
    auth_endpoint = discovery["authorization_endpoint"]

    params: dict[str, str] = {
        "response_type": "code",
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "scope": " ".join(config.scopes),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        **config.extra_params,
    }
    return f"{auth_endpoint}?{urlencode(params)}"


# ---------------------------------------------------------------------------
# Token exchange
# ---------------------------------------------------------------------------

async def exchange_code_for_tokens(
    config: OIDCProviderConfig,
    code: str,
    code_verifier: str,
) -> OIDCTokenSet:
    """
    Exchange authorization code for tokens at the IdP token endpoint.
    Sends PKCE code_verifier; uses client_secret_post.
    """
    discovery = await discover(config.issuer)
    token_endpoint = discovery["token_endpoint"]

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.redirect_uri,
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "code_verifier": code_verifier,
    }

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            token_endpoint,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"IdP token exchange failed: {resp.status_code} {resp.text}",
        )

    payload = resp.json()
    if "error" in payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"IdP returned error: {payload['error']} — {payload.get('error_description','')}",
        )

    return OIDCTokenSet(
        access_token=payload["access_token"],
        id_token=payload.get("id_token", ""),
        refresh_token=payload.get("refresh_token"),
        expires_in=payload.get("expires_in", 3600),
        token_type=payload.get("token_type", "Bearer"),
    )


# ---------------------------------------------------------------------------
# ID Token validation  (OIDC Core 1.0 §3.1.3.7)
# ---------------------------------------------------------------------------

async def validate_id_token(
    config: OIDCProviderConfig,
    id_token: str,
    nonce: str,
) -> dict[str, Any]:
    """
    Full OIDC ID token validation:
      1. Decode header to get kid
      2. Fetch JWKS (cached)
      3. Verify RS256/ES256 signature
      4. Validate iss, aud, exp, nonce claims
    Returns the verified claims dict.
    """
    discovery = await discover(config.issuer)
    jwks_uri = discovery["jwks_uri"]
    keys = await get_jwks(config.issuer, jwks_uri)

    # Try each key until one verifies (handles key rotation)
    last_error: Exception | None = None
    for key in keys:
        try:
            claims = jwt.decode(
                id_token,
                key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                audience=config.client_id,
                issuer=config.issuer,
                options={"verify_exp": True, "verify_nbf": True},
            )
            # Nonce validation (replay protection)
            if claims.get("nonce") != nonce:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="ID token nonce mismatch — possible replay attack",
                )
            # iat must be in the past (clock-skew tolerance: 5 min)
            iat = claims.get("iat", 0)
            if iat > time.time() + 300:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="ID token iat is in the future",
                )
            return claims

        except ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="ID token has expired",
            )
        except JWTError as exc:
            last_error = exc
            continue  # try next key

    # If we exhausted all keys, the signature is invalid — could be key rotation
    # Flush JWKS cache and retry once
    invalidate_jwks_cache(config.issuer)
    keys_fresh = await get_jwks(config.issuer, jwks_uri)
    for key in keys_fresh:
        try:
            claims = jwt.decode(
                id_token,
                key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                audience=config.client_id,
                issuer=config.issuer,
            )
            if claims.get("nonce") != nonce:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="ID token nonce mismatch — possible replay attack",
                )
            return claims
        except JWTError as exc:
            last_error = exc

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"ID token signature validation failed: {last_error}",
    )


# ---------------------------------------------------------------------------
# UserInfo endpoint fetch + claim extraction
# ---------------------------------------------------------------------------

async def fetch_userinfo(
    config: OIDCProviderConfig,
    access_token: str,
) -> dict[str, Any]:
    discovery = await discover(config.issuer)
    userinfo_endpoint = discovery.get("userinfo_endpoint")
    if not userinfo_endpoint:
        return {}

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()


def extract_user_info(
    id_token_claims: dict[str, Any],
    userinfo: dict[str, Any] | None = None,
) -> OIDCUserInfo:
    """
    Merge ID token claims with UserInfo endpoint data.
    UserInfo claims take precedence per OIDC Core §5.3.2.
    Also extracts OIDC-A agent metadata claims (WP §3.1).
    """
    merged = {**id_token_claims, **(userinfo or {})}
    return OIDCUserInfo(
        sub=merged["sub"],
        email=merged.get("email"),
        email_verified=merged.get("email_verified", False),
        name=merged.get("name"),
        picture=merged.get("picture"),
        # Agent metadata claims (OIDC-A / WP §3.1)
        agent_model=merged.get("agent_model"),
        agent_provider=merged.get("agent_provider"),
        agent_version=merged.get("agent_version"),
        raw=merged,
    )


# ---------------------------------------------------------------------------
# Secure state / nonce store  (in-memory for single instance; use Redis in prod)
# ---------------------------------------------------------------------------

_PENDING_FLOWS: dict[str, dict] = {}   # state -> {nonce, verifier, org_slug, expires_at}
_FLOW_TTL = 600  # 10 min


def store_flow(
    state: str,
    nonce: str,
    code_verifier: str,
    organization_slug: str,
) -> None:
    _PENDING_FLOWS[state] = {
        "nonce": nonce,
        "code_verifier": code_verifier,
        "organization_slug": organization_slug,
        "expires_at": time.time() + _FLOW_TTL,
    }
    _purge_expired_flows()


def consume_flow(state: str) -> dict:
    """
    One-shot: retrieve and delete the pending flow for this state.
    Raises HTTPException if not found or expired.
    """
    flow = _PENDING_FLOWS.pop(state, None)
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unknown or already-used OAuth state parameter",
        )
    if time.time() > flow["expires_at"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth flow has expired — please restart sign-in",
        )
    return flow


def _purge_expired_flows() -> None:
    now = time.time()
    expired = [k for k, v in _PENDING_FLOWS.items() if now > v["expires_at"]]
    for k in expired:
        del _PENDING_FLOWS[k]
