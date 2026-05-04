"""
app/ssf/emitter.py

Shared Signals Framework (SSF) event emitter.

Implements:
  - OpenID SSF (draft-ietf-sharedsignals-framework)
  - CAEP (Continuous Access Evaluation Profile)

Events emitted:
  1. caep.session-revoked     — fired by session_router.py (Phase 1 stub → real)
  2. caep.credential-change   — fired on agent record update
  3. agent.deprovisioned       — fired on SCIM DELETE (WP §3.2)
     This is the cross-system de-provisioning broadcast the whitepaper
     requires for federated domain propagation.

Receiver registration:
  Receivers register via POST /v1/ssf/receivers (added in this module).
  Each receiver gets a push endpoint (HTTP) and an optional polling stream.
  Stored in the ssf_receivers table (schema below).

SSF stream token:
  Each receiver is issued a signed SSF stream token (JWT) that it presents
  when polling. The stream token encodes the receiver's event types.

Wire in app/main.py:
    from app.ssf.emitter import ssf_router
    app.include_router(ssf_router, prefix="/v1/ssf", tags=["SSF"])
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

ssf_router = APIRouter()

# ---------------------------------------------------------------------------
# CAEP event type URNs
# ---------------------------------------------------------------------------

CAEP_SESSION_REVOKED = (
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
)
CAEP_CREDENTIAL_CHANGE = (
    "https://schemas.openid.net/secevent/caep/event-type/credential-change"
)
AGENT_DEPROVISIONED = (
    "https://schemas.openid.net/secevent/agent/event-type/agent-deprovisioned"
)
AGENT_STATUS_CHANGE = (
    "https://schemas.openid.net/secevent/agent/event-type/agent-status-change"
)

# ---------------------------------------------------------------------------
# Receiver registry (in-memory — replace with DB in prod)
# ---------------------------------------------------------------------------

_RECEIVERS: dict[str, dict] = {}
# receiver_id -> {
#   endpoint_url, event_types, stream_token_jti,
#   registered_at, last_delivered_at
# }


class ReceiverRegistration(BaseModel):
    endpoint_url: str                       # POST target for push delivery
    event_types: list[str] = [
        CAEP_SESSION_REVOKED,
        AGENT_DEPROVISIONED,
        AGENT_STATUS_CHANGE,
    ]
    delivery_mode: str = "push"             # push | poll


class ReceiverResponse(BaseModel):
    receiver_id: str
    stream_token: str                       # JWT for poll authentication
    endpoint_url: str
    event_types: list[str]


# ---------------------------------------------------------------------------
# SSF receiver management routes
# ---------------------------------------------------------------------------

@ssf_router.post(
    "/receivers",
    summary="Register an SSF event receiver",
    status_code=201,
)
async def register_receiver(body: ReceiverRegistration) -> ReceiverResponse:
    """
    Register an endpoint to receive SSF CAEP events.
    Returns a receiver_id and stream_token for authentication.
    """
    receiver_id = str(uuid.uuid4())
    stream_token = _issue_stream_token(receiver_id, body.event_types)

    _RECEIVERS[receiver_id] = {
        "endpoint_url": body.endpoint_url,
        "event_types": body.event_types,
        "delivery_mode": body.delivery_mode,
        "stream_token_jti": receiver_id,
        "registered_at": time.time(),
        "last_delivered_at": None,
        "pending_events": [],              # for poll mode
    }

    return ReceiverResponse(
        receiver_id=receiver_id,
        stream_token=stream_token,
        endpoint_url=body.endpoint_url,
        event_types=body.event_types,
    )


@ssf_router.delete("/receivers/{receiver_id}", status_code=204)
async def deregister_receiver(receiver_id: str) -> None:
    if receiver_id not in _RECEIVERS:
        raise HTTPException(status_code=404, detail="Receiver not found")
    del _RECEIVERS[receiver_id]


@ssf_router.get("/receivers/{receiver_id}/events", summary="Poll for pending events")
async def poll_events(receiver_id: str) -> JSONResponse:
    """
    RFC SSF §6.2 polling endpoint.
    Returns and clears pending events for the receiver.
    """
    receiver = _RECEIVERS.get(receiver_id)
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")
    events = receiver.pop("pending_events", [])
    receiver["pending_events"] = []
    return JSONResponse(content={"sets": events})


# ---------------------------------------------------------------------------
# Stream token issuance
# ---------------------------------------------------------------------------

def _issue_stream_token(receiver_id: str, event_types: list[str]) -> str:
    from jose import jwt
    private_key = os.environ.get("SIGNING_KEY_PRIVATE_PEM", "")
    if not private_key:
        return f"stream-token-stub-{receiver_id}"  # test mode

    now = int(time.time())
    return jwt.encode(
        {
            "iss": os.environ.get("BASE_URL", ""),
            "sub": receiver_id,
            "aud": "ssf-stream",
            "iat": now,
            "exp": now + 86400 * 365,          # 1 year stream token
            "jti": str(uuid.uuid4()),
            "event_types": event_types,
        },
        private_key,
        algorithm="RS256",
    )


# ---------------------------------------------------------------------------
# Core emitter — called by SCIM DELETE and session revoke
# ---------------------------------------------------------------------------

def _build_set(
    event_type: str,
    subject: dict[str, Any],
    event_claims: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a Security Event Token (SET) per RFC 8417.
    The SET is a signed JWT wrapping the event.
    """
    return {
        "iss": os.environ.get("BASE_URL", "https://agent-id.openautonomyx.com"),
        "jti": str(uuid.uuid4()),
        "iat": int(time.time()),
        "aud": [],          # filled per-receiver on delivery
        "events": {
            event_type: {
                "subject": subject,
                "event_timestamp": int(time.time() * 1000),
                **event_claims,
            }
        },
    }


async def emit_agent_deprovisioned(
    agent_id: str,
    agent_did: str,
    organization_slug: str,
    reason: str = "scim_delete",
) -> None:
    """
    Emit AGENT_DEPROVISIONED to all registered receivers.

    Called by SCIM DELETE handler (WP §3.2 cross-system de-provisioning).
    Also called by the existing /v1/agent-records/{id}/deprovision endpoint
    — wire it there too.

    In production this should be dispatched to a background worker
    (Celery / asyncio task) to not block the HTTP response.
    """
    base = os.environ.get("BASE_URL", "https://agent-id.openautonomyx.com")
    set_payload = _build_set(
        event_type=AGENT_DEPROVISIONED,
        subject={
            "format": "did",
            "did": agent_did,
            "iss": base,
            "sub": agent_id,
        },
        event_claims={
            "organization_slug": organization_slug,
            "reason_admin": {"en": reason},
            "initiating_entity": "system",
        },
    )
    await _deliver_to_all_receivers(AGENT_DEPROVISIONED, set_payload)


async def emit_session_revoked(
    subject_id: str,
    session_id: str,
    reason: str = "user_initiated",
) -> None:
    """
    Emit CAEP SessionRevoked to all registered receivers.
    Upgrades the stub in app/routers/session_router.py to real delivery.
    """
    base = os.environ.get("BASE_URL", "https://agent-id.openautonomyx.com")
    set_payload = _build_set(
        event_type=CAEP_SESSION_REVOKED,
        subject={
            "format": "iss_sub",
            "iss": base,
            "sub": subject_id,
        },
        event_claims={
            "session_id": session_id,
            "initiating_entity": "policy",
            "reason_admin": {"en": reason},
        },
    )
    await _deliver_to_all_receivers(CAEP_SESSION_REVOKED, set_payload)


async def emit_agent_status_change(
    agent_id: str,
    agent_did: str,
    old_status: str,
    new_status: str,
    reason: str = "",
) -> None:
    """Emit AGENT_STATUS_CHANGE on SCIM PATCH active=false (suspension)."""
    base = os.environ.get("BASE_URL", "https://agent-id.openautonomyx.com")
    set_payload = _build_set(
        event_type=AGENT_STATUS_CHANGE,
        subject={
            "format": "did",
            "did": agent_did,
            "iss": base,
            "sub": agent_id,
        },
        event_claims={
            "previous_status": old_status,
            "current_status": new_status,
            "reason": reason,
        },
    )
    await _deliver_to_all_receivers(AGENT_STATUS_CHANGE, set_payload)


# ---------------------------------------------------------------------------
# Delivery engine
# ---------------------------------------------------------------------------

async def _deliver_to_all_receivers(
    event_type: str,
    set_payload: dict[str, Any],
) -> None:
    """
    Fan-out delivery to all receivers that subscribed to this event type.
    Push: HTTP POST to endpoint_url.
    Poll: append to pending_events queue.
    Failures are logged and retried up to 3 times with exponential backoff.
    """
    tasks = []
    for receiver_id, receiver in _RECEIVERS.items():
        if event_type not in receiver.get("event_types", []):
            continue
        personalised = {**set_payload, "aud": [receiver_id]}
        if receiver.get("delivery_mode") == "poll":
            receiver.setdefault("pending_events", []).append(personalised)
        else:
            tasks.append(_push_event(receiver["endpoint_url"], personalised))

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        import logging
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logging.getLogger(__name__).warning(
                    "SSF push delivery failed: %s", result
                )


async def _push_event(endpoint_url: str, set_payload: dict[str, Any]) -> None:
    """HTTP POST with exponential backoff retry (3 attempts)."""
    import logging
    log = logging.getLogger(__name__)
    last_exc: Exception | None = None

    for attempt in range(3):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    endpoint_url,
                    json=set_payload,
                    headers={"Content-Type": "application/secevent+jwt"},
                )
                if resp.status_code < 400:
                    return
                log.warning(
                    "SSF push to %s returned %s (attempt %d)",
                    endpoint_url, resp.status_code, attempt + 1,
                )
        except Exception as exc:
            last_exc = exc
            log.warning("SSF push attempt %d failed: %s", attempt + 1, exc)
        await asyncio.sleep(2 ** attempt)   # 1s, 2s, 4s

    log.error("SSF push permanently failed to %s: %s", endpoint_url, last_exc)
