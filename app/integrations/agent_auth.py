from __future__ import annotations

import uuid
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

from app.config import settings


class AuthorizationSubject(BaseModel):
    type: Literal["user", "agent", "service"] = "agent"
    id: str = Field(min_length=1, max_length=512)
    tenant: str = Field(min_length=1, max_length=255)


class AuthorizationAction(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class AuthorizationResource(BaseModel):
    type: str = Field(min_length=1, max_length=255)
    id: str = Field(min_length=1, max_length=512)


class AuthorizationEvaluationRequest(BaseModel):
    subject: AuthorizationSubject
    action: AuthorizationAction
    resource: AuthorizationResource
    context: dict[str, Any] = Field(default_factory=dict)


class AuthorizationEvaluationResponse(BaseModel):
    decision: bool
    decision_id: str
    reason: str | None = None
    obligations: list[dict[str, Any]] = Field(default_factory=list)
    source: str = "agent-did-local"
    raw: dict[str, Any] = Field(default_factory=dict)


class AgentAuthClient:
    """Client for an AuthZEN-compatible Agent-Auth decision service.

    The local fallback is intentionally deny-by-default when no external decision service
    is configured. This keeps CAAS/tool-runtime integrations safe in staging and prod.
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self.base_url = (base_url or settings.agent_auth_url).rstrip("/")
        self.api_key = api_key or settings.agent_auth_api_key
        self.timeout_seconds = timeout_seconds or settings.agent_auth_timeout_seconds

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)

    async def evaluate(self, payload: AuthorizationEvaluationRequest) -> AuthorizationEvaluationResponse:
        decision_id = f"local-{uuid.uuid4().hex}"
        if not self.enabled:
            return AuthorizationEvaluationResponse(
                decision=False,
                decision_id=decision_id,
                reason="agent-auth service not configured",
                obligations=[{"type": "audit", "level": "full"}],
                source="agent-did-local",
            )

        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"

        url = f"{self.base_url}/access/v1/evaluation"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(url, json=payload.model_dump(), headers=headers)
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            return AuthorizationEvaluationResponse(
                decision=False,
                decision_id=decision_id,
                reason=f"agent-auth request failed: {exc.__class__.__name__}",
                obligations=[{"type": "audit", "level": "full"}],
                source="agent-did-local",
            )

        return AuthorizationEvaluationResponse(
            decision=bool(body.get("decision", body.get("allowed", False))),
            decision_id=str(body.get("decision_id") or body.get("id") or decision_id),
            reason=body.get("reason"),
            obligations=list(body.get("obligations") or []),
            source="agent-auth",
            raw=body,
        )
