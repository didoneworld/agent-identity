from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any

import httpx

from .models import (
    AgentLifecycleAction,
    AgentRecord,
    Blueprint,
    BlueprintLifecycleAction,
    LifecycleAuditEvent,
    LifecycleRequest,
    LifecycleTransition,
    ValidationReport,
)

AuthProvider = Callable[[], str | None]


class AgentDidError(RuntimeError):
    """Raised for non-2xx Agent DID API responses."""

    def __init__(self, message: str, *, status_code: int | None = None, detail: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail


class AgentDidClient:
    """Synchronous SDK client for Agent DID control-plane APIs.

    The client is intentionally thin and adapter-friendly: pass an API key, bearer
    token, dynamic auth provider, custom headers, or an httpx transport to embed it
    in another platform without coupling to a specific identity vendor.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        bearer_token: str | None = None,
        auth_provider: AuthProvider | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.bearer_token = bearer_token
        self.auth_provider = auth_provider
        self.default_headers = dict(headers or {})
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout, transport=transport)

    @classmethod
    def from_env(cls, *, prefix: str = "AGENTDID", **kwargs: Any) -> "AgentDidClient":
        base_url = os.environ.get(f"{prefix}_BASE_URL", "http://localhost:8000")
        return cls(
            base_url,
            api_key=os.environ.get(f"{prefix}_API_KEY"),
            bearer_token=os.environ.get(f"{prefix}_BEARER_TOKEN"),
            **kwargs,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "AgentDidClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _headers(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        headers = {"Accept": "application/json", **self.default_headers}
        token = self.auth_provider() if self.auth_provider else None
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        if token or self.bearer_token:
            headers["Authorization"] = f"Bearer {token or self.bearer_token}"
        if extra:
            headers.update(extra)
        return headers

    def _request(self, method: str, path: str, *, json: Any = None, params: Mapping[str, Any] | None = None) -> Any:
        response = self._client.request(method, path, json=json, params=params, headers=self._headers())
        if response.status_code >= 400:
            try:
                detail = response.json()
            except ValueError:
                detail = response.text
            raise AgentDidError(
                f"Agent DID API request failed with status {response.status_code}",
                status_code=response.status_code,
                detail=detail,
            )
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    def list_agent_records(self) -> list[AgentRecord]:
        return [AgentRecord.from_dict(item) for item in self._request("GET", "/v1/agent-records")]

    def get_agent_record(self, agent_id: str) -> AgentRecord:
        return AgentRecord.from_dict(self._request("GET", f"/v1/agent-records/{agent_id}"))

    def get_agent_record_by_did(self, did: str) -> AgentRecord:
        return AgentRecord.from_dict(self._request("GET", f"/v1/agent-records/by-did/{did}"))

    def upsert_agent_record(self, record: dict[str, Any]) -> AgentRecord:
        return AgentRecord.from_dict(self._request("POST", "/v1/agent-records", json=record))

    def validate_agent(self, agent_id: str) -> ValidationReport:
        return ValidationReport.from_dict(self._request("POST", f"/v1/agent-records/{agent_id}/validate", json={}))

    def transition_agent(
        self,
        agent_id: str,
        action: AgentLifecycleAction | str,
        request: LifecycleRequest | None = None,
        **kwargs: Any,
    ) -> LifecycleTransition:
        payload = request or LifecycleRequest(**kwargs)
        action_value = str(action)
        return LifecycleTransition.from_dict(
            self._request("POST", f"/v1/agent-records/{agent_id}/{action_value}", json=payload.to_payload())
        )

    def submit_review(self, agent_id: str, **kwargs: Any) -> LifecycleTransition:
        return self.transition_agent(agent_id, AgentLifecycleAction.SUBMIT_REVIEW, **kwargs)

    def approve_agent(self, agent_id: str, **kwargs: Any) -> LifecycleTransition:
        return self.transition_agent(agent_id, AgentLifecycleAction.APPROVE, **kwargs)

    def activate_agent(self, agent_id: str, **kwargs: Any) -> LifecycleTransition:
        return self.transition_agent(agent_id, AgentLifecycleAction.ACTIVATE, **kwargs)

    def suspend_agent(self, agent_id: str, **kwargs: Any) -> LifecycleTransition:
        return self.transition_agent(agent_id, AgentLifecycleAction.SUSPEND, **kwargs)

    def resume_agent(self, agent_id: str, **kwargs: Any) -> LifecycleTransition:
        return self.transition_agent(agent_id, AgentLifecycleAction.RESUME, **kwargs)

    def quarantine_agent(self, agent_id: str, **kwargs: Any) -> LifecycleTransition:
        return self.transition_agent(agent_id, AgentLifecycleAction.QUARANTINE, **kwargs)

    def renew_agent(self, agent_id: str, **kwargs: Any) -> LifecycleTransition:
        return self.transition_agent(agent_id, AgentLifecycleAction.RENEW, **kwargs)

    def rotate_agent_credentials(self, agent_id: str, **kwargs: Any) -> LifecycleTransition:
        return self.transition_agent(agent_id, AgentLifecycleAction.ROTATE_CREDENTIALS, **kwargs)

    def deprovision_agent(self, agent_id: str, **kwargs: Any) -> LifecycleTransition:
        return self.transition_agent(agent_id, AgentLifecycleAction.DEPROVISION, **kwargs)

    def delete_agent(self, agent_id: str) -> LifecycleTransition:
        return LifecycleTransition.from_dict(self._request("DELETE", f"/v1/agent-records/{agent_id}"))

    def get_blueprint(self, blueprint_id: str) -> Blueprint:
        return Blueprint.from_dict(self._request("GET", f"/v1/blueprints/{blueprint_id}"))

    def transition_blueprint(
        self,
        blueprint_id: str,
        action: BlueprintLifecycleAction | str,
        request: LifecycleRequest | None = None,
        **kwargs: Any,
    ) -> LifecycleTransition:
        payload = request or LifecycleRequest(**kwargs)
        action_value = str(action)
        return LifecycleTransition.from_dict(
            self._request("POST", f"/v1/blueprints/{blueprint_id}/{action_value}", json=payload.to_payload())
        )

    def disable_blueprint(self, blueprint_id: str, **kwargs: Any) -> LifecycleTransition:
        return self.transition_blueprint(blueprint_id, BlueprintLifecycleAction.DISABLE, **kwargs)

    def deprovision_blueprint_children(self, blueprint_id: str, **kwargs: Any) -> LifecycleTransition:
        return self.transition_blueprint(blueprint_id, BlueprintLifecycleAction.DEPROVISION_CHILDREN, **kwargs)

    def delete_blueprint(self, blueprint_id: str) -> LifecycleTransition:
        return LifecycleTransition.from_dict(self._request("DELETE", f"/v1/blueprints/{blueprint_id}"))

    def list_lifecycle_events(
        self,
        *,
        subject_type: str | None = None,
        subject_id: str | None = None,
    ) -> list[LifecycleAuditEvent]:
        params = {key: value for key, value in {"subject_type": subject_type, "subject_id": subject_id}.items() if value}
        return [
            LifecycleAuditEvent.from_dict(item)
            for item in self._request("GET", "/v1/audit/lifecycle-events", params=params)
        ]

    def list_agent_lifecycle_events(self, agent_id: str) -> list[LifecycleAuditEvent]:
        return [
            LifecycleAuditEvent.from_dict(item)
            for item in self._request("GET", f"/v1/agent-records/{agent_id}/lifecycle-events")
        ]

    def list_blueprint_lifecycle_events(self, blueprint_id: str) -> list[LifecycleAuditEvent]:
        return [
            LifecycleAuditEvent.from_dict(item)
            for item in self._request("GET", f"/v1/blueprints/{blueprint_id}/lifecycle-events")
        ]
