from __future__ import annotations

from fastapi import APIRouter, Depends

from app.integrations.agent_auth import (
    AgentAuthClient,
    AuthorizationEvaluationRequest,
    AuthorizationEvaluationResponse,
)
from app.integrations.caas import CaaSClient, CaaSDecisionForwardRequest


router = APIRouter(prefix="/v1/authorization", tags=["authorization"])


def get_agent_auth_client() -> AgentAuthClient:
    return AgentAuthClient()


def get_caas_client() -> CaaSClient:
    return CaaSClient()


@router.post("/evaluate", response_model=AuthorizationEvaluationResponse)
async def evaluate_authorization(
    payload: AuthorizationEvaluationRequest,
    agent_auth: AgentAuthClient = Depends(get_agent_auth_client),
    caas: CaaSClient = Depends(get_caas_client),
) -> AuthorizationEvaluationResponse:
    """Evaluate an agent/user action using Agent-Auth and optionally forward to CAAS.

    This endpoint is the control-plane bridge:
    Agent DID owns identity/lifecycle context, Agent-Auth owns AuthZEN-style
    decisions, and CAAS can consume the resulting decision for runtime enforcement.
    """


    decision = await agent_auth.evaluate(payload)
    if isinstance(decision, dict):
        decision = AuthorizationEvaluationResponse(**decision)

    await caas.forward_decision(
        CaaSDecisionForwardRequest(
            subject=payload.subject.model_dump(),
            action=payload.action.model_dump(),
            resource=payload.resource.model_dump(),
            context=payload.context,
            decision=decision.decision,
            decision_id=decision.decision_id,
            obligations=decision.obligations,
            reason=decision.reason,
        )
    )
    return decision
