from __future__ import annotations

import json
from time import perf_counter
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db, init_database
from app.db_models import AgentRecord, AgentIdentityBlueprint
from app.migrations import migrate_database
from app.runtime import InMemoryRateLimiter, build_request_context, log_request, rate_limit_response
from app.schemas import (
    AgentRecordResponse,
    AuthorizationCheckRequest,
    AuthorizationCheckResponse,
    AuthorizationTupleResponse,
    AuthorizationTupleWrite,
    AgentRecordWrite,
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyRevokeResponse,
    ApiKeySummary,
    AuditEventResponse,
    BootstrapResponse,
    DeprovisionRequest,

    BlueprintLifecycleResponse,
    LifecycleAuditEventResponse,
    LifecycleRequest,
    LifecycleTransitionResponse,
    LifecycleValidationReportResponse,
    IdentityProviderConfigRequest,
    IdentityProviderConfigResponse,
    OidcCallbackRequest,
    OidcStartResponse,
    OrganizationBootstrapRequest,
    OrganizationResponse,
    SamlAssertionRequest,
    SessionAuthResponse,
    ServiceInfoResponse,
)
from app.services import AuthorizationError, BootstrapConflictError, ProtocolValidationError, SaaSService

# Phase 1-3 routers
from app.routers.discovery import router as discovery_router
from app.routers.oidc_router import router as oidc_router
from app.routers.saml_router import router as saml_router
from app.routers.session_router import router as session_router
from app.routers.scim_router import router as scim_router
from app.ssf.emitter import ssf_router
from app.lifecycle import BLUEPRINT_ACTION_TARGETS, BLUEPRINT_TRANSITIONS, LifecycleRequestData, agent_lifecycle_state, set_agent_lifecycle_state, validate_transition, validation_report_for_record
from app.approval.gate import approval_router


def _record_response(record: AgentRecord) -> AgentRecordResponse:
    return AgentRecordResponse(
        id=record.id,
        organization_id=record.organization_id,
        did=record.did,
        display_name=record.display_name,
        status=record.status,
        lifecycle_state=agent_lifecycle_state(record),
        environment=record.environment,
        protocol_version=record.protocol_version,
        record=record.record_json,
        created_at=record.created_at,
        updated_at=record.updated_at,
        deprovisioned_at=record.deprovisioned_at,
    )


def create_app(
    database_url: str | None = None,
    rate_limit_max_requests: int | None = None,
    rate_limit_window_seconds: int | None = None,
) -> FastAPI:
    engine = init_database(database_url)
    schema_revision = migrate_database(engine)
    service = SaaSService(schema_path=settings.schema_path)
    resolved_rate_limit_requests = rate_limit_max_requests or settings.api_rate_limit_requests
    resolved_rate_limit_window = rate_limit_window_seconds or settings.api_rate_limit_window_seconds

    app = FastAPI(
        title="Agent Identity SaaS",
        version=settings.app_version,
        description="Enterprise-oriented control plane for tenant-scoped Agent ID records and lifecycle operations.",
    )
    app.state.service = service
    app.state.schema_revision = schema_revision
    app.state.rate_limiter = InMemoryRateLimiter(
        max_requests=resolved_rate_limit_requests,
        window_seconds=resolved_rate_limit_window,
    )
    app.state.rate_limit_requests = resolved_rate_limit_requests
    app.state.rate_limit_window_seconds = resolved_rate_limit_window
    static_dir = settings.root_dir / "app" / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.middleware("http")
    async def add_runtime_guards(request: Request, call_next):
        request_id, actor = build_request_context(request)
        limiter_result = app.state.rate_limiter.check(actor)
        if not limiter_result.allowed:
            response = rate_limit_response(request_id, limiter_result.retry_after_seconds or 1)
            log_request(request.method, request.url.path, response.status_code, 0.0, request_id, actor)
            return response

        started_at = perf_counter()
        response = await call_next(request)
        duration_ms = (perf_counter() - started_at) * 1000
        response.headers["X-Request-ID"] = request_id
        log_request(request.method, request.url.path, response.status_code, duration_ms, request_id, actor)
        return response

    def require_auth(
        db: Annotated[Session, Depends(get_db)],
        x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    ):
        auth = None
        if x_api_key:
            auth = service.authenticate(db, x_api_key)
        elif authorization and authorization.startswith("Bearer "):
            auth = service.authenticate_session(db, authorization.removeprefix("Bearer ").strip())
        if auth is None:
            detail = "missing credentials" if not x_api_key and not authorization else "invalid credentials"
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)
        return auth

    def require_api_key_admin(
        auth=Depends(require_auth),
    ):
        if auth.auth_type != "api_key" or auth.role != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin api key required")
        if auth is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
        return auth

    def require_role(*allowed_roles: str):
        def dependency(auth=Depends(require_auth)):
            if auth.role not in allowed_roles:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
            return auth

        return dependency

    @app.get("/health")
    def health() -> ServiceInfoResponse:
        return ServiceInfoResponse(
            service=settings.service_name,
            version=settings.app_version,
            database_url_scheme=engine.url.drivername,
            schema_revision=app.state.schema_revision,
            rate_limit_requests=app.state.rate_limit_requests,
            rate_limit_window_seconds=app.state.rate_limit_window_seconds,
        )

    @app.get("/", include_in_schema=False)
    def ui() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    @app.post("/v1/bootstrap", response_model=BootstrapResponse, status_code=201)
    def bootstrap(payload: OrganizationBootstrapRequest, db: Annotated[Session, Depends(get_db)]):
        try:
            organization, api_key = service.bootstrap_organization(
                db,
                name=payload.organization_name,
                slug=payload.organization_slug,
                api_key_label=payload.api_key_label,
            )
        except BootstrapConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return BootstrapResponse(organization_id=organization.id, organization_slug=organization.slug, api_key=api_key)

    @app.get("/v1/organizations", response_model=list[OrganizationResponse])
    def list_organizations(
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_role("admin", "writer", "reader")),
    ):
        return service.list_organizations(db, auth.organization_id)

    @app.get("/v1/identity-providers", response_model=list[IdentityProviderConfigResponse])
    def list_identity_providers(
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_role("admin", "writer", "reader")),
    ):
        providers = service.list_identity_providers(db, auth.organization_id)
        return [
            IdentityProviderConfigResponse(
                id=provider.id,
                provider_type=provider.provider_type,
                enabled=provider.enabled,
                display_name=provider.display_name,
                issuer=provider.issuer,
                entity_id=provider.entity_id,
                login_url=provider.login_url,
                callback_url=provider.callback_url,
                client_id=provider.client_id,
                metadata=provider.metadata_json,
                default_role=provider.default_role,
                created_at=provider.created_at,
                updated_at=provider.updated_at,
            )
            for provider in providers
        ]

    @app.post("/v1/identity-providers/oidc", response_model=IdentityProviderConfigResponse, status_code=201)
    def upsert_oidc_provider(
        payload: IdentityProviderConfigRequest,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_api_key_admin),
    ):
        provider = service.upsert_identity_provider(
            db,
            organization_id=auth.organization_id,
            actor_label=auth.actor_label,
            provider_type="oidc",
            payload=payload.model_dump(),
        )
        return IdentityProviderConfigResponse(
            id=provider.id,
            provider_type=provider.provider_type,
            enabled=provider.enabled,
            display_name=provider.display_name,
            issuer=provider.issuer,
            entity_id=provider.entity_id,
            login_url=provider.login_url,
            callback_url=provider.callback_url,
            client_id=provider.client_id,
            metadata=provider.metadata_json,
            default_role=provider.default_role,
            created_at=provider.created_at,
            updated_at=provider.updated_at,
        )

    @app.post("/v1/identity-providers/saml", response_model=IdentityProviderConfigResponse, status_code=201)
    def upsert_saml_provider(
        payload: IdentityProviderConfigRequest,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_api_key_admin),
    ):
        provider = service.upsert_identity_provider(
            db,
            organization_id=auth.organization_id,
            actor_label=auth.actor_label,
            provider_type="saml",
            payload=payload.model_dump(),
        )
        return IdentityProviderConfigResponse(
            id=provider.id,
            provider_type=provider.provider_type,
            enabled=provider.enabled,
            display_name=provider.display_name,
            issuer=provider.issuer,
            entity_id=provider.entity_id,
            login_url=provider.login_url,
            callback_url=provider.callback_url,
            client_id=provider.client_id,
            metadata=provider.metadata_json,
            default_role=provider.default_role,
            created_at=provider.created_at,
            updated_at=provider.updated_at,
        )

    @app.get("/v1/sso/oidc/start/{organization_slug}", response_model=OidcStartResponse)
    def start_oidc_sign_in(
        organization_slug: str,
        db: Annotated[Session, Depends(get_db)],
    ):
        organization = service.get_organization_by_slug(db, organization_slug)
        if organization is None:
            raise HTTPException(status_code=404, detail="organization not found")
        provider = service.get_identity_provider(db, organization.id, "oidc")
        if provider is None:
            raise HTTPException(status_code=404, detail="oidc provider not configured")
        return OidcStartResponse(
            organization_slug=organization.slug,
            authorization_url=service.build_oidc_authorization_url(organization, provider),
        )

    @app.post("/v1/sso/oidc/callback/{organization_slug}", response_model=SessionAuthResponse)
    def oidc_callback(
        organization_slug: str,
        payload: OidcCallbackRequest,
        db: Annotated[Session, Depends(get_db)],
    ):
        organization = service.get_organization_by_slug(db, organization_slug)
        if organization is None:
            raise HTTPException(status_code=404, detail="organization not found")
        provider = service.get_identity_provider(db, organization.id, "oidc")
        if provider is None:
            raise HTTPException(status_code=404, detail="oidc provider not configured")
        session, token = service.create_oidc_session(
            db,
            organization=organization,
            provider=provider,
            actor_label="oidc-callback",
            subject=payload.subject,
            email=payload.email,
            display_name=payload.display_name,
            role=payload.role,
            claims=payload.claims,
        )
        return SessionAuthResponse(
            access_token=token,
            expires_at=session.expires_at,
            organization_id=organization.id,
            organization_slug=organization.slug,
            subject=session.subject,
            email=session.email,
            display_name=session.display_name,
            role=session.role,
            provider_type=session.provider_type,
        )

    @app.post("/v1/sso/saml/acs/{organization_slug}", response_model=SessionAuthResponse)
    def saml_acs(
        organization_slug: str,
        payload: SamlAssertionRequest,
        db: Annotated[Session, Depends(get_db)],
    ):
        organization = service.get_organization_by_slug(db, organization_slug)
        if organization is None:
            raise HTTPException(status_code=404, detail="organization not found")
        provider = service.get_identity_provider(db, organization.id, "saml")
        if provider is None:
            raise HTTPException(status_code=404, detail="saml provider not configured")
        try:
            session, token = service.create_saml_session(
                db,
                organization=organization,
                provider=provider,
                actor_label="saml-acs",
                saml_response=payload.saml_response,
                role=payload.role,
            )
        except ProtocolValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return SessionAuthResponse(
            access_token=token,
            expires_at=session.expires_at,
            organization_id=organization.id,
            organization_slug=organization.slug,
            subject=session.subject,
            email=session.email,
            display_name=session.display_name,
            role=session.role,
            provider_type=session.provider_type,
        )

    @app.get("/v1/api-keys", response_model=list[ApiKeySummary])
    def list_api_keys(
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_api_key_admin),
    ):
        return [
            ApiKeySummary(
                id=item.id,
                label=item.label,
                key_prefix=item.key_prefix,
                last_four=item.last_four,
                role=item.role,
                is_active=item.is_active,
                created_at=item.created_at,
                revoked_at=item.revoked_at,
                last_used_at=item.last_used_at,
            )
            for item in service.list_api_keys(db, auth.organization_id)
        ]

    @app.post("/v1/api-keys", response_model=ApiKeyCreateResponse, status_code=201)
    def create_api_key(
        payload: ApiKeyCreateRequest,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_api_key_admin),
    ):
        api_key, raw_key = service.create_api_key(
            db,
            organization_id=auth.organization_id,
            actor_label=auth.actor_label,
            label=payload.label,
            role=payload.role,
        )
        return ApiKeyCreateResponse(
            id=api_key.id,
            label=api_key.label,
            role=api_key.role,
            api_key=raw_key,
            key_prefix=api_key.key_prefix,
            last_four=api_key.last_four,
            created_at=api_key.created_at,
        )

    @app.post("/v1/api-keys/{api_key_id}/revoke", response_model=ApiKeyRevokeResponse)
    def revoke_api_key(
        api_key_id: str,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_api_key_admin),
    ):
        api_key = service.revoke_api_key(
            db,
            organization_id=auth.organization_id,
            actor_label=auth.actor_label,
            api_key_id=api_key_id,
        )
        if api_key is None:
            raise HTTPException(status_code=404, detail="api key not found")
        return ApiKeyRevokeResponse(id=api_key.id, is_active=api_key.is_active, revoked_at=api_key.revoked_at)

    @app.get("/v1/agent-records", response_model=list[AgentRecordResponse])
    def list_agent_records(
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_role("admin", "writer", "reader")),
    ):
        return [_record_response(record) for record in service.list_records(db, auth.organization_id)]

    @app.post("/v1/agent-records", response_model=AgentRecordResponse, status_code=201)
    def upsert_agent_record(
        payload: AgentRecordWrite,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_role("admin", "writer")),
    ):
        try:
            record = service.upsert_record(db, auth.organization_id, auth.actor_label, payload)
        except ProtocolValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return _record_response(record)

    @app.get("/v1/agent-records/{record_id}", response_model=AgentRecordResponse)
    def get_agent_record(
        record_id: str,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_role("admin", "writer", "reader")),
    ):
        record = service.get_record_by_id(db, auth.organization_id, record_id)
        if record is None:
            raise HTTPException(status_code=404, detail="agent record not found")
        try:
            service.ensure_record_permission(db, auth, record, "read")
        except AuthorizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return _record_response(record)

    @app.get("/v1/agent-records/by-did/{did:path}", response_model=AgentRecordResponse)
    def get_agent_record_by_did(
        did: str,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_role("admin", "writer", "reader")),
    ):
        record = service.get_record_by_did(db, auth.organization_id, did)
        if record is None:
            raise HTTPException(status_code=404, detail="agent record not found")
        try:
            service.ensure_record_permission(db, auth, record, "read")
        except AuthorizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return _record_response(record)

    @app.get("/v1/audit-events", response_model=list[AuditEventResponse])
    def list_audit_events(
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_role("admin", "writer", "reader")),
        agent_record_id: str | None = None,
    ):
        events = service.list_audit_events(db, auth.organization_id, agent_record_id=agent_record_id)
        return [
            AuditEventResponse(
                id=event.id,
                actor_label=event.actor_label,
                action=event.action,
                reason=event.reason,
                metadata=event.metadata_json,
                created_at=event.created_at,
            )
            for event in events
        ]

    @app.post("/v1/agent-records/{record_id}/deprovision")
    def deprovision_agent_record(
        record_id: str,
        payload: LifecycleRequest,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_role("admin", "writer", "reader")),
    ):
        current = service.get_record_by_id(db, auth.organization_id, record_id)
        if current is None:
            raise HTTPException(status_code=404, detail="agent record not found")
        try:
            service.ensure_record_permission(db, auth, current, "deprovision")
        except AuthorizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        req = LifecycleRequestData(**payload.model_dump())
        previous = agent_lifecycle_state(current)
        report = service.build_deprovisioning_report(record_id, req.requested_by or auth.actor_label, req.dry_run)
        if req.dry_run:
            response = _record_response(current).model_dump(mode="json")
            response.update({"subject_type": "agent", "subject_id": record_id, "previous_state": previous, "new_state": "deprovisioning", "dry_run": True, "deprovisioning_report": report})
            return response
        record = service.deprovision_record(
            db,
            auth.organization_id,
            auth.actor_label,
            record_id=record_id,
            reason=payload.reason or "deprovision requested",
        )
        set_agent_lifecycle_state(record, "deprovisioned")
        event = service._lifecycle_audit(db, organization_id=auth.organization_id, event_type="agent.deprovisioned", subject_type="agent", subject_id=record.id, actor_label=auth.actor_label, previous_state=previous, new_state="deprovisioned", request=req, metadata={"deprovisioning_report": report}, agent_record_id=record.id)
        db.commit(); db.refresh(record)
        response = _record_response(record).model_dump(mode="json")
        response.update({"subject_type": "agent", "subject_id": record_id, "previous_state": previous, "new_state": "deprovisioned", "dry_run": False, "audit_event_id": event.id, "deprovisioning_report": report})
        return response

    def _lifecycle_request(payload: LifecycleRequest) -> LifecycleRequestData:
        data = payload.model_dump()
        return LifecycleRequestData(**data)

    def _transition_response(subject_type: str, subject_id: str, result: dict) -> LifecycleTransitionResponse:
        return LifecycleTransitionResponse(
            subject_type=subject_type,
            subject_id=subject_id,
            previous_state=result.get("previous_state"),
            new_state=result.get("new_state"),
            dry_run=result.get("dry_run", False),
            validation_report=result.get("validation_report"),
            audit_event_id=result.get("audit_event_id"),
            deprovisioning_report=result.get("deprovisioning_report"),
        )

    @app.post("/v1/agent-records/{record_id}/validate", response_model=LifecycleValidationReportResponse)
    def validate_agent_lifecycle(
        record_id: str,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_role("admin", "writer", "reader")),
    ):
        record = service.get_record_by_id(db, auth.organization_id, record_id)
        if record is None:
            raise HTTPException(status_code=404, detail="agent record not found")
        return validation_report_for_record(record)

    @app.post("/v1/agent-records/{record_id}/submit-review", response_model=LifecycleTransitionResponse)
    @app.post("/v1/agent-records/{record_id}/approve", response_model=LifecycleTransitionResponse)
    @app.post("/v1/agent-records/{record_id}/activate", response_model=LifecycleTransitionResponse)
    @app.post("/v1/agent-records/{record_id}/suspend", response_model=LifecycleTransitionResponse)
    @app.post("/v1/agent-records/{record_id}/resume", response_model=LifecycleTransitionResponse)
    @app.post("/v1/agent-records/{record_id}/quarantine", response_model=LifecycleTransitionResponse)
    @app.post("/v1/agent-records/{record_id}/renew", response_model=LifecycleTransitionResponse)
    @app.post("/v1/agent-records/{record_id}/rotate-credentials", response_model=LifecycleTransitionResponse)
    @app.post("/v1/agent-records/{record_id}/archive", response_model=LifecycleTransitionResponse)
    def transition_agent_record_lifecycle(
        record_id: str,
        payload: LifecycleRequest,
        request: Request,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_role("admin", "writer")),
    ):
        action = request.url.path.rstrip("/").rsplit("/", 1)[-1]
        try:
            _record, result = service.transition_agent_lifecycle(db, auth.organization_id, auth.actor_label, record_id, action, _lifecycle_request(payload))
        except KeyError:
            raise HTTPException(status_code=404, detail="agent record not found")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except PermissionError as exc:
            try:
                detail = json.loads(str(exc))
            except Exception:
                detail = str(exc)
            raise HTTPException(status_code=422, detail=detail) from exc
        return _transition_response("agent", record_id, result)

    @app.delete("/v1/agent-records/{record_id}", response_model=LifecycleTransitionResponse)
    def delete_agent_record_lifecycle(
        record_id: str,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_role("admin", "writer")),
    ):
        try:
            _record, result = service.transition_agent_lifecycle(db, auth.organization_id, auth.actor_label, record_id, "delete", LifecycleRequestData(reason="delete requested", force=True))
        except KeyError:
            raise HTTPException(status_code=404, detail="agent record not found")
        return _transition_response("agent", record_id, result)

    def _blueprint_response(blueprint: AgentIdentityBlueprint) -> BlueprintLifecycleResponse:
        return BlueprintLifecycleResponse(id=blueprint.id, organization_id=blueprint.organization_id, lifecycle_state=blueprint.lifecycle_state, metadata=blueprint.metadata_json, updated_at=blueprint.updated_at)

    def _get_or_create_blueprint(db: Session, organization_id: str, blueprint_id: str) -> AgentIdentityBlueprint:
        blueprint = db.scalar(select(AgentIdentityBlueprint).where(AgentIdentityBlueprint.organization_id == organization_id, AgentIdentityBlueprint.id == blueprint_id))
        if blueprint is None:
            blueprint = AgentIdentityBlueprint(id=blueprint_id, organization_id=organization_id, metadata_json={"compatibility_profiles": ["microsoft_entra_agent_id_optional_alignment"]})
            db.add(blueprint); db.flush()
        return blueprint

    @app.get("/v1/blueprints/{blueprint_id}", response_model=BlueprintLifecycleResponse)
    def get_blueprint(blueprint_id: str, db: Annotated[Session, Depends(get_db)], auth=Depends(require_role("admin", "writer", "reader"))):
        return _blueprint_response(_get_or_create_blueprint(db, auth.organization_id, blueprint_id))

    @app.post("/v1/blueprints/{blueprint_id}/activate", response_model=LifecycleTransitionResponse)
    @app.post("/v1/blueprints/{blueprint_id}/disable", response_model=LifecycleTransitionResponse)
    @app.post("/v1/blueprints/{blueprint_id}/enable", response_model=LifecycleTransitionResponse)
    @app.post("/v1/blueprints/{blueprint_id}/deprecate", response_model=LifecycleTransitionResponse)
    @app.post("/v1/blueprints/{blueprint_id}/quarantine", response_model=LifecycleTransitionResponse)
    @app.post("/v1/blueprints/{blueprint_id}/deprovision-children", response_model=LifecycleTransitionResponse)
    @app.post("/v1/blueprints/{blueprint_id}/archive", response_model=LifecycleTransitionResponse)
    def transition_blueprint_lifecycle(blueprint_id: str, payload: LifecycleRequest, request: Request, db: Annotated[Session, Depends(get_db)], auth=Depends(require_role("admin", "writer"))):
        action = request.url.path.rstrip("/").rsplit("/", 1)[-1]
        req = _lifecycle_request(payload)
        blueprint = _get_or_create_blueprint(db, auth.organization_id, blueprint_id)
        previous = blueprint.lifecycle_state
        target = BLUEPRINT_ACTION_TARGETS[action]
        try:
            validate_transition("blueprint", previous, target, req.force)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if req.dry_run:
            return _transition_response("blueprint", blueprint_id, {"dry_run": True, "previous_state": previous, "new_state": target})
        blueprint.lifecycle_state = target; blueprint.updated_at = service._lifecycle_audit.__globals__["utc_now"]()
        event = service._lifecycle_audit(db, organization_id=auth.organization_id, event_type=f"blueprint.{target}", subject_type="blueprint", subject_id=blueprint.id, actor_label=auth.actor_label, previous_state=previous, new_state=target, request=req, metadata={"action": action})
        if action in {"disable", "deprovision-children"}:
            child_target = "suspended" if action == "disable" else "deprovisioning"
            for record in service.list_records(db, auth.organization_id):
                if (record.record_json or {}).get("blueprint_id") == blueprint.id or ((record.record_json or {}).get("lifecycle") or {}).get("blueprint_id") == blueprint.id or ((((record.record_json or {}).get("extensions") or {}).get("lifecycle") or {}).get("blueprint_id") == blueprint.id):
                    old = agent_lifecycle_state(record)
                    if req.force or child_target in {"suspended", "deprovisioning"}:
                        set_agent_lifecycle_state(record, child_target)
                        service._lifecycle_audit(db, organization_id=auth.organization_id, event_type=f"agent.{child_target}", subject_type="agent", subject_id=record.id, actor_label=auth.actor_label, previous_state=old, new_state=child_target, request=req, metadata={"cascade_from_blueprint": blueprint.id}, agent_record_id=record.id)
        db.commit()
        return _transition_response("blueprint", blueprint_id, {"previous_state": previous, "new_state": target, "audit_event_id": event.id})

    @app.delete("/v1/blueprints/{blueprint_id}", response_model=LifecycleTransitionResponse)
    def delete_blueprint_lifecycle(blueprint_id: str, db: Annotated[Session, Depends(get_db)], auth=Depends(require_role("admin", "writer"))):
        blueprint = _get_or_create_blueprint(db, auth.organization_id, blueprint_id)
        previous = blueprint.lifecycle_state
        blueprint.lifecycle_state = "deleted"; blueprint.updated_at = service._lifecycle_audit.__globals__["utc_now"]()
        event = service._lifecycle_audit(db, organization_id=auth.organization_id, event_type="blueprint.deleted", subject_type="blueprint", subject_id=blueprint.id, actor_label=auth.actor_label, previous_state=previous, new_state="deleted", request=LifecycleRequestData(reason="delete requested", force=True), metadata={})
        db.commit()
        return _transition_response("blueprint", blueprint_id, {"previous_state": previous, "new_state": "deleted", "audit_event_id": event.id})

    @app.get("/v1/audit/lifecycle-events", response_model=list[LifecycleAuditEventResponse])
    def list_lifecycle_events(db: Annotated[Session, Depends(get_db)], auth=Depends(require_role("admin", "writer", "reader")), subject_type: str | None = None, subject_id: str | None = None):
        events = service.list_lifecycle_audit_events(db, auth.organization_id, subject_type, subject_id)
        return [LifecycleAuditEventResponse(event_id=e.id, event_type=e.event_type, subject_type=e.subject_type, subject_id=e.subject_id, previous_state=e.previous_state, new_state=e.new_state, actor_type=e.actor_type, actor_id=e.actor_id, requested_by=e.requested_by, approved_by=e.approved_by, reason=e.reason, ticket_id=e.ticket_id, policy_id=e.policy_id, correlation_id=e.correlation_id, idempotency_key=e.idempotency_key, timestamp=e.created_at, evidence_hash=e.evidence_hash, metadata=e.metadata_json) for e in events]

    @app.get("/v1/agent-records/{record_id}/lifecycle-events", response_model=list[LifecycleAuditEventResponse])
    def list_agent_lifecycle_events(record_id: str, db: Annotated[Session, Depends(get_db)], auth=Depends(require_role("admin", "writer", "reader"))):
        events = service.list_lifecycle_audit_events(db, auth.organization_id, "agent", record_id)
        return [LifecycleAuditEventResponse(event_id=e.id, event_type=e.event_type, subject_type=e.subject_type, subject_id=e.subject_id, previous_state=e.previous_state, new_state=e.new_state, actor_type=e.actor_type, actor_id=e.actor_id, requested_by=e.requested_by, approved_by=e.approved_by, reason=e.reason, ticket_id=e.ticket_id, policy_id=e.policy_id, correlation_id=e.correlation_id, idempotency_key=e.idempotency_key, timestamp=e.created_at, evidence_hash=e.evidence_hash, metadata=e.metadata_json) for e in events]

    @app.get("/v1/blueprints/{blueprint_id}/lifecycle-events", response_model=list[LifecycleAuditEventResponse])
    def list_blueprint_lifecycle_events(blueprint_id: str, db: Annotated[Session, Depends(get_db)], auth=Depends(require_role("admin", "writer", "reader"))):
        events = service.list_lifecycle_audit_events(db, auth.organization_id, "blueprint", blueprint_id)
        return [LifecycleAuditEventResponse(event_id=e.id, event_type=e.event_type, subject_type=e.subject_type, subject_id=e.subject_id, previous_state=e.previous_state, new_state=e.new_state, actor_type=e.actor_type, actor_id=e.actor_id, requested_by=e.requested_by, approved_by=e.approved_by, reason=e.reason, ticket_id=e.ticket_id, policy_id=e.policy_id, correlation_id=e.correlation_id, idempotency_key=e.idempotency_key, timestamp=e.created_at, evidence_hash=e.evidence_hash, metadata=e.metadata_json) for e in events]

    @app.get("/v1/fga/tuples", response_model=list[AuthorizationTupleResponse])
    def list_fga_tuples(
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_role("admin", "writer", "reader")),
        object_type: str | None = None,
        object_id: str | None = None,
    ):
        tuples = service.list_authorization_tuples(
            db,
            organization_id=auth.organization_id,
            object_type=object_type,
            object_id=object_id,
        )
        return [
            AuthorizationTupleResponse(
                id=item.id,
                subject=item.subject,
                relation=item.relation,
                object_type=item.object_type,
                object_id=item.object_id,
                created_at=item.created_at,
            )
            for item in tuples
        ]

    @app.post("/v1/fga/tuples", response_model=AuthorizationTupleResponse, status_code=201)
    def create_fga_tuple(
        payload: AuthorizationTupleWrite,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_role("admin")),
    ):
        auth_tuple = service.create_authorization_tuple(
            db,
            organization_id=auth.organization_id,
            actor_label=auth.actor_label,
            subject=payload.subject,
            relation=payload.relation,
            object_type=payload.object_type,
            object_id=payload.object_id,
        )
        return AuthorizationTupleResponse(
            id=auth_tuple.id,
            subject=auth_tuple.subject,
            relation=auth_tuple.relation,
            object_type=auth_tuple.object_type,
            object_id=auth_tuple.object_id,
            created_at=auth_tuple.created_at,
        )

    @app.post("/v1/fga/check", response_model=AuthorizationCheckResponse)
    def check_fga_tuple(
        payload: AuthorizationCheckRequest,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_role("admin", "writer", "reader")),
    ):
        allowed = service.check_authorization_tuple(
            db,
            organization_id=auth.organization_id,
            subject=payload.subject,
            relation=payload.relation,
            object_type=payload.object_type,
            object_id=payload.object_id,
        )
        return AuthorizationCheckResponse(allowed=allowed)

    # ── Phase 1: hardened identity flows ──────────────────────────────────────
    # Discovery must be at root (no prefix) — OIDC RPs hit /.well-known/*
    app.include_router(discovery_router, tags=["Discovery"])
    app.include_router(oidc_router,    prefix="/v1/sso/oidc", tags=["SSO – OIDC"])
    app.include_router(saml_router,    prefix="/v1/sso/saml", tags=["SSO – SAML"])
    app.include_router(session_router, prefix="/v1",          tags=["Sessions"])

    # ── Phase 2: SCIM lifecycle + SSF + approvals ──────────────────────────
    app.include_router(scim_router,    prefix="/v1/scim/v2",  tags=["SCIM"])
    app.include_router(ssf_router,     prefix="/v1/ssf",      tags=["SSF"])
    app.include_router(approval_router,prefix="/v1/approvals",tags=["Approvals"])

    return app


app = create_app()
