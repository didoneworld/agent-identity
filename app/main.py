from __future__ import annotations

from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base, get_db, init_database
from app.db_models import AgentRecord
from app.schemas import (
    AgentRecordResponse,
    AgentRecordWrite,
    ApiKeySummary,
    AuditEventResponse,
    BootstrapResponse,
    DeprovisionRequest,
    OrganizationBootstrapRequest,
    OrganizationResponse,
    ServiceInfoResponse,
)
from app.services import BootstrapConflictError, ProtocolValidationError, SaaSService


def _record_response(record: AgentRecord) -> AgentRecordResponse:
    return AgentRecordResponse(
        id=record.id,
        organization_id=record.organization_id,
        did=record.did,
        display_name=record.display_name,
        status=record.status,
        environment=record.environment,
        protocol_version=record.protocol_version,
        record=record.record_json,
        created_at=record.created_at,
        updated_at=record.updated_at,
        deprovisioned_at=record.deprovisioned_at,
    )


def create_app(database_url: str | None = None) -> FastAPI:
    engine = init_database(database_url)
    service = SaaSService(schema_path=settings.schema_path)

    app = FastAPI(
        title="Agent ID Protocol SaaS",
        version="0.2.0",
        description="Enterprise-oriented control plane for tenant-scoped Agent ID records and lifecycle operations.",
    )
    app.state.service = service

    Base.metadata.create_all(bind=engine)
    static_dir = settings.root_dir / "app" / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    def require_auth(
        db: Annotated[Session, Depends(get_db)],
        x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    ):
        if not x_api_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing api key")
        auth = service.authenticate(db, x_api_key)
        if auth is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid api key")
        return auth

    @app.get("/health")
    def health() -> ServiceInfoResponse:
        return ServiceInfoResponse(
            service="agent-identity-saas",
            version="0.2.0",
            database_url_scheme=settings.database_url.split(":", 1)[0],
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
        auth=Depends(require_auth),
    ):
        return service.list_organizations(db, auth.organization_id)

    @app.get("/v1/api-keys", response_model=list[ApiKeySummary])
    def list_api_keys(
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_auth),
    ):
        return [
            ApiKeySummary(
                id=item.id,
                label=item.label,
                key_prefix=item.key_prefix,
                last_four=item.last_four,
                is_active=item.is_active,
                created_at=item.created_at,
            )
            for item in service.list_api_keys(db, auth.organization_id)
        ]

    @app.get("/v1/agent-records", response_model=list[AgentRecordResponse])
    def list_agent_records(
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_auth),
    ):
        return [_record_response(record) for record in service.list_records(db, auth.organization_id)]

    @app.post("/v1/agent-records", response_model=AgentRecordResponse, status_code=201)
    def upsert_agent_record(
        payload: AgentRecordWrite,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_auth),
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
        auth=Depends(require_auth),
    ):
        record = service.get_record_by_id(db, auth.organization_id, record_id)
        if record is None:
            raise HTTPException(status_code=404, detail="agent record not found")
        return _record_response(record)

    @app.get("/v1/agent-records/by-did/{did:path}", response_model=AgentRecordResponse)
    def get_agent_record_by_did(
        did: str,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_auth),
    ):
        record = service.get_record_by_did(db, auth.organization_id, did)
        if record is None:
            raise HTTPException(status_code=404, detail="agent record not found")
        return _record_response(record)

    @app.get("/v1/audit-events", response_model=list[AuditEventResponse])
    def list_audit_events(
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_auth),
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

    @app.post("/v1/agent-records/{record_id}/deprovision", response_model=AgentRecordResponse)
    def deprovision_agent_record(
        record_id: str,
        payload: DeprovisionRequest,
        db: Annotated[Session, Depends(get_db)],
        auth=Depends(require_auth),
    ):
        record = service.deprovision_record(
            db,
            auth.organization_id,
            auth.actor_label,
            record_id=record_id,
            reason=payload.reason,
        )
        if record is None:
            raise HTTPException(status_code=404, detail="agent record not found")
        return _record_response(record)

    return app


app = create_app()
