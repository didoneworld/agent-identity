from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    agent_records: Mapped[list["AgentRecord"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    audit_events: Mapped[list["AuditEvent"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    identity_providers: Mapped[list["IdentityProviderConfig"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    sessions: Mapped[list["UserSession"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    authorization_tuples: Mapped[list["AuthorizationTuple"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    blueprints: Mapped[list["AgentIdentityBlueprint"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    last_four: Mapped[str] = mapped_column(String(4), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="admin", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped[Organization] = relationship(back_populates="api_keys")


class AgentRecord(Base):
    __tablename__ = "agent_records"
    __table_args__ = (UniqueConstraint("organization_id", "did", name="uq_agent_record_org_did"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    blueprint_id: Mapped[str | None] = mapped_column(ForeignKey("agent_identity_blueprints.blueprint_id"), index=True)
    did: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    environment: Mapped[str] = mapped_column(String(32), nullable=False)
    protocol_version: Mapped[str] = mapped_column(String(32), nullable=False)
    record_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    deprovisioned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped[Organization] = relationship(back_populates="agent_records")
    blueprint: Mapped["AgentIdentityBlueprint | None"] = relationship(back_populates="agent_records")
    audit_events: Mapped[list["AuditEvent"]] = relationship(back_populates="agent_record", cascade="all, delete-orphan")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    agent_record_id: Mapped[str | None] = mapped_column(ForeignKey("agent_records.id"), index=True)
    actor_label: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="audit_events")
    agent_record: Mapped[AgentRecord | None] = relationship(back_populates="audit_events")


class IdentityProviderConfig(Base):
    __tablename__ = "identity_provider_configs"
    __table_args__ = (UniqueConstraint("organization_id", "provider_type", name="uq_org_provider_type"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    provider_type: Mapped[str] = mapped_column(String(16), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    issuer: Mapped[str | None] = mapped_column(String(512))
    entity_id: Mapped[str | None] = mapped_column(String(512))
    login_url: Mapped[str | None] = mapped_column(String(1024))
    callback_url: Mapped[str | None] = mapped_column(String(1024))
    client_id: Mapped[str | None] = mapped_column(String(255))
    client_secret: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    default_role: Mapped[str] = mapped_column(String(32), default="reader", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="identity_providers")


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    provider_type: Mapped[str] = mapped_column(String(16), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    email: Mapped[str | None] = mapped_column(String(255))
    display_name: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="reader", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped[Organization] = relationship(back_populates="sessions")


class AuthorizationTuple(Base):
    __tablename__ = "authorization_tuples"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "subject",
            "relation",
            "object_type",
            "object_id",
            name="uq_fga_tuple",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    relation: Mapped[str] = mapped_column(String(64), nullable=False)
    object_type: Mapped[str] = mapped_column(String(64), nullable=False)
    object_id: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="authorization_tuples")


class AgentIdentityBlueprint(Base):
    __tablename__ = "agent_identity_blueprints"
    __table_args__ = (UniqueConstraint("organization_id", "blueprint_id", name="uq_org_blueprint_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    blueprint_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    publisher: Mapped[str] = mapped_column(String(255), nullable=False)
    verified_publisher: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    publisher_domain: Mapped[str | None] = mapped_column(String(255))
    sign_in_audience: Mapped[str] = mapped_column(String(64), default="single_tenant", nullable=False)
    identifier_uris_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    app_roles_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    optional_claims_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    group_membership_claims_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    token_encryption_key_id: Mapped[str | None] = mapped_column(String(255))
    certification_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    info_urls_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    tags_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    extension_fields_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), default="draft", nullable=False, index=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class LifecycleAuditEvent(Base):
    __tablename__ = "lifecycle_audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    agent_record_id: Mapped[str | None] = mapped_column(ForeignKey("agent_records.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    previous_state: Mapped[str | None] = mapped_column(String(32))
    new_state: Mapped[str | None] = mapped_column(String(32))
    actor_type: Mapped[str] = mapped_column(String(32), default="user", nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_by: Mapped[str | None] = mapped_column(String(255))
    approved_by: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str | None] = mapped_column(Text)
    ticket_id: Mapped[str | None] = mapped_column(String(255))
    policy_id: Mapped[str | None] = mapped_column(String(255))
    correlation_id: Mapped[str | None] = mapped_column(String(255), index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(255), index=True)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class LifecycleJsonRecord(Base):
    __tablename__ = "lifecycle_json_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    record_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="active", index=True)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


# Concrete lifecycle tables required by the lifecycle management contract. They intentionally
# use a common JSON payload shape so deployments can remain vendor-neutral and DID-first while
# evolving metadata without locking to one provider schema.
def _json_table(name: str):
    return type(
        name,
        (LifecycleJsonRecord,),
        {"__tablename__": name, "__mapper_args__": {"concrete": True}, "id": mapped_column(String(36), primary_key=True, default=lambda: str(uuid4())), "organization_id": mapped_column(ForeignKey("organizations.id"), nullable=False, index=True), "record_type": mapped_column(String(64), nullable=False, index=True), "subject_type": mapped_column(String(32), nullable=False, index=True), "subject_id": mapped_column(String(255), nullable=False, index=True), "status": mapped_column(String(64), nullable=False, default="active", index=True), "payload_json": mapped_column(JSON, default=dict, nullable=False), "created_at": mapped_column(DateTime(timezone=True), default=utc_now, nullable=False), "updated_at": mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)},
    )

LifecycleState = _json_table("lifecycle_states")
LifecycleTransition = _json_table("lifecycle_transitions")
LifecyclePolicy = _json_table("lifecycle_policies")
LifecyclePolicyBinding = _json_table("lifecycle_policy_bindings")
LifecycleValidationReport = _json_table("lifecycle_validation_reports")
CredentialLifecycleEvent = _json_table("credential_lifecycle_events")
PermissionLifecycleEvent = _json_table("permission_lifecycle_events")
SponsorLifecycleEvent = _json_table("sponsor_lifecycle_events")
OwnerLifecycleEvent = _json_table("owner_lifecycle_events")
DeprovisioningJob = _json_table("deprovisioning_jobs")
DeprovisioningStep = _json_table("deprovisioning_steps")
RenewalRequest = _json_table("renewal_requests")
RiskFinding = _json_table("risk_findings")
QuarantineRecord = _json_table("quarantine_records")
LifecycleWebhookSubscription = _json_table("lifecycle_webhook_subscriptions")
LifecycleWebhookDelivery = _json_table("lifecycle_webhook_deliveries")



# Additional models expected by services.py but missing after merge


class AgentDirectGrant(Base):
    __tablename__ = "agent_direct_grants"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    agent_record_id: Mapped[str] = mapped_column(ForeignKey("agent_records.id"), nullable=False, index=True)
    grant_type: Mapped[str] = mapped_column(String(32), nullable=False)
    principal_type: Mapped[str] = mapped_column(String(32), nullable=False)
    principal_id: Mapped[str] = mapped_column(String(255), nullable=False)
    scopes_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BlueprintConsentGrant(Base):
    __tablename__ = "blueprint_consent_grants"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    blueprint_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    consent_type: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    principal_id: Mapped[str] = mapped_column(String(255), nullable=False)
    scopes_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BlueprintOwner(Base):
    __tablename__ = "blueprint_owners"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    blueprint_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    owner_type: Mapped[str] = mapped_column(String(32), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class BlueprintSponsor(Base):
    __tablename__ = "blueprint_sponsors"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    blueprint_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    sponsor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    sponsor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


# More missing models from the full merged code


class BlueprintCredential(Base):
    __tablename__ = "blueprint_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    blueprint_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    credential_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    credential_type: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rotation_status: Mapped[str] = mapped_column(String(64), default="current", nullable=False)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    development_only: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    production_warning: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BlueprintRequiredResourceAccess(Base):
    __tablename__ = "blueprint_required_resource_access"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    blueprint_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    resource_app_id: Mapped[str] = mapped_column(String(255), nullable=False)
    scopes_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    app_roles_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)


class BlueprintInheritablePermission(Base):
    __tablename__ = "blueprint_inheritable_permissions"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    blueprint_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    permission_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[str] = mapped_column(String(64), nullable=False)
    inheritable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class BlueprintPrincipal(Base):
    __tablename__ = "blueprint_principals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    blueprint_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    principal_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    app_id: Mapped[str] = mapped_column(String(255), nullable=False)
    client_id: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
