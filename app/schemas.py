from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class OrganizationBootstrapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_name: str = Field(min_length=2, max_length=255)
    organization_slug: str = Field(min_length=2, max_length=120, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    api_key_label: str = Field(default="bootstrap-admin", min_length=2, max_length=255)


class BootstrapResponse(BaseModel):
    organization_id: str
    organization_slug: str
    api_key: str


class OrganizationResponse(BaseModel):
    id: str
    name: str
    slug: str
    created_at: datetime


class IdentityProviderConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str = Field(min_length=2, max_length=255)
    issuer: str | None = Field(default=None, min_length=3, max_length=512)
    entity_id: str | None = Field(default=None, min_length=3, max_length=512)
    login_url: str | None = Field(default=None, min_length=3, max_length=1024)
    callback_url: str | None = Field(default=None, min_length=3, max_length=1024)
    client_id: str | None = Field(default=None, min_length=2, max_length=255)
    client_secret: str | None = Field(default=None, min_length=2, max_length=4096)
    metadata: dict[str, Any] = Field(default_factory=dict)
    default_role: str = Field(default="reader", pattern=r"^(admin|writer|reader)$")


class IdentityProviderConfigResponse(BaseModel):
    id: str
    provider_type: str
    enabled: bool
    display_name: str
    issuer: str | None
    entity_id: str | None
    login_url: str | None
    callback_url: str | None
    client_id: str | None
    metadata: dict[str, Any]
    default_role: str
    created_at: datetime
    updated_at: datetime


class OidcStartResponse(BaseModel):
    organization_slug: str
    authorization_url: str


class OidcCallbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=2, max_length=255)
    email: str | None = Field(default=None, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    role: str | None = Field(default=None, pattern=r"^(admin|writer|reader)$")
    claims: dict[str, Any] = Field(default_factory=dict)


class SamlAssertionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    saml_response: str = Field(min_length=10)
    role: str | None = Field(default=None, pattern=r"^(admin|writer|reader)$")


class SessionAuthResponse(BaseModel):
    access_token: str
    expires_at: datetime
    organization_id: str
    organization_slug: str
    subject: str
    email: str | None
    display_name: str | None
    role: str
    provider_type: str


class AuthorizationTupleWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=2, max_length=255)
    relation: str = Field(pattern=r"^(viewer|editor|owner)$")
    object_type: str = Field(pattern=r"^(agent_record)$")
    object_id: str = Field(min_length=1, max_length=255)


class AuthorizationTupleResponse(BaseModel):
    id: str
    subject: str
    relation: str
    object_type: str
    object_id: str
    created_at: datetime


class AuthorizationCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=2, max_length=255)
    relation: str = Field(pattern=r"^(viewer|editor|owner)$")
    object_type: str = Field(pattern=r"^(agent_record)$")
    object_id: str = Field(min_length=1, max_length=255)


class AuthorizationCheckResponse(BaseModel):
    allowed: bool


class ApiKeySummary(BaseModel):
    id: str
    label: str
    key_prefix: str
    last_four: str
    role: str
    is_active: bool
    created_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None


class ApiKeyCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=2, max_length=255)
    role: str = Field(pattern=r"^(admin|writer|reader)$")


class ApiKeyCreateResponse(BaseModel):
    id: str
    label: str
    role: str
    api_key: str
    key_prefix: str
    last_four: str
    created_at: datetime


class ApiKeyRevokeResponse(BaseModel):
    id: str
    is_active: bool
    revoked_at: datetime | None


class AgentRecordWrite(BaseModel):
    model_config = ConfigDict(extra="allow")

    agent_id_protocol_version: str
    agent: dict[str, Any]
    authorization: dict[str, Any]
    governance: dict[str, Any]
    bindings: dict[str, Any]
    extensions: dict[str, Any] = Field(default_factory=dict)


class AgentRecordResponse(BaseModel):
    id: str
    organization_id: str
    did: str
    display_name: str
    status: str
    lifecycle_state: str = "active"
    environment: str
    protocol_version: str
    record: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    deprovisioned_at: datetime | None


class AuditEventResponse(BaseModel):
    id: int
    actor_label: str
    action: str
    reason: str | None
    metadata: dict[str, Any]
    created_at: datetime


class DeprovisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=1000)


class AuthContext(BaseModel):
    organization_id: str
    organization_slug: str
    api_key_id: str | None = None
    session_id: str | None = None
    subject: str | None = None
    actor_label: str
    role: str
    auth_type: str


class ServiceInfoResponse(BaseModel):
    service: str
    version: str
    database_url_scheme: str
    schema_revision: str
    rate_limit_requests: int
    rate_limit_window_seconds: int


class LifecycleRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    reason: str | None = Field(default=None, max_length=1000)
    ticket_id: str | None = Field(default=None, max_length=255)
    requested_by: str | None = Field(default=None, max_length=255)
    approved_by: str | None = Field(default=None, max_length=255)
    effective_at: datetime | None = None
    expires_at: datetime | None = None
    force: bool = False
    dry_run: bool = False
    idempotency_key: str | None = Field(default=None, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)


class LifecycleValidationReportResponse(BaseModel):
    passed: bool
    failed: list[str]
    warnings: list[str]
    blocking_issues: list[str]
    recommended_actions: list[str]


class LifecycleTransitionResponse(BaseModel):
    subject_type: str
    subject_id: str
    previous_state: str | None
    new_state: str | None
    dry_run: bool = False
    validation_report: LifecycleValidationReportResponse | None = None
    audit_event_id: str | None = None
    deprovisioning_report: dict[str, Any] | None = None


class LifecycleAuditEventResponse(BaseModel):
    event_id: str
    event_type: str
    subject_type: str
    subject_id: str
    previous_state: str | None
    new_state: str | None
    actor_type: str
    actor_id: str
    requested_by: str | None
    approved_by: str | None
    reason: str | None
    ticket_id: str | None
    policy_id: str | None
    correlation_id: str | None
    idempotency_key: str | None
    timestamp: datetime
    evidence_hash: str
    metadata: dict[str, Any]


class BlueprintLifecycleResponse(BaseModel):
    id: str
    organization_id: str
    lifecycle_state: str
    metadata: dict[str, Any]
    updated_at: datetime



class AgentIdentityBlueprintWrite(BaseModel):
    model_config = ConfigDict(extra="allow")

    blueprint_id: str
    display_name: str
    description: str = ""
    publisher: str
    verified_publisher: bool = False
    publisher_domain: str | None = None
    sign_in_audience: str = "single_tenant"
    identifier_uris_json: list = Field(default_factory=list)
    app_roles_json: list = Field(default_factory=list)
    optional_claims_json: dict = Field(default_factory=dict)
    group_membership_claims_json: list = Field(default_factory=list)
    token_encryption_key_id: str | None = None
    certification_json: dict = Field(default_factory=dict)
    info_urls_json: dict = Field(default_factory=dict)
    tags_json: list = Field(default_factory=list)
    status: str = "active"
    extension_fields_json: dict = Field(default_factory=dict)


class AgentIdentityBlueprintPatch(BaseModel):
    model_config = ConfigDict(extra="allow")

    display_name: str | None = None
    description: str | None = None
    publisher: str | None = None
    verified_publisher: bool | None = None
    publisher_domain: str | None = None
    sign_in_audience: str | None = None
    identifier_uris_json: list | None = None
    app_roles_json: list | None = None
    optional_claims_json: dict | None = None
    group_membership_claims_json: list | None = None
    token_encryption_key_id: str | None = None
    certification_json: dict | None = None
    info_urls_json: dict | None = None
    tags_json: list | None = None
    extension_fields_json: dict | None = None


class AgentIdentityBlueprintResponse(BaseModel):
    id: str
    organization_id: str
    blueprint_id: str
    display_name: str
    description: str
    publisher: str
    verified_publisher: bool
    publisher_domain: str | None
    sign_in_audience: str
    identifier_uris_json: list
    app_roles_json: list
    optional_claims_json: dict
    group_membership_claims_json: list
    token_encryption_key_id: str | None
    certification_json: dict
    info_urls_json: dict
    tags_json: list
    status: str
    extension_fields_json: dict
    created_at: datetime
    updated_at: datetime


class BlueprintPrincipalWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    principal_id: str
    app_id: str
    client_id: str | None = None


class BlueprintPrincipalResponse(BaseModel):
    id: str
    organization_id: str
    tenant_id: str
    blueprint_id: str
    principal_id: str
    app_id: str
    client_id: str | None
    created_at: datetime
    deleted_at: datetime | None


class BlueprintCredentialWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_id: str
    credential_type: str
    display_name: str
    metadata_json: dict = Field(default_factory=dict)
    expires_at: datetime | None = None
    development_only: bool = False


class BlueprintCredentialResponse(BaseModel):
    id: str
    organization_id: str
    blueprint_id: str
    credential_id: str
    credential_type: str
    display_name: str
    metadata_json: dict
    expires_at: datetime | None
    rotation_status: str
    last_rotated_at: datetime | None
    development_only: bool
    production_warning: str | None
    created_at: datetime
    deleted_at: datetime | None


class BlueprintPolicyActionResponse(BaseModel):
    action: str
    blueprint_id: str
    success: bool
    message: str


class EffectivePermissionsResponse(BaseModel):
    blueprint_id: str
    permission_id: str
    display_name: str
    scope: str
    inheritable: bool
    owner_id: str | None
    sponsor_id: str | None
