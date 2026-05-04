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

class InfoUrls(BaseModel):
    model_config = ConfigDict(extra="forbid")

    marketing: str | None = None
    support: str | None = None
    terms_of_service: str | None = None
    privacy: str | None = None


class BlueprintCredentialWrite(BaseModel):
    model_config = ConfigDict(extra="allow")

    credential_id: str | None = Field(default=None, min_length=1, max_length=255)
    credential_type: str = Field(pattern=r"^(federated_identity|key|certificate|password|managed_identity)$")
    display_name: str = Field(min_length=1, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime | None = None
    rotation_status: str = Field(default="current", pattern=r"^(current|rotation_due|rotating|rotated|expired|revoked)$")
    last_rotated_at: datetime | None = None
    development_only: bool = False


class BlueprintCredentialResponse(BlueprintCredentialWrite):
    id: str
    organization_id: str
    blueprint_id: str
    production_warning: str | None = None
    created_at: datetime
    deleted_at: datetime | None = None


class PermissionGrant(BaseModel):
    model_config = ConfigDict(extra="allow")

    resource_app_id: str = Field(min_length=1, max_length=255)
    scopes: list[str] = Field(default_factory=list)
    app_roles: list[str] = Field(default_factory=list)


class PermissionModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    required_resource_access: list[PermissionGrant] = Field(default_factory=list)
    inheritable_permissions: list[PermissionGrant] = Field(default_factory=list)
    consent_grants: list[PermissionGrant] = Field(default_factory=list)
    direct_agent_grants: list[PermissionGrant] = Field(default_factory=list)
    denied_permissions: list[PermissionGrant] = Field(default_factory=list)


class EffectivePermissionsResponse(BaseModel):
    blueprint_id: str
    inherited_blueprint_grants: list[PermissionGrant]
    direct_agent_grants: list[PermissionGrant]
    denied_permissions: list[PermissionGrant]
    effective_permissions: list[PermissionGrant]


class BlueprintPrincipalWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=255)
    principal_id: str = Field(min_length=1, max_length=255)
    app_id: str = Field(min_length=1, max_length=255)
    client_id: str | None = Field(default=None, min_length=1, max_length=255)


class BlueprintPrincipalResponse(BlueprintPrincipalWrite):
    id: str
    organization_id: str
    blueprint_id: str
    created_at: datetime
    deleted_at: datetime | None = None


class AgentIdentityBlueprintWrite(BaseModel):
    model_config = ConfigDict(extra="allow")

    blueprint_id: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    description: str = ""
    publisher: str = Field(min_length=1, max_length=255)
    verified_publisher: bool = False
    publisher_domain: str | None = Field(default=None, max_length=255)
    sign_in_audience: str = Field(default="single_tenant", pattern=r"^(single_tenant|multi_tenant|personal_accounts|multi_tenant_and_personal)$")
    identifier_uris: list[str] = Field(default_factory=list)
    app_roles: list[dict[str, Any]] = Field(default_factory=list)
    optional_claims: dict[str, Any] = Field(default_factory=dict)
    group_membership_claims: list[str] = Field(default_factory=list)
    token_encryption_key_id: str | None = None
    certification: dict[str, Any] = Field(default_factory=dict)
    info_urls: InfoUrls = Field(default_factory=InfoUrls)
    tags: list[str] = Field(default_factory=list)
    status: str = Field(default="active", pattern=r"^(active|disabled|deleted)$")
    credentials: list[BlueprintCredentialWrite] = Field(default_factory=list)
    permissions: PermissionModel = Field(default_factory=PermissionModel)
    owners: list[str] = Field(default_factory=list)
    sponsors: list[str] = Field(default_factory=list)
    extension_fields: dict[str, Any] = Field(default_factory=dict)


class AgentIdentityBlueprintPatch(BaseModel):
    model_config = ConfigDict(extra="allow")

    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    publisher: str | None = Field(default=None, min_length=1, max_length=255)
    verified_publisher: bool | None = None
    publisher_domain: str | None = Field(default=None, max_length=255)
    sign_in_audience: str | None = Field(default=None, pattern=r"^(single_tenant|multi_tenant|personal_accounts|multi_tenant_and_personal)$")
    identifier_uris: list[str] | None = None
    app_roles: list[dict[str, Any]] | None = None
    optional_claims: dict[str, Any] | None = None
    group_membership_claims: list[str] | None = None
    token_encryption_key_id: str | None = None
    certification: dict[str, Any] | None = None
    info_urls: InfoUrls | None = None
    tags: list[str] | None = None
    status: str | None = Field(default=None, pattern=r"^(active|disabled|deleted)$")
    permissions: PermissionModel | None = None
    owners: list[str] | None = None
    sponsors: list[str] | None = None
    extension_fields: dict[str, Any] | None = None


class AgentIdentityBlueprintResponse(AgentIdentityBlueprintWrite):
    id: str
    organization_id: str
    created_at: datetime
    updated_at: datetime


class BlueprintPolicyActionResponse(BaseModel):
    blueprint_id: str
    status: str
    affected_agent_record_ids: list[str] = Field(default_factory=list)
    exported_inventory: list[dict[str, Any]] | None = None
