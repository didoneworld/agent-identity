from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from jsonschema import Draft202012Validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db_models import (
    AgentRecord,
    AgentDirectGrant,
    AgentIdentityBlueprint,
    ApiKey,
    AuditEvent,
    AuthorizationTuple,
    BlueprintConsentGrant,
    BlueprintCredential,
    BlueprintInheritablePermission,
    BlueprintOwner,
    BlueprintPrincipal,
    BlueprintRequiredResourceAccess,
    BlueprintSponsor,

    IdentityProviderConfig,
    Organization,
    UserSession,
    utc_now,
)
from app.schemas import AgentIdentityBlueprintPatch, AgentIdentityBlueprintWrite, AgentRecordWrite, AuthContext, BlueprintCredentialWrite, BlueprintPrincipalWrite
from app.security import create_session_token, generate_api_key, hash_api_key, verify_session_token
from app.lifecycle import LifecycleServiceMixin


class ProtocolValidationError(Exception):
    pass


class BootstrapConflictError(Exception):
    pass


class AuthorizationError(Exception):
    pass


API_KEY_ROLES = {"admin", "writer", "reader"}
PROVIDER_TYPES = {"oidc", "saml"}
RELATION_PERMISSIONS = {
    "viewer": {"read"},
    "editor": {"read", "write"},
    "owner": {"read", "write", "deprovision", "manage_fga"},
}


def _as_utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=utc_now().tzinfo)
    return value


class SaaSService(LifecycleServiceMixin):
    def __init__(self, schema_path: Path) -> None:
        schema = json.loads(schema_path.read_text())
        self.validator = Draft202012Validator(schema)

    def validate_record(self, record: dict[str, Any]) -> None:
        try:
            self.validator.validate(record)
        except Exception as exc:  # jsonschema ValidationError
            raise ProtocolValidationError(str(exc)) from exc

    def bootstrap_organization(self, db: Session, name: str, slug: str, api_key_label: str) -> tuple[Organization, str]:
        if db.scalar(select(Organization.id).limit(1)) is not None:
            raise BootstrapConflictError("bootstrap has already been completed")

        organization = Organization(name=name, slug=slug)
        raw_key = generate_api_key()
        api_key = ApiKey(
            organization=organization,
            label=api_key_label,
            key_hash=hash_api_key(raw_key),
            key_prefix=raw_key[:12],
            last_four=raw_key[-4:],
            role="admin",
        )
        db.add_all([organization, api_key])
        db.flush()
        self._audit(db, organization_id=organization.id, actor_label="bootstrap", action="organization_bootstrapped")
        db.commit()
        db.refresh(organization)
        return organization, raw_key

    def authenticate(self, db: Session, raw_key: str) -> AuthContext | None:
        hashed = hash_api_key(raw_key)
        api_key = db.scalar(select(ApiKey).where(ApiKey.key_hash == hashed, ApiKey.is_active.is_(True)))
        if api_key is None:
            return None
        organization = db.scalar(select(Organization).where(Organization.id == api_key.organization_id))
        if organization is None:
            return None
        api_key.last_used_at = utc_now()
        db.commit()
        return AuthContext(
            organization_id=api_key.organization_id,
            organization_slug=organization.slug,
            api_key_id=api_key.id,
            actor_label=f"api-key:{api_key.label}",
            role=api_key.role,
            auth_type="api_key",
        )

    def authenticate_session(self, db: Session, bearer_token: str) -> AuthContext | None:
        payload = verify_session_token(bearer_token, settings.session_signing_secret)
        if payload is None:
            return None

        session_id = payload.get("session_id")
        if not session_id:
            return None
        session = db.scalar(select(UserSession).where(UserSession.id == session_id, UserSession.is_active.is_(True)))
        if session is None or _as_utc(session.expires_at) < utc_now():
            return None
        organization = db.scalar(select(Organization).where(Organization.id == session.organization_id))
        if organization is None:
            return None
        session.last_used_at = utc_now()
        db.commit()
        return AuthContext(
            organization_id=session.organization_id,
            organization_slug=organization.slug,
            session_id=session.id,
            subject=session.subject,
            actor_label=f"session:{session.subject}",
            role=session.role,
            auth_type="session",
        )

    def list_organizations(self, db: Session, organization_id: str) -> list[Organization]:
        return list(db.scalars(select(Organization).where(Organization.id == organization_id)))

    def list_api_keys(self, db: Session, organization_id: str) -> list[ApiKey]:
        return list(db.scalars(select(ApiKey).where(ApiKey.organization_id == organization_id).order_by(ApiKey.created_at)))

    def get_organization_by_slug(self, db: Session, slug: str) -> Organization | None:
        return db.scalar(select(Organization).where(Organization.slug == slug))

    def upsert_identity_provider(
        self,
        db: Session,
        organization_id: str,
        actor_label: str,
        provider_type: str,
        payload: dict[str, Any],
    ) -> IdentityProviderConfig:
        if provider_type not in PROVIDER_TYPES:
            raise AuthorizationError("invalid provider type")
        existing = db.scalar(
            select(IdentityProviderConfig).where(
                IdentityProviderConfig.organization_id == organization_id,
                IdentityProviderConfig.provider_type == provider_type,
            )
        )
        now = utc_now()
        if existing is None:
            existing = IdentityProviderConfig(
                organization_id=organization_id,
                provider_type=provider_type,
                created_at=now,
                updated_at=now,
            )
            db.add(existing)
        existing.enabled = True
        existing.display_name = payload["display_name"]
        existing.issuer = payload.get("issuer")
        existing.entity_id = payload.get("entity_id")
        existing.login_url = payload.get("login_url")
        existing.callback_url = payload.get("callback_url")
        existing.client_id = payload.get("client_id")
        existing.client_secret = payload.get("client_secret")
        existing.metadata_json = payload.get("metadata", {})
        existing.default_role = payload.get("default_role", "reader")
        existing.updated_at = now
        db.flush()
        self._audit(
            db,
            organization_id=organization_id,
            actor_label=actor_label,
            action="identity_provider_upserted",
            metadata={"provider_type": provider_type, "display_name": existing.display_name},
        )
        db.commit()
        db.refresh(existing)
        return existing

    def list_identity_providers(self, db: Session, organization_id: str) -> list[IdentityProviderConfig]:
        stmt = (
            select(IdentityProviderConfig)
            .where(IdentityProviderConfig.organization_id == organization_id)
            .order_by(IdentityProviderConfig.provider_type)
        )
        return list(db.scalars(stmt))

    def get_identity_provider(
        self,
        db: Session,
        organization_id: str,
        provider_type: str,
    ) -> IdentityProviderConfig | None:
        return db.scalar(
            select(IdentityProviderConfig).where(
                IdentityProviderConfig.organization_id == organization_id,
                IdentityProviderConfig.provider_type == provider_type,
                IdentityProviderConfig.enabled.is_(True),
            )
        )

    def build_oidc_authorization_url(self, organization: Organization, provider: IdentityProviderConfig) -> str:
        return (
            f"{provider.login_url}?client_id={provider.client_id}"
            f"&response_type=code&scope=openid%20profile%20email"
            f"&redirect_uri={provider.callback_url}&state={organization.slug}"
        )

    def create_oidc_session(
        self,
        db: Session,
        organization: Organization,
        provider: IdentityProviderConfig,
        actor_label: str,
        subject: str,
        email: str | None,
        display_name: str | None,
        role: str | None,
        claims: dict[str, Any] | None = None,
    ) -> tuple[UserSession, str]:
        resolved_role = role or provider.default_role
        return self._create_session(
            db,
            organization=organization,
            provider_type="oidc",
            actor_label=actor_label,
            subject=subject,
            email=email,
            display_name=display_name,
            role=resolved_role,
            claims=claims or {},
        )

    def create_saml_session(
        self,
        db: Session,
        organization: Organization,
        provider: IdentityProviderConfig,
        actor_label: str,
        saml_response: str,
        role: str | None,
    ) -> tuple[UserSession, str]:
        subject, email, display_name, parsed_claims = self._parse_saml_response(saml_response)
        resolved_role = role or provider.default_role
        return self._create_session(
            db,
            organization=organization,
            provider_type="saml",
            actor_label=actor_label,
            subject=subject,
            email=email,
            display_name=display_name,
            role=resolved_role,
            claims=parsed_claims,
        )

    def create_api_key(
        self,
        db: Session,
        organization_id: str,
        actor_label: str,
        label: str,
        role: str,
    ) -> tuple[ApiKey, str]:
        if role not in API_KEY_ROLES:
            raise AuthorizationError("invalid api key role")
        raw_key = generate_api_key()
        api_key = ApiKey(
            organization_id=organization_id,
            label=label,
            role=role,
            key_hash=hash_api_key(raw_key),
            key_prefix=raw_key[:12],
            last_four=raw_key[-4:],
        )
        db.add(api_key)
        db.flush()
        self._audit(
            db,
            organization_id=organization_id,
            actor_label=actor_label,
            action="api_key_created",
            metadata={"api_key_id": api_key.id, "label": label, "role": role},
        )
        db.commit()
        db.refresh(api_key)
        return api_key, raw_key

    def list_authorization_tuples(
        self,
        db: Session,
        organization_id: str,
        object_type: str | None = None,
        object_id: str | None = None,
    ) -> list[AuthorizationTuple]:
        stmt = select(AuthorizationTuple).where(AuthorizationTuple.organization_id == organization_id)
        if object_type is not None:
            stmt = stmt.where(AuthorizationTuple.object_type == object_type)
        if object_id is not None:
            stmt = stmt.where(AuthorizationTuple.object_id == object_id)
        stmt = stmt.order_by(AuthorizationTuple.created_at)
        return list(db.scalars(stmt))

    def create_authorization_tuple(
        self,
        db: Session,
        organization_id: str,
        actor_label: str,
        subject: str,
        relation: str,
        object_type: str,
        object_id: str,
    ) -> AuthorizationTuple:
        existing = db.scalar(
            select(AuthorizationTuple).where(
                AuthorizationTuple.organization_id == organization_id,
                AuthorizationTuple.subject == subject,
                AuthorizationTuple.relation == relation,
                AuthorizationTuple.object_type == object_type,
                AuthorizationTuple.object_id == object_id,
            )
        )
        if existing is not None:
            return existing
        auth_tuple = AuthorizationTuple(
            organization_id=organization_id,
            subject=subject,
            relation=relation,
            object_type=object_type,
            object_id=object_id,
        )
        db.add(auth_tuple)
        db.flush()
        self._audit(
            db,
            organization_id=organization_id,
            actor_label=actor_label,
            action="authorization_tuple_created",
            metadata={
                "subject": subject,
                "relation": relation,
                "object_type": object_type,
                "object_id": object_id,
            },
        )
        db.commit()
        db.refresh(auth_tuple)
        return auth_tuple

    def check_authorization_tuple(
        self,
        db: Session,
        organization_id: str,
        subject: str,
        relation: str,
        object_type: str,
        object_id: str,
    ) -> bool:
        return (
            db.scalar(
                select(AuthorizationTuple.id).where(
                    AuthorizationTuple.organization_id == organization_id,
                    AuthorizationTuple.subject == subject,
                    AuthorizationTuple.relation == relation,
                    AuthorizationTuple.object_type == object_type,
                    AuthorizationTuple.object_id == object_id,
                )
            )
            is not None
        )

    def ensure_record_permission(
        self,
        db: Session,
        auth: AuthContext,
        record: AgentRecord,
        action: str,
    ) -> None:
        role_permissions = {
            "reader": {"read"},
            "writer": {"read", "write"},
            "admin": {"read", "write", "deprovision", "manage_fga"},
        }
        requires_tuple = auth.auth_type == "session" and auth.role == "reader" and action == "read"
        if not requires_tuple and action in role_permissions.get(auth.role, set()):
            return
        if auth.subject is None:
            raise AuthorizationError("insufficient permission")

        tuples = list(
            db.scalars(
                select(AuthorizationTuple).where(
                    AuthorizationTuple.organization_id == auth.organization_id,
                    AuthorizationTuple.subject == auth.subject,
                    AuthorizationTuple.object_type == "agent_record",
                    AuthorizationTuple.object_id == record.id,
                )
            )
        )
        for auth_tuple in tuples:
            if action in RELATION_PERMISSIONS.get(auth_tuple.relation, set()):
                return
        raise AuthorizationError("insufficient permission")

    def revoke_api_key(
        self,
        db: Session,
        organization_id: str,
        actor_label: str,
        api_key_id: str,
    ) -> ApiKey | None:
        api_key = db.scalar(
            select(ApiKey).where(ApiKey.organization_id == organization_id, ApiKey.id == api_key_id)
        )
        if api_key is None:
            return None
        api_key.is_active = False
        api_key.revoked_at = utc_now()
        self._audit(
            db,
            organization_id=organization_id,
            actor_label=actor_label,
            action="api_key_revoked",
            metadata={"api_key_id": api_key.id, "label": api_key.label, "role": api_key.role},
        )
        db.commit()
        db.refresh(api_key)
        return api_key

    def _blueprint_payload(self, blueprint: AgentIdentityBlueprint) -> dict[str, Any]:
        return {
            "blueprint_id": blueprint.blueprint_id,
            "display_name": blueprint.display_name,
            "description": blueprint.description,
            "publisher": blueprint.publisher,
            "verified_publisher": blueprint.verified_publisher,
            "publisher_domain": blueprint.publisher_domain,
            "sign_in_audience": blueprint.sign_in_audience,
            "identifier_uris": blueprint.identifier_uris_json or [],
            "app_roles": blueprint.app_roles_json or [],
            "optional_claims": blueprint.optional_claims_json or {},
            "group_membership_claims": blueprint.group_membership_claims_json or [],
            "token_encryption_key_id": blueprint.token_encryption_key_id,
            "certification": blueprint.certification_json or {},
            "info_urls": blueprint.info_urls_json or {},
            "tags": blueprint.tags_json or [],
            "status": blueprint.status,
            "credentials": [self._credential_payload(c) for c in blueprint.credentials if c.deleted_at is None],
            "permissions": self._permission_payload(None, blueprint.organization_id, blueprint.blueprint_id),
            "owners": [o.subject for o in self._owners_for_blueprint(blueprint.organization_id, blueprint.blueprint_id)],
            "sponsors": [s.subject for s in self._sponsors_for_blueprint(blueprint.organization_id, blueprint.blueprint_id)],
            "extension_fields": blueprint.extension_fields_json or {},
            "id": blueprint.id,
            "organization_id": blueprint.organization_id,
            "created_at": blueprint.created_at,
            "updated_at": blueprint.updated_at,
        }

    def _credential_payload(self, credential: BlueprintCredential) -> dict[str, Any]:
        return {
            "id": credential.id,
            "organization_id": credential.organization_id,
            "blueprint_id": credential.blueprint_id,
            "credential_id": credential.credential_id,
            "credential_type": credential.credential_type,
            "display_name": credential.display_name,
            "metadata": credential.metadata_json or {},
            "expires_at": credential.expires_at,
            "rotation_status": credential.rotation_status,
            "last_rotated_at": credential.last_rotated_at,
            "development_only": credential.development_only,
            "production_warning": credential.production_warning,
            "created_at": credential.created_at,
            "deleted_at": credential.deleted_at,
        }

    def _owners_for_blueprint(self, organization_id: str, blueprint_id: str) -> list[BlueprintOwner]:
        return []

    def _sponsors_for_blueprint(self, organization_id: str, blueprint_id: str) -> list[BlueprintSponsor]:
        return []

    def get_blueprint(self, db: Session, organization_id: str, blueprint_id: str) -> AgentIdentityBlueprint | None:
        return db.scalar(select(AgentIdentityBlueprint).where(AgentIdentityBlueprint.organization_id == organization_id, AgentIdentityBlueprint.blueprint_id == blueprint_id))

    def list_blueprints(self, db: Session, organization_id: str) -> list[AgentIdentityBlueprint]:
        return list(db.scalars(select(AgentIdentityBlueprint).where(AgentIdentityBlueprint.organization_id == organization_id).order_by(AgentIdentityBlueprint.created_at)))

    def create_blueprint(self, db: Session, organization_id: str, actor_label: str, payload: AgentIdentityBlueprintWrite) -> AgentIdentityBlueprint:
        if self.get_blueprint(db, organization_id, payload.blueprint_id):
            raise ProtocolValidationError("blueprint_id already exists")
        now = utc_now()
        blueprint = AgentIdentityBlueprint(
            organization_id=organization_id,
            blueprint_id=payload.blueprint_id,
            display_name=payload.display_name,
            description=payload.description,
            publisher=payload.publisher,
            verified_publisher=payload.verified_publisher,
            publisher_domain=payload.publisher_domain,
            sign_in_audience=payload.sign_in_audience,
            identifier_uris_json=payload.identifier_uris,
            app_roles_json=payload.app_roles,
            optional_claims_json=payload.optional_claims,
            group_membership_claims_json=payload.group_membership_claims,
            token_encryption_key_id=payload.token_encryption_key_id,
            certification_json=payload.certification,
            info_urls_json=payload.info_urls.model_dump(),
            tags_json=payload.tags,
            status=payload.status,
            extension_fields_json=payload.extension_fields,
            created_at=now,
            updated_at=now,
        )
        db.add(blueprint)
        db.flush()
        self._replace_permissions(db, organization_id, payload.blueprint_id, payload.permissions.model_dump())
        self._replace_people(db, organization_id, payload.blueprint_id, payload.owners, payload.sponsors)
        for credential in payload.credentials:
            self.add_blueprint_credential(db, organization_id, actor_label, payload.blueprint_id, credential, commit=False)
        self._audit(db, organization_id=organization_id, actor_label=actor_label, action="blueprint_created", metadata={"blueprint_id": payload.blueprint_id, "owners": payload.owners, "sponsors": payload.sponsors})
        db.commit(); db.refresh(blueprint)
        return blueprint

    def update_blueprint(self, db: Session, organization_id: str, actor_label: str, blueprint_id: str, payload: AgentIdentityBlueprintPatch) -> AgentIdentityBlueprint | None:
        blueprint = self.get_blueprint(db, organization_id, blueprint_id)
        if blueprint is None:
            return None
        data = payload.model_dump(exclude_unset=True)
        scalar_map = {"display_name":"display_name","description":"description","publisher":"publisher","verified_publisher":"verified_publisher","publisher_domain":"publisher_domain","sign_in_audience":"sign_in_audience","token_encryption_key_id":"token_encryption_key_id","status":"status"}
        for key, attr in scalar_map.items():
            if key in data:
                setattr(blueprint, attr, data[key])
        json_map = {"identifier_uris":"identifier_uris_json","app_roles":"app_roles_json","optional_claims":"optional_claims_json","group_membership_claims":"group_membership_claims_json","certification":"certification_json","tags":"tags_json","extension_fields":"extension_fields_json"}
        for key, attr in json_map.items():
            if key in data:
                setattr(blueprint, attr, data[key])
        if "info_urls" in data:
            blueprint.info_urls_json = data["info_urls"] or {}
        if "permissions" in data and data["permissions"] is not None:
            self._replace_permissions(db, organization_id, blueprint_id, data["permissions"])
        if "owners" in data or "sponsors" in data:
            owners = data.get("owners", [o.subject for o in db.scalars(select(BlueprintOwner).where(BlueprintOwner.organization_id == organization_id, BlueprintOwner.blueprint_id == blueprint_id))])
            sponsors = data.get("sponsors", [s.subject for s in db.scalars(select(BlueprintSponsor).where(BlueprintSponsor.organization_id == organization_id, BlueprintSponsor.blueprint_id == blueprint_id))])
            self._replace_people(db, organization_id, blueprint_id, owners, sponsors)
        blueprint.updated_at = utc_now()
        self._audit(db, organization_id=organization_id, actor_label=actor_label, action="blueprint_updated", metadata={"blueprint_id": blueprint_id})
        db.commit(); db.refresh(blueprint)
        return blueprint

    def delete_blueprint(self, db: Session, organization_id: str, actor_label: str, blueprint_id: str) -> AgentIdentityBlueprint | None:
        blueprint = self.get_blueprint(db, organization_id, blueprint_id)
        if blueprint is None: return None
        blueprint.status = "deleted"; blueprint.updated_at = utc_now()
        self._audit(db, organization_id=organization_id, actor_label=actor_label, action="blueprint_deleted", metadata={"blueprint_id": blueprint_id})
        db.commit(); db.refresh(blueprint); return blueprint

    def set_blueprint_status(self, db: Session, organization_id: str, actor_label: str, blueprint_id: str, enabled: bool) -> tuple[AgentIdentityBlueprint | None, list[str]]:
        blueprint = self.get_blueprint(db, organization_id, blueprint_id)
        if blueprint is None: return None, []
        blueprint.status = "active" if enabled else "disabled"; blueprint.updated_at = utc_now()
        affected=[]
        if not enabled:
            for record in self.list_records_by_blueprint(db, organization_id, blueprint_id):
                record.status = "disabled"; record.record_json.setdefault("agent", {})["status"] = "disabled"; record.updated_at = utc_now(); affected.append(record.id)
        self._audit(db, organization_id=organization_id, actor_label=actor_label, action="blueprint_enabled" if enabled else "blueprint_disabled", metadata={"blueprint_id": blueprint_id, "affected_agent_record_ids": affected})
        db.commit(); db.refresh(blueprint); return blueprint, affected

    def list_records_by_blueprint(self, db: Session, organization_id: str, blueprint_id: str) -> list[AgentRecord]:
        return list(db.scalars(select(AgentRecord).where(AgentRecord.organization_id == organization_id, AgentRecord.blueprint_id == blueprint_id).order_by(AgentRecord.created_at)))

    def create_record_from_blueprint(self, db: Session, organization_id: str, actor_label: str, blueprint_id: str, payload: AgentRecordWrite) -> AgentRecord:
        if self.get_blueprint(db, organization_id, blueprint_id) is None:
            raise ProtocolValidationError("blueprint not found")
        data = payload.model_dump()
        data["blueprint_id"] = blueprint_id
        data.setdefault("extensions", {})["blueprint_id"] = blueprint_id
        return self.upsert_record(db, organization_id, actor_label, AgentRecordWrite(**data))

    def add_blueprint_credential(self, db: Session, organization_id: str, actor_label: str, blueprint_id: str, payload: BlueprintCredentialWrite, commit: bool = True) -> BlueprintCredential:
        if self.get_blueprint(db, organization_id, blueprint_id) is None: raise ProtocolValidationError("blueprint not found")
        warning = None
        if payload.credential_type == "password":
            warning = "Password credentials are for development only and should not be used in production."
        credential = BlueprintCredential(organization_id=organization_id, blueprint_id=blueprint_id, credential_id=payload.credential_id or f"cred-{uuid4()}", credential_type=payload.credential_type, display_name=payload.display_name, metadata_json=payload.metadata, expires_at=payload.expires_at, rotation_status=payload.rotation_status, last_rotated_at=payload.last_rotated_at, development_only=payload.development_only, production_warning=warning)
        db.add(credential); db.flush()
        self._audit(db, organization_id=organization_id, actor_label=actor_label, action="blueprint_credential_added", metadata={"blueprint_id": blueprint_id, "credential_id": credential.credential_id, "production_warning": warning})
        if commit: db.commit(); db.refresh(credential)
        return credential

    def rotate_blueprint_credential(self, db: Session, organization_id: str, actor_label: str, blueprint_id: str, credential_id: str) -> BlueprintCredential | None:
        credential = db.scalar(select(BlueprintCredential).where(BlueprintCredential.organization_id == organization_id, BlueprintCredential.blueprint_id == blueprint_id, BlueprintCredential.credential_id == credential_id, BlueprintCredential.deleted_at.is_(None)))
        if credential is None: return None
        credential.rotation_status = "rotated"; credential.last_rotated_at = utc_now()
        self._audit(db, organization_id=organization_id, actor_label=actor_label, action="blueprint_credential_rotated", metadata={"blueprint_id": blueprint_id, "credential_id": credential_id})
        db.commit(); db.refresh(credential); return credential

    def delete_blueprint_credential(self, db: Session, organization_id: str, actor_label: str, blueprint_id: str, credential_id: str) -> BlueprintCredential | None:
        credential = db.scalar(select(BlueprintCredential).where(BlueprintCredential.organization_id == organization_id, BlueprintCredential.blueprint_id == blueprint_id, BlueprintCredential.credential_id == credential_id, BlueprintCredential.deleted_at.is_(None)))
        if credential is None: return None
        credential.deleted_at = utc_now(); credential.rotation_status = "revoked"
        self._audit(db, organization_id=organization_id, actor_label=actor_label, action="blueprint_credential_deleted", metadata={"blueprint_id": blueprint_id, "credential_id": credential_id})
        db.commit(); db.refresh(credential); return credential

    def create_blueprint_principal(self, db: Session, organization_id: str, actor_label: str, blueprint_id: str, payload: BlueprintPrincipalWrite) -> BlueprintPrincipal:
        if self.get_blueprint(db, organization_id, blueprint_id) is None: raise ProtocolValidationError("blueprint not found")
        principal = BlueprintPrincipal(organization_id=organization_id, blueprint_id=blueprint_id, tenant_id=payload.tenant_id, principal_id=payload.principal_id, app_id=payload.app_id, client_id=payload.client_id)
        db.add(principal); db.flush()
        self._audit(db, organization_id=organization_id, actor_label=f"blueprint-principal:{payload.principal_id}", action="blueprint_principal_provisioned", metadata={"blueprint_id": blueprint_id, "tenant_id": payload.tenant_id, "requested_by": actor_label})
        db.commit(); db.refresh(principal); return principal

    def delete_blueprint_principal(self, db: Session, organization_id: str, actor_label: str, blueprint_id: str, principal_id: str) -> BlueprintPrincipal | None:
        principal = db.scalar(select(BlueprintPrincipal).where(BlueprintPrincipal.organization_id == organization_id, BlueprintPrincipal.blueprint_id == blueprint_id, BlueprintPrincipal.principal_id == principal_id, BlueprintPrincipal.deleted_at.is_(None)))
        if principal is None: return None
        principal.deleted_at = utc_now()
        self._audit(db, organization_id=organization_id, actor_label=f"blueprint-principal:{principal.principal_id}", action="blueprint_principal_deprovisioned", metadata={"blueprint_id": blueprint_id, "tenant_id": principal.tenant_id, "requested_by": actor_label})
        db.commit(); db.refresh(principal); return principal

    def revoke_blueprint_permission_grant(self, db: Session, organization_id: str, actor_label: str, blueprint_id: str, resource_app_id: str, scopes: list[str] | None = None, app_roles: list[str] | None = None) -> dict[str, Any] | None:
        if self.get_blueprint(db, organization_id, blueprint_id) is None:
            return None
        grant = BlueprintConsentGrant(
            organization_id=organization_id,
            blueprint_id=blueprint_id,
            resource_app_id=resource_app_id,
            scopes_json=scopes or [],
            app_roles_json=app_roles or [],
            revoked=True,
        )
        db.add(grant)
        self._audit(db, organization_id=organization_id, actor_label=actor_label, action="blueprint_permission_grant_revoked", metadata={"blueprint_id": blueprint_id, "resource_app_id": resource_app_id, "scopes": scopes or [], "app_roles": app_roles or []})
        db.commit()
        return {"resource_app_id": resource_app_id, "scopes": scopes or [], "app_roles": app_roles or [], "revoked": True}

    def effective_permissions(self, db: Session, organization_id: str, blueprint_id: str, agent_record_id: str | None = None) -> dict[str, Any]:
        inherited = [self._grant_dict(g.resource_app_id, g.scopes_json, g.app_roles_json) for g in db.scalars(select(BlueprintInheritablePermission).where(BlueprintInheritablePermission.organization_id == organization_id, BlueprintInheritablePermission.blueprint_id == blueprint_id))]
        direct = []
        denied = []
        for g in db.scalars(select(BlueprintConsentGrant).where(BlueprintConsentGrant.organization_id == organization_id, BlueprintConsentGrant.blueprint_id == blueprint_id, BlueprintConsentGrant.revoked.is_(True))):
            denied.append(self._grant_dict(g.resource_app_id, g.scopes_json, g.app_roles_json))
        if agent_record_id:
            for g in db.scalars(select(AgentDirectGrant).where(AgentDirectGrant.organization_id == organization_id, AgentDirectGrant.agent_record_id == agent_record_id)):
                direct.append(self._grant_dict(g.resource_app_id, g.scopes_json, g.app_roles_json)); denied.append(self._grant_dict(g.resource_app_id, g.denied_json.get("scopes", []), g.denied_json.get("app_roles", [])))
        effective = self._merge_grants(inherited + direct, denied)
        return {"blueprint_id": blueprint_id, "inherited_blueprint_grants": inherited, "direct_agent_grants": direct, "denied_permissions": [d for d in denied if d["scopes"] or d["app_roles"]], "effective_permissions": effective}

    def _grant_dict(self, resource_app_id: str, scopes: list[str], app_roles: list[str]) -> dict[str, Any]:
        return {"resource_app_id": resource_app_id, "scopes": scopes or [], "app_roles": app_roles or []}

    def _merge_grants(self, grants: list[dict[str, Any]], denied: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_resource: dict[str, dict[str, set[str]]] = {}
        for grant in grants:
            entry = by_resource.setdefault(grant["resource_app_id"], {"scopes": set(), "app_roles": set()})
            entry["scopes"].update(grant.get("scopes", [])); entry["app_roles"].update(grant.get("app_roles", []))
        for deny in denied:
            entry = by_resource.setdefault(deny["resource_app_id"], {"scopes": set(), "app_roles": set()})
            entry["scopes"].difference_update(deny.get("scopes", [])); entry["app_roles"].difference_update(deny.get("app_roles", []))
        return [{"resource_app_id": r, "scopes": sorted(v["scopes"]), "app_roles": sorted(v["app_roles"])} for r, v in sorted(by_resource.items()) if v["scopes"] or v["app_roles"]]

    def _permission_payload(self, db: Session | None, organization_id: str, blueprint_id: str) -> dict[str, Any]:
        if db is None: return {"required_resource_access": [], "inheritable_permissions": [], "consent_grants": [], "direct_agent_grants": [], "denied_permissions": []}
        return {}

    def _replace_permissions(self, db: Session, organization_id: str, blueprint_id: str, permissions: dict[str, Any]) -> None:
        for model in (BlueprintRequiredResourceAccess, BlueprintInheritablePermission, BlueprintConsentGrant):
            for item in db.scalars(select(model).where(model.organization_id == organization_id, model.blueprint_id == blueprint_id)):
                db.delete(item)
        for key, model in (("required_resource_access", BlueprintRequiredResourceAccess), ("inheritable_permissions", BlueprintInheritablePermission), ("consent_grants", BlueprintConsentGrant)):
            for grant in permissions.get(key, []) or []:
                kwargs = dict(organization_id=organization_id, blueprint_id=blueprint_id, resource_app_id=grant["resource_app_id"], scopes_json=grant.get("scopes", []), app_roles_json=grant.get("app_roles", []))
                if model is BlueprintConsentGrant: kwargs["revoked"] = False
                db.add(model(**kwargs))

    def _replace_people(self, db: Session, organization_id: str, blueprint_id: str, owners: list[str], sponsors: list[str]) -> None:
        for model in (BlueprintOwner, BlueprintSponsor):
            for item in db.scalars(select(model).where(model.organization_id == organization_id, model.blueprint_id == blueprint_id)):
                db.delete(item)
        for owner in owners: db.add(BlueprintOwner(organization_id=organization_id, blueprint_id=blueprint_id, subject=owner, subject_type="group" if owner.startswith("group:") else "user"))
        for sponsor in sponsors: db.add(BlueprintSponsor(organization_id=organization_id, blueprint_id=blueprint_id, subject=sponsor, subject_type="group" if sponsor.startswith("group:") else "user"))

    def list_records(self, db: Session, organization_id: str) -> list[AgentRecord]:
        stmt = select(AgentRecord).where(AgentRecord.organization_id == organization_id).order_by(AgentRecord.created_at)
        return list(db.scalars(stmt))

    def get_record_by_id(self, db: Session, organization_id: str, record_id: str) -> AgentRecord | None:
        stmt = select(AgentRecord).where(AgentRecord.organization_id == organization_id, AgentRecord.id == record_id)
        return db.scalar(stmt)

    def get_record_by_did(self, db: Session, organization_id: str, did: str) -> AgentRecord | None:
        stmt = select(AgentRecord).where(AgentRecord.organization_id == organization_id, AgentRecord.did == did)
        return db.scalar(stmt)

    def upsert_record(
        self,
        db: Session,
        organization_id: str,
        actor_label: str,
        payload: AgentRecordWrite,
    ) -> AgentRecord:
        record = payload.model_dump()
        blueprint_id = record.get("blueprint_id") or record.get("agent", {}).get("blueprint_id") or record.get("extensions", {}).get("blueprint_id")
        if blueprint_id:
            blueprint = self.get_blueprint(db, organization_id, blueprint_id)
            if blueprint is None:
                raise ProtocolValidationError("blueprint not found")
            if blueprint.status == "deleted":
                raise ProtocolValidationError("blueprint is deleted")
            record["blueprint_id"] = blueprint_id
            record.setdefault("extensions", {})["blueprint_id"] = blueprint_id
            record["extensions"].setdefault("blueprint", {})
            inherited = record["extensions"]["blueprint"].setdefault("inherited_metadata", {})
            shared = {
                "display_name": blueprint.display_name,
                "publisher": blueprint.publisher,
                "verified_publisher": blueprint.verified_publisher,
                "publisher_domain": blueprint.publisher_domain,
                "sign_in_audience": blueprint.sign_in_audience,
                "identifier_uris": blueprint.identifier_uris_json or [],
                "app_roles": blueprint.app_roles_json or [],
                "optional_claims": blueprint.optional_claims_json or {},
                "group_membership_claims": blueprint.group_membership_claims_json or [],
                "token_encryption_key_id": blueprint.token_encryption_key_id,
                "certification": blueprint.certification_json or {},
                "info_urls": blueprint.info_urls_json or {},
                "tags": blueprint.tags_json or [],
            }
            for key, value in shared.items():
                inherited.setdefault(key, value)
            sponsors = [s.subject for s in db.scalars(select(BlueprintSponsor).where(BlueprintSponsor.organization_id == organization_id, BlueprintSponsor.blueprint_id == blueprint_id))]
            owners = [o.subject for o in db.scalars(select(BlueprintOwner).where(BlueprintOwner.organization_id == organization_id, BlueprintOwner.blueprint_id == blueprint_id))]
            record["extensions"]["blueprint"]["sponsors"] = record["extensions"]["blueprint"].get("sponsors", sponsors)
            record["extensions"]["blueprint"]["owners"] = record["extensions"]["blueprint"].get("owners", owners)
            if blueprint.status == "disabled":
                record["agent"]["status"] = "disabled"
        self.validate_record(record)
        did = record["agent"]["did"]
        existing = self.get_record_by_did(db, organization_id, did)
        now = utc_now()
        if existing is None:
            existing = AgentRecord(
                organization_id=organization_id,
                blueprint_id=blueprint_id,
                did=did,
                display_name=record["agent"]["display_name"],
                status=record["agent"]["status"],
                environment=record["agent"]["environment"],
                protocol_version=record["agent_id_protocol_version"],
                record_json=record,
                created_at=now,
                updated_at=now,
            )
            db.add(existing)
            action = "agent_record_created"
        else:
            existing.blueprint_id = blueprint_id
            existing.display_name = record["agent"]["display_name"]
            existing.status = record["agent"]["status"]
            existing.environment = record["agent"]["environment"]
            existing.protocol_version = record["agent_id_protocol_version"]
            existing.record_json = record
            existing.updated_at = now
            action = "agent_record_updated"

        db.flush()
        self._audit(
            db,
            organization_id=organization_id,
            actor_label=actor_label,
            action=action,
            agent_record_id=existing.id,
            metadata={"did": did, "status": existing.status, "blueprint_id": blueprint_id, "sponsors": record.get("extensions", {}).get("blueprint", {}).get("sponsors", [])},
        )
        db.commit()
        db.refresh(existing)
        return existing

    def deprovision_record(
        self,
        db: Session,
        organization_id: str,
        actor_label: str,
        record_id: str,
        reason: str,
    ) -> AgentRecord | None:
        record = self.get_record_by_id(db, organization_id, record_id)
        if record is None:
            return None
        record.record_json["agent"]["status"] = "disabled"
        record.status = "disabled"
        record.updated_at = utc_now()
        record.deprovisioned_at = utc_now()
        self._audit(
            db,
            organization_id=organization_id,
            agent_record_id=record.id,
            actor_label=actor_label,
            action="agent_record_deprovisioned",
            reason=reason,
            metadata={"did": record.did},
        )
        db.commit()
        db.refresh(record)
        return record

    def list_audit_events(self, db: Session, organization_id: str, agent_record_id: str | None = None) -> list[AuditEvent]:
        stmt = select(AuditEvent).where(AuditEvent.organization_id == organization_id).order_by(AuditEvent.created_at)
        if agent_record_id is not None:
            stmt = stmt.where(AuditEvent.agent_record_id == agent_record_id)
        return list(db.scalars(stmt))

    def _create_session(
        self,
        db: Session,
        organization: Organization,
        provider_type: str,
        actor_label: str,
        subject: str,
        email: str | None,
        display_name: str | None,
        role: str,
        claims: dict[str, Any],
    ) -> tuple[UserSession, str]:
        now = utc_now()
        session = UserSession(
            organization_id=organization.id,
            provider_type=provider_type,
            subject=subject,
            email=email,
            display_name=display_name,
            role=role,
            created_at=now,
            expires_at=now + timedelta(seconds=settings.session_ttl_seconds),
            last_used_at=now,
        )
        db.add(session)
        db.flush()
        token = create_session_token(
            {
                "session_id": session.id,
                "organization_id": organization.id,
                "organization_slug": organization.slug,
                "subject": subject,
                "role": role,
                "provider_type": provider_type,
            },
            settings.session_signing_secret,
            settings.session_ttl_seconds,
        )
        self._audit(
            db,
            organization_id=organization.id,
            actor_label=actor_label,
            action="sso_session_created",
            metadata={
                "provider_type": provider_type,
                "subject": subject,
                "email": email,
                "role": role,
                "claims": claims,
            },
        )
        db.commit()
        db.refresh(session)
        return session, token

    def _parse_saml_response(self, saml_response: str) -> tuple[str, str | None, str | None, dict[str, Any]]:
        xml_bytes = base64.b64decode(saml_response)
        root = ET.fromstring(xml_bytes)
        namespace = {"saml2": "urn:oasis:names:tc:SAML:2.0:assertion"}
        name_id = root.find(".//saml2:NameID", namespace)
        if name_id is None or not name_id.text:
            raise ProtocolValidationError("SAML response is missing NameID")

        email = None
        display_name = None
        attributes: dict[str, Any] = {}
        for attribute in root.findall(".//saml2:Attribute", namespace):
            attr_name = attribute.attrib.get("Name")
            values = [value.text for value in attribute.findall("./saml2:AttributeValue", namespace) if value.text]
            if attr_name:
                attributes[attr_name] = values[0] if len(values) == 1 else values
            lowered = (attr_name or "").lower()
            if lowered in {"email", "emailaddress", "mail"} and values:
                email = values[0]
            if lowered in {"displayname", "name", "givenname"} and values:
                display_name = values[0]
        return name_id.text, email, display_name, attributes

    def _audit(
        self,
        db: Session,
        organization_id: str,
        actor_label: str,
        action: str,
        agent_record_id: str | None = None,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        db.add(
            AuditEvent(
                organization_id=organization_id,
                agent_record_id=agent_record_id,
                actor_label=actor_label,
                action=action,
                reason=reason,
                metadata_json=metadata or {},
            )
        )
