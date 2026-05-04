from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from datetime import timedelta
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db_models import (
    AgentRecord,
    ApiKey,
    AuditEvent,
    AuthorizationTuple,
    IdentityProviderConfig,
    Organization,
    UserSession,
    utc_now,
)
from app.schemas import AgentRecordWrite, AuthContext
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
        self.validate_record(record)
        did = record["agent"]["did"]
        existing = self.get_record_by_did(db, organization_id, did)
        now = utc_now()
        if existing is None:
            existing = AgentRecord(
                organization_id=organization_id,
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
            metadata={"did": did, "status": existing.status},
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
