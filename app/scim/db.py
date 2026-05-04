"""
app/scim/db.py

SCIM DB adapter — maps AgenticIdentity CRUD operations to the
agent_records table already defined in agent-did's Postgres schema.

The existing agent_records table has:
  id, organization_id, did, display_name, record_type,
  status, raw_record (JSONB), created_at, updated_at

We use the JSONB raw_record column to store all SCIM extension fields
(agentModel, agentProvider, delegationScope, etc.) without a schema
migration on the first iteration. A formal Alembic migration adding
dedicated columns is documented in the TODO below.

Replace the _db() stub with your existing DB session factory.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from app.scim.schema import (
    AgenticIdentityCreate,
    AgenticIdentityResponse,
    AgentStatus,
    ScimMeta,
    _iso_now,
)


# ---------------------------------------------------------------------------
# DB session stub — replace with your existing pattern
# ---------------------------------------------------------------------------

async def _db():
    """
    Yield an async DB connection.
    Replace with your existing pattern, e.g.:
        from app.database import get_db
        async with get_db() as conn:
            yield conn

    The queries below use asyncpg-style $1/$2 placeholders.
    For SQLAlchemy core, swap to :param style.
    """
    raise NotImplementedError(
        "Replace _db() with your existing DB session factory from app/database.py"
    )


# ---------------------------------------------------------------------------
# SCIM → DB field mappings
# ---------------------------------------------------------------------------

def _to_db_row(resource: AgenticIdentityCreate, org_id: str) -> dict[str, Any]:
    """Convert an AgenticIdentity resource to agent_records columns."""
    return {
        "id": str(uuid.uuid4()),
        "organization_id": org_id,
        "did": resource.agentDid,
        "display_name": resource.displayName,
        "record_type": resource.agentType,
        "status": resource.status.value,
        "raw_record": json.dumps({
            # SCIM extension fields stored in JSONB
            "scim_external_id": resource.externalId,
            "agent_model": resource.agentModel,
            "agent_provider": resource.agentProvider,
            "agent_version": resource.agentVersion,
            "organization_slug": resource.organizationSlug,
            "active": resource.active,
            "delegation_scope": resource.delegationScope,
            "allowed_tools": resource.allowedTools,
            "max_token_budget": resource.maxTokenBudget,
            "requires_human_approval": resource.requiresHumanApproval,
            "approval_threshold": resource.approvalThreshold,
            "approval_group_id": resource.approvalGroupId,
            "schemas": resource.schemas,
        }),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def _from_db_row(row: dict[str, Any]) -> AgenticIdentityResponse:
    """Reconstruct an AgenticIdentityResponse from an agent_records row."""
    raw = row.get("raw_record") or {}
    if isinstance(raw, str):
        raw = json.loads(raw)

    return AgenticIdentityResponse(
        id=str(row["id"]),
        schemas=raw.get("schemas", ["urn:ietf:params:scim:schemas:extension:AgenticIdentity:2.0:Agent"]),
        externalId=raw.get("scim_external_id"),
        displayName=row.get("display_name", ""),
        agentDid=row.get("did", ""),
        agentModel=raw.get("agent_model"),
        agentProvider=raw.get("agent_provider"),
        agentVersion=raw.get("agent_version"),
        agentType=row.get("record_type", "autonomous"),
        organizationSlug=raw.get("organization_slug", ""),
        active=raw.get("active", True),
        status=AgentStatus(row.get("status", AgentStatus.PENDING_APPROVAL.value)),
        delegationScope=raw.get("delegation_scope", []),
        allowedTools=raw.get("allowed_tools", []),
        maxTokenBudget=raw.get("max_token_budget"),
        requiresHumanApproval=raw.get("requires_human_approval", True),
        approvalThreshold=raw.get("approval_threshold", 1),
        approvalGroupId=raw.get("approval_group_id"),
        meta=ScimMeta(
            created=str(row.get("created_at", _iso_now())),
            lastModified=str(row.get("updated_at", _iso_now())),
        ),
    )


# ---------------------------------------------------------------------------
# CRUD operations
# All are async — plug directly into FastAPI route handlers
# ---------------------------------------------------------------------------

async def create_agent_record(
    resource: AgenticIdentityCreate,
    org_id: str,
) -> AgenticIdentityResponse:
    """
    INSERT a new agent record.
    Returns the created resource with server-assigned id and meta.

    TODO: replace stub with real DB insert:
        row = _to_db_row(resource, org_id)
        async with get_db() as conn:
            await conn.execute(
                "INSERT INTO agent_records (id, organization_id, did, display_name, "
                "record_type, status, raw_record, created_at, updated_at) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                row["id"], row["organization_id"], row["did"], ...
            )
        return _from_db_row(row)
    """
    row = _to_db_row(resource, org_id)
    # Stub: return the constructed row as a response (no real DB write)
    return _from_db_row(row)


async def get_agent_record(record_id: str, org_id: str) -> AgenticIdentityResponse | None:
    """
    SELECT one agent record by id + org scope.

    TODO:
        async with get_db() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM agent_records WHERE id=$1 AND organization_id=$2",
                record_id, org_id
            )
        if not row:
            return None
        return _from_db_row(dict(row))
    """
    return None  # stub — replace with real DB read


async def list_agent_records(
    org_id: str,
    filter_str: str | None = None,
    start_index: int = 1,
    count: int = 100,
) -> tuple[list[AgenticIdentityResponse], int]:
    """
    SELECT agent records with optional SCIM filter + pagination.
    Returns (resources, total_count).

    SCIM filter parsing note:
      The filter_str follows RFC 7644 §3.4.2.2, e.g.:
        'displayName eq "my-agent"'
        'status eq "Active"'
        'agentProvider eq "anthropic"'
      Parse with a minimal filter parser or a library like scim2-filter-parser.

    TODO:
        query = "SELECT * FROM agent_records WHERE organization_id=$1"
        params = [org_id]
        # Apply filter if present (parse filter_str → SQL WHERE clause)
        query += " LIMIT $2 OFFSET $3"
        params += [count, start_index - 1]
        async with get_db() as conn:
            rows = await conn.fetch(query, *params)
            total = await conn.fetchval(
                "SELECT COUNT(*) FROM agent_records WHERE organization_id=$1", org_id
            )
        return [_from_db_row(dict(r)) for r in rows], total
    """
    return [], 0  # stub


async def update_agent_record(
    record_id: str,
    org_id: str,
    updates: dict[str, Any],
) -> AgenticIdentityResponse | None:
    """
    UPDATE an agent record (SCIM PUT/PATCH).
    `updates` is a flat dict of field → value from the SCIM patch operations.

    TODO:
        # Merge updates into raw_record JSONB + update top-level columns
        async with get_db() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM agent_records WHERE id=$1 AND organization_id=$2",
                record_id, org_id
            )
            if not row:
                return None
            raw = json.loads(row["raw_record"] or "{}")
            raw.update(updates.get("raw", {}))
            await conn.execute(
                "UPDATE agent_records SET display_name=$1, status=$2, "
                "raw_record=$3, updated_at=$4 WHERE id=$5",
                updates.get("displayName", row["display_name"]),
                updates.get("status", row["status"]),
                json.dumps(raw),
                datetime.now(timezone.utc).isoformat(),
                record_id,
            )
        return await get_agent_record(record_id, org_id)
    """
    return None  # stub


async def delete_agent_record(record_id: str, org_id: str) -> bool:
    """
    Hard-delete an agent record (SCIM DELETE).
    Sets status=Deprovisioned before physical delete so the SSF
    emitter can read final state.

    Returns True if the record existed and was deleted.

    TODO:
        async with get_db() as conn:
            result = await conn.execute(
                "UPDATE agent_records SET status='Deprovisioned', updated_at=$1 "
                "WHERE id=$2 AND organization_id=$3",
                datetime.now(timezone.utc).isoformat(), record_id, org_id
            )
            if result == "UPDATE 0":
                return False
            # Optionally hard-delete after SSF event emission:
            # await conn.execute(
            #     "DELETE FROM agent_records WHERE id=$1", record_id
            # )
        return True
    """
    return True  # stub — always succeeds for now


async def get_org_id_for_slug(org_slug: str) -> str | None:
    """
    Look up organization.id from slug.

    TODO:
        async with get_db() as conn:
            row = await conn.fetchrow(
                "SELECT id FROM organizations WHERE slug=$1", org_slug
            )
        return str(row["id"]) if row else None
    """
    return str(uuid.uuid4())  # stub
