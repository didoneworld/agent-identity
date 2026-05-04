"""
app/scim/schema.py

SCIM 2.0 AgenticIdentity resource type schema.

Based on:
  - RFC 7643 (SCIM Core Schema)
  - RFC 7644 (SCIM Protocol)
  - draft-wahl-scim-agent-schema (WP §2.9)

The AgenticIdentity resource type extends the standard SCIM User schema
with agent-specific attributes. Every field maps directly to the
agent_records table columns already in agent-did's Postgres schema.

Schema URN:
  urn:ietf:params:scim:schemas:extension:AgenticIdentity:2.0:Agent
"""

from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field
import time
import uuid

# ---------------------------------------------------------------------------
# SCIM constants
# ---------------------------------------------------------------------------

SCIM_AGENT_SCHEMA_URN = (
    "urn:ietf:params:scim:schemas:extension:AgenticIdentity:2.0:Agent"
)
SCIM_LIST_RESPONSE_URN = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_ERROR_URN = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_PATCH_OP_URN = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

RESOURCE_TYPE = "Agent"
SCIM_BASE_PATH = "/v1/scim/v2"


# ---------------------------------------------------------------------------
# Agent status enum — maps to WP §3.2 lifecycle states
# ---------------------------------------------------------------------------

class AgentStatus(str, Enum):
    PENDING_APPROVAL = "PendingApproval"   # awaiting M-of-N gate (WP §3.4)
    ACTIVE = "Active"
    SUSPENDED = "Suspended"
    DEPROVISIONED = "Deprovisioned"        # terminal — SSF CAEP event emitted


# ---------------------------------------------------------------------------
# SCIM Meta sub-object
# ---------------------------------------------------------------------------

class ScimMeta(BaseModel):
    resourceType: str = RESOURCE_TYPE
    created: str = Field(default_factory=lambda: _iso_now())
    lastModified: str = Field(default_factory=lambda: _iso_now())
    location: str = ""
    version: str = Field(default_factory=lambda: f'W/"{uuid.uuid4().hex[:8]}"')


def _iso_now() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# SCIM AgenticIdentity resource
# draft-wahl-scim-agent-schema attributes mapped to agent_records columns
# ---------------------------------------------------------------------------

class AgenticIdentityCreate(BaseModel):
    """Payload for POST /v1/scim/v2/AgenticIdentities"""
    # Core SCIM fields
    schemas: list[str] = Field(default=[SCIM_AGENT_SCHEMA_URN])
    externalId: str | None = None

    # Agent identity fields (WP §3.1 / OIDC-A)
    displayName: str                        # human-readable agent name
    agentDid: str                           # did:web or did:key
    agentModel: str | None = None           # e.g. "claude-sonnet-4-6"
    agentProvider: str | None = None        # e.g. "anthropic"
    agentVersion: str | None = None         # e.g. "4.6.0"
    agentType: str = "autonomous"           # autonomous | delegated | embedded
    organizationSlug: str                   # owning org

    # Lifecycle
    active: bool = True
    status: AgentStatus = AgentStatus.PENDING_APPROVAL

    # Authorization metadata (feeds into CAAS SpiceDB tuples)
    delegationScope: list[str] = Field(default_factory=list)
    allowedTools: list[str] = Field(default_factory=list)
    maxTokenBudget: int | None = None

    # Governance
    requiresHumanApproval: bool = True      # triggers M-of-N gate (WP §3.4)
    approvalThreshold: int = 1              # M in M-of-N
    approvalGroupId: str | None = None      # CAAS decision-service group


class AgenticIdentityResponse(AgenticIdentityCreate):
    """Full resource representation returned by GET/POST/PUT"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    meta: ScimMeta = Field(default_factory=ScimMeta)

    def scim_location(self, base_url: str) -> str:
        return f"{base_url}{SCIM_BASE_PATH}/AgenticIdentities/{self.id}"

    def to_scim_dict(self, base_url: str = "") -> dict[str, Any]:
        d = self.model_dump()
        d["meta"]["location"] = self.scim_location(base_url)
        return d


# ---------------------------------------------------------------------------
# SCIM ListResponse wrapper
# ---------------------------------------------------------------------------

class ScimListResponse(BaseModel):
    schemas: list[str] = [SCIM_LIST_RESPONSE_URN]
    totalResults: int
    startIndex: int = 1
    itemsPerPage: int
    Resources: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# SCIM PatchOp
# ---------------------------------------------------------------------------

class PatchOperation(BaseModel):
    op: str           # add | remove | replace
    path: str | None = None
    value: Any = None


class ScimPatchRequest(BaseModel):
    schemas: list[str] = [SCIM_PATCH_OP_URN]
    Operations: list[PatchOperation]


# ---------------------------------------------------------------------------
# SCIM Error response helper
# ---------------------------------------------------------------------------

def scim_error(status: int, detail: str, scim_type: str | None = None) -> dict:
    body: dict[str, Any] = {
        "schemas": [SCIM_ERROR_URN],
        "status": str(status),
        "detail": detail,
    }
    if scim_type:
        body["scimType"] = scim_type
    return body
