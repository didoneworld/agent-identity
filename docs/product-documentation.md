# Agent Identity Product Documentation

This document describes the current Agent Identity SaaS control plane implementation: features, runtime configuration, default settings, and HTTP API.

## Overview

Agent Identity is an open source, vendor-agnostic agent identity and access management control plane built around:
- W3C DID-backed agent identity records
- OIDC-oriented deployment positioning
- tenant-scoped registry and lifecycle operations
- an admin UI served from the same FastAPI service

The current implementation is a single FastAPI service with:
- a REST API
- a built-in admin console at `/`
- schema validation against the Agent ID record JSON Schema
- SQLite for local development
- Postgres support through `DATABASE_URL`

## Features

### Core platform features

- Organization bootstrap for the first tenant
- API key based access control using `X-API-Key`
- Tenant-scoped Agent ID record storage
- Record lookup by internal record ID or DID
- Upsert semantics for Agent ID records
- Deprovision workflow that changes agent status to `disabled`
- Audit logging for bootstrap, record create/update, and deprovision actions
- Admin console UI for bootstrap, session entry, record submission, audit viewing, and deprovisioning

### Protocol features

- Agent ID record validation against `schemas/json/agent-id-record.schema.json`
- Required `authorization` and `governance` blocks
- Delegation and identity-chain validation rules
- DID-based core identity model

## Implementation Notes

### Persistence model

The current service uses the following tables:
- `organizations`
- `api_keys`
- `agent_records`
- `audit_events`

Important current behavior:
- only one bootstrap operation is allowed; after the first organization exists, `/v1/bootstrap` returns `409`
- API keys are stored by SHA-256 hash, not in plaintext
- Agent ID records are stored as full JSON payloads in `record_json`
- agent uniqueness is enforced per tenant on `(organization_id, did)`

### Admin UI

The built-in admin UI is served from:
- `/` for the HTML shell
- `/static/app.css`
- `/static/app.js`

The UI currently supports:
- bootstrap first organization
- save API key session in browser local storage
- list organizations and API keys
- list agent records
- load a record into the JSON editor
- submit record JSON to create or update
- list audit events
- deprovision an agent record

## Configuration

### Environment variables

Current runtime environment variables:

| Variable | Purpose | Default |
|---|---|---|
| `DATABASE_URL` | SQLAlchemy database connection string | `sqlite:///data/agent_id_protocol.db` |
| `PORT` | HTTP port used by the container start script | `8000` |
| `APP_PORT` | Host-side app port for `docker compose` | `8000` |
| `POSTGRES_PORT` | Host-side Postgres port for `docker compose` | `5432` |

### Default settings

Current defaults in the application:

| Setting | Value |
|---|---|
| Service name from `/health` | `agent-identity-saas` |
| API version | `0.2.0` |
| Local database engine | SQLite |
| Compose database engine | Postgres 16 Alpine |
| API key header | `X-API-Key` |
| Bootstrap default API key label | `bootstrap-admin` |
| Organization slug validation | lowercase alphanumeric plus hyphen |
| Deprovision status target | `disabled` |

### Local development defaults

When no environment is provided:
- database file path is `data/agent_id_protocol.db`
- FastAPI serves on `127.0.0.1:8000` when started with `uvicorn`
- Docker container serves on container port `8000`

## Deployment and Runtime

### Local application run

```bash
python3 -m uvicorn app.main:app --reload
```

UI:

```bash
http://127.0.0.1:8000/
```

### Docker image

Build locally:

```bash
docker build -t agent-identity:local .
```

Run locally:

```bash
docker run --rm -p 8000:8000 agent-identity:local
```

Run validation tests inside the image:

```bash
docker run --rm agent-identity:local /app/scripts/validate.sh
```

### Docker Compose

Start the full local stack:

```bash
docker compose up --build
```

Default exposed services:
- app: `http://127.0.0.1:8000`
- postgres: `127.0.0.1:5432`

Alternate host ports:

```bash
APP_PORT=8012 POSTGRES_PORT=5433 docker compose up --build
```

### Published images

- Docker Hub: `autonomyx/agent-identity:latest`
- GHCR: `ghcr.io/didoneworld/agent-identity:latest`

## API Documentation

### Interactive API docs

Because this is a FastAPI service, the default OpenAPI endpoints are available:
- Swagger UI: `/docs`
- ReDoc: `/redoc`
- OpenAPI JSON: `/openapi.json`

### Authentication

All tenant-scoped endpoints require:

```http
X-API-Key: <raw-api-key>
```

Unauthenticated endpoints:
- `GET /health`
- `GET /`
- `POST /v1/bootstrap`

Authenticated endpoints:
- `GET /v1/organizations`
- `GET /v1/api-keys`
- `GET /v1/agent-records`
- `POST /v1/agent-records`
- `GET /v1/agent-records/{record_id}`
- `GET /v1/agent-records/by-did/{did}`
- `GET /v1/audit-events`
- `POST /v1/agent-records/{record_id}/deprovision`

### `GET /health`

Purpose:
- liveness and runtime information

Response:

```json
{
  "service": "agent-identity-saas",
  "version": "0.2.0",
  "database_url_scheme": "sqlite"
}
```

### `POST /v1/bootstrap`

Purpose:
- initialize the first organization and generate the first admin API key

Request body:

```json
{
  "organization_name": "Didone World",
  "organization_slug": "didoneworld",
  "api_key_label": "ops-admin"
}
```

Validation:
- `organization_name`: 2 to 255 chars
- `organization_slug`: lowercase, digits, hyphen
- `api_key_label`: 2 to 255 chars

Success response:

```json
{
  "organization_id": "uuid",
  "organization_slug": "didoneworld",
  "api_key": "aidp_..."
}
```

Failure cases:
- `409` if bootstrap has already been completed

### `GET /v1/organizations`

Purpose:
- return the authenticated tenant organization

Response:

```json
[
  {
    "id": "uuid",
    "name": "Didone World",
    "slug": "didoneworld",
    "created_at": "2026-04-29T13:00:00Z"
  }
]
```

### `GET /v1/api-keys`

Purpose:
- list API keys for the authenticated organization

Response:

```json
[
  {
    "id": "uuid",
    "label": "ops-admin",
    "key_prefix": "aidp_xxxxxxxx",
    "last_four": "ABCD",
    "is_active": true,
    "created_at": "2026-04-29T13:00:00Z"
  }
]
```

### `GET /v1/agent-records`

Purpose:
- list all agent records for the authenticated organization

Response:
- array of `AgentRecordResponse`

Shape:

```json
[
  {
    "id": "uuid",
    "organization_id": "uuid",
    "did": "did:web:agents.didone.world:catalog:planner",
    "display_name": "Planner Agent",
    "status": "active",
    "environment": "prod",
    "protocol_version": "0.2.0",
    "record": {},
    "created_at": "2026-04-29T13:00:00Z",
    "updated_at": "2026-04-29T13:00:00Z",
    "deprovisioned_at": null
  }
]
```

### `POST /v1/agent-records`

Purpose:
- create a new agent record or update an existing record with the same DID inside the tenant

Request body:
- full Agent ID record payload

Example:

```json
{
  "agent_id_protocol_version": "0.2.0",
  "agent": {
    "did": "did:web:agents.didone.world:catalog:planner",
    "display_name": "Planner Agent",
    "owner": "didoneworld",
    "role": "planner",
    "environment": "prod",
    "version": "v1",
    "status": "active",
    "trust_level": "internal",
    "capabilities": ["planning"]
  },
  "authorization": {
    "mode": "delegated",
    "subject_context": "on_behalf_of_user",
    "delegation_proof_formats": ["oauth_token_exchange"],
    "scope_reference": "https://agents.didone.world/policies/planner",
    "expires_at": "2026-12-31T23:59:59Z",
    "max_delegation_depth": 1,
    "attenuation_required": true,
    "human_approval_required": false
  },
  "governance": {
    "provisioning": "internal_iam",
    "audit_endpoint": "https://agents.didone.world/audit/planner",
    "status_endpoint": "https://agents.didone.world/status/planner",
    "deprovisioning_endpoint": "https://agents.didone.world/deprovision/planner",
    "identity_chain_preserved": true
  },
  "bindings": {
    "a2a": {
      "endpoint_url": "https://agents.didone.world/a2a/planner",
      "agent_card_name": "PlannerAgent"
    },
    "acp": {
      "endpoint_url": null
    },
    "anp": {
      "did": null,
      "endpoint_url": null
    }
  },
  "extensions": {}
}
```

Behavior:
- creates a new record if DID is not already present for the tenant
- updates the existing record if DID already exists for the tenant
- writes an audit event with action `agent_record_created` or `agent_record_updated`

Failure cases:
- `422` when the payload fails schema validation

### `GET /v1/agent-records/{record_id}`

Purpose:
- fetch a single agent record by internal record ID

Failure cases:
- `404` if not found inside the authenticated tenant

### `GET /v1/agent-records/by-did/{did}`

Purpose:
- fetch a single agent record by DID

Failure cases:
- `404` if not found inside the authenticated tenant

### `GET /v1/audit-events`

Purpose:
- list audit events for the authenticated tenant

Optional query parameter:
- `agent_record_id`

Response:

```json
[
  {
    "id": 1,
    "actor_label": "api-key:ops-admin",
    "action": "agent_record_created",
    "reason": null,
    "metadata": {
      "did": "did:web:agents.didone.world:catalog:planner",
      "status": "active"
    },
    "created_at": "2026-04-29T13:00:00Z"
  }
]
```

### `POST /v1/agent-records/{record_id}/deprovision`

Purpose:
- disable an existing agent record and record the action in audit logs

Request body:

```json
{
  "reason": "credential rotation"
}
```

Behavior:
- sets `record.agent.status` to `disabled`
- sets `status` to `disabled`
- sets `deprovisioned_at`
- writes audit action `agent_record_deprovisioned`

Failure cases:
- `404` if the record is not found inside the authenticated tenant
- `422` if `reason` is shorter than 3 chars or longer than 1000 chars

## Current Limits and Default Operational Behavior

- bootstrap is single-use in the current implementation
- authentication is API-key only
- there is no user/session login system yet
- there is no RBAC or SSO yet
- there are no migrations yet; tables are created from ORM metadata at startup
- there are no background workers or async jobs yet
- there is no billing, quotas, or tenant self-service yet

## Recommended Next Documentation Additions

- SSO and SCIM integration guide once implemented
- deployment guide for Kubernetes or managed containers
- migration and backup strategy once Alembic is added
- webhook/integration guide once outbound integrations are added
