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
- startup schema migration tracking
- in-memory API rate limiting and request ID logging

## Current State

The product is now a working SaaS control-plane foundation with:
- tenant bootstrap and organization isolation
- API key authentication plus signed bearer sessions for OIDC and SAML ingress
- tenant-scoped Agent ID registry and deprovision lifecycle
- audit events and record-level FGA tuples
- containerized local runtime and automated tests

This is beyond a pure reference implementation, but it is still an MVP-to-foundation stage product rather than a fully hardened enterprise IAM platform.

## Current Limitations

- OIDC support is a trusted callback/session issuance flow. It does not yet perform live authorization-code exchange against an external IdP, fetch JWKS, or validate upstream ID tokens.
- SAML support parses assertions and creates local sessions, but does not yet validate XML signatures, ingest IdP metadata automatically, or manage certificate rotation.
- FGA is implemented as a local tuple store with basic `viewer`, `editor`, and `owner` relations on `agent_record`. It does not yet support group subjects, relation inheritance, model migration, or OpenFGA interoperability.
- Session management is minimal: no refresh tokens, logout endpoint, revocation list, session browser UI, or anomaly detection.
- The built-in UI does not yet expose IdP configuration, SSO flows, or FGA tuple management.
- Platform hardening is incomplete: no SCIM, MFA, invitations, approval workflows, encrypted secret storage, Redis-backed rate limiting, or production metrics/tracing stack.

## Future Plan

### Phase 1: Identity hardening

- Implement full OIDC authorization-code flow with upstream token validation
- Add JWKS retrieval and cache management
- Add SAML signature validation and metadata ingestion
- Add logout, session revocation, and session administration endpoints

### Phase 2: Authorization expansion

- Add group-to-role and group-to-tuple mapping
- Support richer FGA object types and relation inheritance
- Define an authorization model version and compatibility policy
- Add OpenFGA-compatible export or adapter paths

### Phase 3: Enterprise controls

- Add SCIM provisioning and deprovisioning
- Add invitation flows and managed user directory concepts
- Add audit export and retention controls
- Add secret encryption and stronger key/session rotation workflows

### Phase 4: Platform readiness

- Move migration management to Alembic
- Add Redis-backed rate limiting and background workers
- Add structured metrics, tracing, and alerting hooks
- Add deployment manifests for production environments

### Phase 5: Product UX

- Add admin screens for OIDC and SAML provider configuration
- Add FGA tuple management and authorization inspection UI
- Add session visibility and revocation UI
- Add tenant settings, onboarding, and operator workflows

## Features

### Core platform features

- Organization bootstrap for the first tenant
- API key based access control using `X-API-Key`
- Role-based API keys for `admin`, `writer`, and `reader`
- OIDC provider configuration and bearer session issuance
- SAML provider configuration and assertion-consumer session issuance
- fine-grained authorization tuple storage for record-level sharing
- Tenant-scoped Agent ID record storage
- Record lookup by internal record ID or DID
- Upsert semantics for Agent ID records
- Deprovision workflow that changes agent status to `disabled`
- Audit logging for bootstrap, record create/update, and deprovision actions
- API key creation and revocation lifecycle endpoints
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
- `identity_provider_configs`
- `user_sessions`
- `authorization_tuples`
- `schema_migrations`

Important current behavior:
- only one bootstrap operation is allowed; after the first organization exists, `/v1/bootstrap` returns `409`
- API keys are stored by SHA-256 hash, not in plaintext
- API keys are assigned one of three roles: `admin`, `writer`, `reader`
- SSO sessions are signed locally and mapped to organization-scoped user sessions
- FGA tuples model `viewer`, `editor`, and `owner` relations on `agent_record` objects
- Agent ID records are stored as full JSON payloads in `record_json`
- agent uniqueness is enforced per tenant on `(organization_id, did)`
- database migrations are applied at service startup and tracked in `schema_migrations`

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
| `API_RATE_LIMIT_REQUESTS` | Maximum requests per rate-limit window | `120` |
| `API_RATE_LIMIT_WINDOW_SECONDS` | Rate-limit window duration in seconds | `60` |
| `SESSION_SIGNING_SECRET` | HMAC secret for bearer session tokens | `agent-identity-dev-secret` |
| `SESSION_TTL_SECONDS` | Bearer session lifetime in seconds | `43200` |

### Default settings

Current defaults in the application:

| Setting | Value |
|---|---|
| Service name from `/health` | `agent-identity-saas` |
| API version | `0.2.0` |
| Product service version | `0.3.0` |
| Local database engine | SQLite |
| Compose database engine | Postgres 16 Alpine |
| API key header | `X-API-Key` |
| Session bearer header | `Authorization: Bearer <token>` |
| Bootstrap default API key label | `bootstrap-admin` |
| API key roles | `admin`, `writer`, `reader` |
| FGA relations | `viewer`, `editor`, `owner` |
| Organization slug validation | lowercase alphanumeric plus hyphen |
| Deprovision status target | `disabled` |
| Schema migration revision | `20260429_02` |

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

Tenant-scoped endpoints accept either:

```http
X-API-Key: <raw-api-key>
```

or

```http
Authorization: Bearer <signed-session-token>
```

Unauthenticated endpoints:
- `GET /health`
- `GET /`
- `POST /v1/bootstrap`

Authenticated endpoints:
- `GET /v1/organizations`
- `GET /v1/identity-providers`
- `POST /v1/identity-providers/oidc`
- `POST /v1/identity-providers/saml`
- `GET /v1/api-keys`
- `POST /v1/api-keys`
- `POST /v1/api-keys/{api_key_id}/revoke`
- `GET /v1/agent-records`
- `POST /v1/agent-records`
- `GET /v1/agent-records/{record_id}`
- `GET /v1/agent-records/by-did/{did}`
- `GET /v1/audit-events`
- `POST /v1/agent-records/{record_id}/deprovision`
- `GET /v1/fga/tuples`
- `POST /v1/fga/tuples`
- `POST /v1/fga/check`

Role matrix:
- `admin`: full tenant access including API key issuance, revocation, provider configuration, record writes, and deprovision
- `writer`: read access plus record create/update
- `reader`: read-only access to organizations, records, and audit events

FGA enforcement notes:
- session-based `reader` users need an explicit `viewer` or stronger tuple to open individual agent record detail endpoints
- `owner` tuples can authorize deprovision when the user would not otherwise have tenant-wide admin rights

### `GET /health`

Purpose:
- liveness and runtime information

Response:

```json
{
  "service": "agent-identity-saas",
  "version": "0.3.0",
  "database_url_scheme": "sqlite",
  "schema_revision": "20260429_02",
  "rate_limit_requests": 120,
  "rate_limit_window_seconds": 60
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

Role required:
- `admin`

Response:

```json
[
  {
    "id": "uuid",
    "label": "ops-admin",
    "key_prefix": "aidp_xxxxxxxx",
    "last_four": "ABCD",
    "role": "admin",
    "is_active": true,
    "created_at": "2026-04-29T13:00:00Z",
    "revoked_at": null,
    "last_used_at": "2026-04-29T13:05:00Z"
  }
]
```

### `POST /v1/api-keys`

Purpose:
- create a new tenant-scoped API key and return the raw secret once

Role required:
- `admin`

Request body:

```json
{
  "label": "writer-bot",
  "role": "writer"
}
```

Success response:

```json
{
  "id": "uuid",
  "label": "writer-bot",
  "role": "writer",
  "api_key": "aidp_...",
  "key_prefix": "aidp_xxxxxxxx",
  "last_four": "ABCD",
  "created_at": "2026-04-29T13:00:00Z"
}
```

### `POST /v1/api-keys/{api_key_id}/revoke`

Purpose:
- revoke an API key so it can no longer authenticate

Role required:
- `admin`

Success response:

```json
{
  "id": "uuid",
  "is_active": false,
  "revoked_at": "2026-04-29T13:15:00Z"
}
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
