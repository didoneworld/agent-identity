# Agent DID

Open source, vendor-agnostic agent identity and access management control plane built around OpenID Connect, SAML, SCIM, Shared Signals, and W3C Decentralized Identifiers.

Agent DID defines an Agent ID record format and provides a runnable FastAPI reference implementation for managing agent identities, governance metadata, authorization, lifecycle operations, and enterprise identity integrations.

## What this repository contains

This repository includes both the Agent ID protocol draft and a working SaaS-style control plane.

### Protocol and interoperability

- Agent ID protocol draft
- DID-backed agent identity record
- Governance and lifecycle metadata for long-running agents
- Authorization metadata for delegated and autonomous agent operation
- Protocol binding examples for A2A, ACP, and ANP
- Publication and compatibility guidance
- JSON Schema for validating Agent ID records

Agent DID does not define agent-to-agent messaging. It is designed to work alongside interoperability protocols such as A2A, ACP, and ANP.

### Control plane

The FastAPI application provides a tenant-scoped registry and admin surface for Agent ID records.

Current capabilities include:

- tenant bootstrap with first admin API key
- API key authentication with `X-API-Key`
- bearer session authentication
- admin, writer, and reader roles
- OIDC and SAML identity provider configuration
- OIDC discovery and SSO routes
- SAML ACS support
- SCIM lifecycle endpoints
- Shared Signals Framework routes
- approval workflow routes
- database-backed Agent ID registry
- record-level fine-grained authorization tuples
- audit logging for identity and lifecycle events
- deprovisioning support
- schema revision tracking and startup migrations
- in-memory request rate limiting
- request ID logging
- SQLite for local development
- `DATABASE_URL` support for Postgres deployments
- built-in web admin console at `/`

## Repository layout

```text
app/                         FastAPI SaaS control plane
app/routers/                 OIDC, SAML, SCIM, session, and discovery routers
app/static/                  Built-in admin console assets
docs/agent-id-spec.md        Agent ID protocol draft
docs/product-documentation.md Product behavior, configuration, defaults, and API docs
docs/openid-alignment.md     Rationale for OpenID authorization and governance alignment
docs/compatibility.md        Evolution and compatibility rules
schemas/agent-id-record.yaml Core Agent ID record example
schemas/json/agent-id-record.schema.json JSON Schema for validation
examples/                    Protocol binding and DID method examples
templates/publish-checklist.md Publication checklist
tests/                       Automated test suite
scripts/                     Validation and utility scripts
```

## Quick start

### Run locally with Python

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m uvicorn app.main:app --reload
```

Open the admin console:

```text
http://127.0.0.1:8000/
```

Check service health:

```bash
curl http://127.0.0.1:8000/health
```

Bootstrap the first organization and admin API key:

```bash
curl -X POST http://127.0.0.1:8000/v1/bootstrap \
  -H 'content-type: application/json' \
  -d '{"organization_name":"Didone World","organization_slug":"didoneworld","api_key_label":"ops-admin"}'
```

The bootstrap response returns the first admin API key. Store it securely; it is used with the `X-API-Key` header for authenticated API calls.

## Run with Docker

Build and run locally:

```bash
docker build -t agent-identity:local .
docker run --rm -p 8000:8000 agent-identity:local
```

Run validation inside the image:

```bash
docker run --rm agent-identity:local /app/scripts/validate.sh
```

Pull a published image:

```bash
docker run --rm -p 8000:8000 autonomyx/agent-identity:latest
```

Published images:

- Docker Hub: `autonomyx/agent-identity:latest`
- GHCR: `ghcr.io/didoneworld/agent-identity:latest`

## Run with Docker Compose

Start the app with Postgres:

```bash
docker compose up --build
```

The compose stack exposes:

- app: `http://127.0.0.1:8000`
- database: `postgresql://agentid:agentid@127.0.0.1:5432/agentid`

Use alternate host ports when defaults are already taken:

```bash
APP_PORT=8012 POSTGRES_PORT=5433 docker compose up --build
```

Create a local environment file from the template:

```bash
cp .env.example .env
```

## Core API surface

Unauthenticated:

- `GET /health`
- `GET /`
- `POST /v1/bootstrap`
- `GET /.well-known/*`
- `GET /v1/sso/oidc/start/{organization_slug}`
- `POST /v1/sso/oidc/callback/{organization_slug}`
- `POST /v1/sso/saml/acs/{organization_slug}`

Authenticated with API key or bearer session:

- `GET /v1/organizations`
- `GET /v1/identity-providers`
- `GET /v1/agent-records`
- `POST /v1/agent-records`
- `GET /v1/agent-records/{record_id}`
- `GET /v1/agent-records/by-did/{did}`
- `GET /v1/audit-events`
- `POST /v1/agent-records/{record_id}/deprovision`
- `GET /v1/fga/tuples`
- `POST /v1/fga/tuples`
- `POST /v1/fga/check`
- `GET /v1/scim/v2/*`
- `POST /v1/ssf/*`
- `GET /v1/approvals/*`

Admin API key only:

- `GET /v1/api-keys`
- `POST /v1/api-keys`
- `POST /v1/api-keys/{api_key_id}/revoke`
- `POST /v1/identity-providers/oidc`
- `POST /v1/identity-providers/saml`

Interactive OpenAPI documentation is available from FastAPI at:

```text
http://127.0.0.1:8000/docs
```

## Identity model

Agent DID separates identity, authorization, and governance:

- DIDs identify agents.
- Authorization metadata describes whether agents act autonomously or on behalf of users, teams, or systems.
- Governance metadata exposes lifecycle, audit, approval, and deprovisioning controls for long-running agents.

Recommended DID methods:

- `did:web` for public organization-managed agent identities
- `did:key` for local, ephemeral, or lightweight agent identities

Examples:

- `examples/did-methods/did-web-agent.yaml`
- `examples/did-methods/did-key-agent.yaml`

## Current limitations

Agent DID is a serious MVP and reference SaaS foundation, not a fully hardened enterprise identity platform.

Known limitations include:

- external OIDC and SAML production hardening is still evolving
- SAML metadata ingestion, certificate validation, logout, and full SP hardening are not complete
- internal FGA is intentionally minimal and is not OpenFGA-compatible yet
- admin UI does not yet expose every API capability
- SCIM, SSF, approvals, and lifecycle automation are early product slices
- Redis-backed rate limiting, background workers, production observability, and secret encryption at rest are not yet included

## Roadmap

Planned work includes:

1. Harden OIDC and SAML flows with full token validation, signed metadata, logout, and session revocation.
2. Expand authorization with group mapping, inheritance, policy templates, and an OpenFGA-compatible model.
3. Mature SCIM, SSF, approvals, audit export, key rotation, and lifecycle automation.
4. Improve operations with Alembic, Redis, workers, metrics, tracing, and deployment manifests.
5. Expand the admin console for identity providers, sessions, FGA tuples, teams, tenant settings, and approvals.

## CI/CD

GitHub Actions is configured to:

- run tests on pull requests
- build and smoke test the container on pull requests
- publish `latest`, branch, tag, and SHA-based image tags on `main` pushes and `v*` tags
- push images to GHCR and Docker Hub

Required GitHub repository secrets for Docker Hub publishing:

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`

GHCR publishing uses `GITHUB_TOKEN` with package write permission.

## License

Add license information here before using Agent DID in production or redistributing packaged builds.
