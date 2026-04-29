# Agent ID Protocol

Open source vendor-agnostic agent identity and access management control plane based on OIDC and W3C DIDs.

## Scope

This repository defines:
- the Agent ID protocol draft
- the core DID-backed agent record
- authorization and governance metadata for agent operation
- protocol binding examples for A2A, ACP, and ANP
- publication and compatibility guidance

This repository does not define agent messaging. It is intended to work alongside interoperability protocols such as A2A, ACP, and ANP.

## Layout

- `docs/agent-id-spec.md`: protocol draft
- `docs/product-documentation.md`: product features, configuration, defaults, and API documentation
- `docs/openid-alignment.md`: rationale for the authorization and governance additions
- `docs/compatibility.md`: evolution and compatibility rules
- `schemas/agent-id-record.yaml`: core record example
- `schemas/json/agent-id-record.schema.json`: JSON Schema for validation
- `examples/a2a-agent-card.json`: A2A binding example
- `templates/publish-checklist.md`: publication checklist

## SaaS Control Plane

The repository now includes a FastAPI-based SaaS control plane for managing Agent ID records per organization.

The root route `/` now serves a built-in admin console for:
- tenant bootstrap
- API key session entry
- agent record listing and raw JSON upsert
- audit log viewing
- deprovision actions

Core endpoints:
- `GET /health`
- `POST /v1/bootstrap`
- `GET /v1/organizations`
- `GET /v1/api-keys`
- `GET /v1/agent-records`
- `POST /v1/agent-records`
- `GET /v1/agent-records/{record_id}`
- `GET /v1/agent-records/by-did/{did}`
- `GET /v1/audit-events`
- `POST /v1/agent-records/{record_id}/deprovision`

Current product slice:
- tenant bootstrap with a first admin API key
- API key authentication via `X-API-Key`
- database-backed Agent ID registry
- audit logging for bootstrap, create/update, and deprovision actions
- SQLite for local development and `DATABASE_URL` support for Postgres deployments

## Published Images

- Docker Hub: `autonomyx/agent-identity:latest`
- GHCR: `ghcr.io/didoneworld/agent-identity:latest`

## CI/CD

GitHub Actions is configured to:
- run tests on every pull request
- build and smoke test the container on pull requests
- publish `latest`, branch, tag, and SHA-based image tags on `main` pushes and `v*` tags
- push to both `ghcr.io/didoneworld/agent-identity` and `autonomyx/agent-identity`

Required GitHub repository secrets for Docker Hub publishing:
- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`

GHCR publishing uses the workflow `GITHUB_TOKEN` with package write permission.

Run locally:

```bash
python3 -m uvicorn app.main:app --reload
```

Open the UI at:

```bash
http://127.0.0.1:8000/
```

Bootstrap the first organization:

```bash
curl -X POST http://127.0.0.1:8000/v1/bootstrap \
  -H 'content-type: application/json' \
  -d '{"organization_name":"Didone World","organization_slug":"didoneworld","api_key_label":"ops-admin"}'
```

## Container

The repository includes a runnable API image:

```bash
docker build -t agent-identity:local .
docker run --rm -p 8000:8000 agent-identity:local
```

Or pull a published image directly:

```bash
docker run --rm -p 8000:8000 autonomyx/agent-identity:latest
```

The image starts the FastAPI service and serves the admin console at `/`. To run validation tests in the container instead:

```bash
docker run --rm agent-identity:local /app/scripts/validate.sh
```

For a full local product stack with Postgres:

```bash
docker compose up --build
```

The compose stack brings up:
- `app` on `http://127.0.0.1:8000`
- `db` on `postgresql://agentid:agentid@127.0.0.1:5432/agentid`

If those host ports are already taken:

```bash
APP_PORT=8012 POSTGRES_PORT=5433 docker compose up --build
```

Environment template:

```bash
cp .env.example .env
```

## Identity Foundation

The protocol uses W3C DID as the identity foundation.

## Security Model

The protocol now treats agent identity, delegated authority, and governance as separate concerns:
- DIDs identify the agent.
- Authorization metadata describes whether the agent acts autonomously or on behalf of users or teams.
- Governance metadata exposes lifecycle, audit, and deprovisioning controls needed for long-running agents.

## Recommended DID Methods

- `did:web` for public organization-managed agent identities
- `did:key` for local, ephemeral, or lightweight agent identities

## Example DID Methods

- `examples/did-methods/did-web-agent.yaml` for organization-managed public identities
- `examples/did-methods/did-key-agent.yaml` for local or ephemeral identities
