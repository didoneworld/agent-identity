# Agent DID How-To Guide

This guide walks through the most common Agent DID workflows: running the service, bootstrapping a tenant, authenticating API calls, creating Agent ID records, configuring identity providers, managing authorization tuples, and deprovisioning agents.

## Prerequisites

Install the following tools for local development:

- Python 3.11 or newer
- Docker and Docker Compose
- `curl`
- `jq`, recommended for reading JSON responses

Clone the repository:

```bash
git clone https://github.com/didoneworld/agent-did.git
cd agent-did
```

## 1. Run Agent DID locally

### Option A: Python development server

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m uvicorn app.main:app --reload
```

The service starts at:

```text
http://127.0.0.1:8000
```

Open the admin console:

```text
http://127.0.0.1:8000/
```

Open API documentation:

```text
http://127.0.0.1:8000/docs
```

### Option B: Docker

```bash
docker build -t agent-identity:local .
docker run --rm -p 8000:8000 agent-identity:local
```

### Option C: Docker Compose with Postgres

```bash
docker compose up --build
```

If the default ports are already in use:

```bash
APP_PORT=8012 POSTGRES_PORT=5433 docker compose up --build
```

## 2. Verify the service is healthy

```bash
curl http://127.0.0.1:8000/health | jq
```

Expected response shape:

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

## 3. Bootstrap the first organization

Bootstrap is a one-time operation for a fresh database. It creates the first organization and returns the first admin API key.

```bash
curl -s -X POST http://127.0.0.1:8000/v1/bootstrap \
  -H 'content-type: application/json' \
  -d '{
    "organization_name": "Didone World",
    "organization_slug": "didoneworld",
    "api_key_label": "ops-admin"
  }' | jq
```

Example response:

```json
{
  "organization_id": "00000000-0000-0000-0000-000000000000",
  "organization_slug": "didoneworld",
  "api_key": "aidp_example_admin_key"
}
```

Save the key in your shell session:

```bash
export AGENT_DID_BASE_URL="http://127.0.0.1:8000"
export AGENT_DID_API_KEY="paste_bootstrap_api_key_here"
```

The raw API key is only returned once. Store it securely.

## 4. Make an authenticated request

List organizations:

```bash
curl -s "$AGENT_DID_BASE_URL/v1/organizations" \
  -H "X-API-Key: $AGENT_DID_API_KEY" | jq
```

List API keys:

```bash
curl -s "$AGENT_DID_BASE_URL/v1/api-keys" \
  -H "X-API-Key: $AGENT_DID_API_KEY" | jq
```

## 5. Create a writer or reader API key

Use an admin API key to create additional scoped keys.

Create a writer key:

```bash
curl -s -X POST "$AGENT_DID_BASE_URL/v1/api-keys" \
  -H "X-API-Key: $AGENT_DID_API_KEY" \
  -H 'content-type: application/json' \
  -d '{
    "label": "writer-bot",
    "role": "writer"
  }' | jq
```

Create a reader key:

```bash
curl -s -X POST "$AGENT_DID_BASE_URL/v1/api-keys" \
  -H "X-API-Key: $AGENT_DID_API_KEY" \
  -H 'content-type: application/json' \
  -d '{
    "label": "read-only-dashboard",
    "role": "reader"
  }' | jq
```

Roles:

| Role | Typical use |
|---|---|
| `admin` | tenant administration, API keys, identity providers, records, FGA, deprovisioning |
| `writer` | create and update Agent ID records |
| `reader` | read organizations, records, and audit events |

## 6. Create an Agent ID record

Create a local file named `planner-agent.json`:

```bash
cat > planner-agent.json <<'JSON'
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
    "capabilities": ["planning", "task_decomposition"]
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
JSON
```

Submit the record:

```bash
curl -s -X POST "$AGENT_DID_BASE_URL/v1/agent-records" \
  -H "X-API-Key: $AGENT_DID_API_KEY" \
  -H 'content-type: application/json' \
  --data-binary @planner-agent.json | jq
```

The endpoint uses upsert semantics. Submitting another record with the same DID updates the existing record inside the tenant.

## 7. List and retrieve Agent ID records

List all records:

```bash
curl -s "$AGENT_DID_BASE_URL/v1/agent-records" \
  -H "X-API-Key: $AGENT_DID_API_KEY" | jq
```

Get a record by DID:

```bash
curl -s "$AGENT_DID_BASE_URL/v1/agent-records/by-did/did:web:agents.didone.world:catalog:planner" \
  -H "X-API-Key: $AGENT_DID_API_KEY" | jq
```

Get a record by internal record ID:

```bash
export AGENT_RECORD_ID="paste_record_id_here"

curl -s "$AGENT_DID_BASE_URL/v1/agent-records/$AGENT_RECORD_ID" \
  -H "X-API-Key: $AGENT_DID_API_KEY" | jq
```

## 8. View audit events

List tenant audit events:

```bash
curl -s "$AGENT_DID_BASE_URL/v1/audit-events" \
  -H "X-API-Key: $AGENT_DID_API_KEY" | jq
```

Filter audit events for one record:

```bash
curl -s "$AGENT_DID_BASE_URL/v1/audit-events?agent_record_id=$AGENT_RECORD_ID" \
  -H "X-API-Key: $AGENT_DID_API_KEY" | jq
```

## 9. Configure an OIDC identity provider

Create or update an OIDC provider configuration:

```bash
curl -s -X POST "$AGENT_DID_BASE_URL/v1/identity-providers/oidc" \
  -H "X-API-Key: $AGENT_DID_API_KEY" \
  -H 'content-type: application/json' \
  -d '{
    "display_name": "Example OIDC",
    "issuer": "https://idp.example.com",
    "client_id": "agent-did-local",
    "client_secret": "replace-me",
    "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
    "token_endpoint": "https://idp.example.com/oauth2/token",
    "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
    "callback_url": "http://127.0.0.1:8000/v1/sso/oidc/callback/didoneworld",
    "default_role": "reader",
    "enabled": true,
    "metadata": {}
  }' | jq
```

Start an OIDC sign-in flow:

```bash
curl -s "$AGENT_DID_BASE_URL/v1/sso/oidc/start/didoneworld" | jq
```

The response includes an authorization URL for the configured provider.

## 10. Configure a SAML identity provider

Create or update a SAML provider configuration:

```bash
curl -s -X POST "$AGENT_DID_BASE_URL/v1/identity-providers/saml" \
  -H "X-API-Key: $AGENT_DID_API_KEY" \
  -H 'content-type: application/json' \
  -d '{
    "display_name": "Example SAML",
    "entity_id": "https://idp.example.com/saml/metadata",
    "login_url": "https://idp.example.com/saml/login",
    "callback_url": "http://127.0.0.1:8000/v1/sso/saml/acs/didoneworld",
    "default_role": "reader",
    "enabled": true,
    "metadata": {}
  }' | jq
```

Post a SAML assertion to the ACS route:

```bash
curl -s -X POST "$AGENT_DID_BASE_URL/v1/sso/saml/acs/didoneworld" \
  -H 'content-type: application/json' \
  -d '{
    "saml_response": "base64_encoded_saml_response_here",
    "role": "reader"
  }' | jq
```

## 11. Use bearer sessions

OIDC and SAML flows return a bearer session token. Use it as an alternative to `X-API-Key`:

```bash
export AGENT_DID_SESSION_TOKEN="paste_session_token_here"

curl -s "$AGENT_DID_BASE_URL/v1/agent-records" \
  -H "Authorization: Bearer $AGENT_DID_SESSION_TOKEN" | jq
```

## 12. Manage record-level authorization tuples

Create a tuple that grants a subject viewer access to one agent record:

```bash
curl -s -X POST "$AGENT_DID_BASE_URL/v1/fga/tuples" \
  -H "X-API-Key: $AGENT_DID_API_KEY" \
  -H 'content-type: application/json' \
  -d "{
    \"subject\": \"user:alice@example.com\",
    \"relation\": \"viewer\",
    \"object_type\": \"agent_record\",
    \"object_id\": \"$AGENT_RECORD_ID\"
  }" | jq
```

Check whether the tuple allows access:

```bash
curl -s -X POST "$AGENT_DID_BASE_URL/v1/fga/check" \
  -H "X-API-Key: $AGENT_DID_API_KEY" \
  -H 'content-type: application/json' \
  -d "{
    \"subject\": \"user:alice@example.com\",
    \"relation\": \"viewer\",
    \"object_type\": \"agent_record\",
    \"object_id\": \"$AGENT_RECORD_ID\"
  }" | jq
```

List tuples for a record:

```bash
curl -s "$AGENT_DID_BASE_URL/v1/fga/tuples?object_type=agent_record&object_id=$AGENT_RECORD_ID" \
  -H "X-API-Key: $AGENT_DID_API_KEY" | jq
```

Common relations:

| Relation | Meaning |
|---|---|
| `viewer` | can read the record |
| `editor` | can read and update the record |
| `owner` | can administer or deprovision the record |

## 13. Deprovision an agent record

Deprovisioning disables the Agent ID record and writes an audit event.

```bash
curl -s -X POST "$AGENT_DID_BASE_URL/v1/agent-records/$AGENT_RECORD_ID/deprovision" \
  -H "X-API-Key: $AGENT_DID_API_KEY" \
  -H 'content-type: application/json' \
  -d '{
    "reason": "retired during local test"
  }' | jq
```

The resulting record should have:

```json
{
  "status": "disabled",
  "deprovisioned_at": "timestamp"
}
```

## 14. Revoke an API key

List keys and copy the key ID:

```bash
curl -s "$AGENT_DID_BASE_URL/v1/api-keys" \
  -H "X-API-Key: $AGENT_DID_API_KEY" | jq
```

Revoke a key:

```bash
export API_KEY_ID="paste_api_key_id_here"

curl -s -X POST "$AGENT_DID_BASE_URL/v1/api-keys/$API_KEY_ID/revoke" \
  -H "X-API-Key: $AGENT_DID_API_KEY" | jq
```

## 15. Validate before committing changes

Run the test suite locally:

```bash
pytest
```

Run the repository validation script:

```bash
./scripts/validate.sh
```

Run validation in Docker:

```bash
docker build -t agent-identity:local .
docker run --rm agent-identity:local /app/scripts/validate.sh
```

## Troubleshooting

### Bootstrap returns `409`

Bootstrap has already been completed for the current database. Use the existing admin API key, switch to a fresh database, or remove the local development database.

For local SQLite development, the default database is usually under `data/`.

### Requests return `401`

Check that the API key is present and correct:

```bash
echo "$AGENT_DID_API_KEY"
```

Then retry with:

```bash
-H "X-API-Key: $AGENT_DID_API_KEY"
```

For bearer sessions, use:

```bash
-H "Authorization: Bearer $AGENT_DID_SESSION_TOKEN"
```

### Requests return `403`

The credential is valid, but the role or authorization tuple does not allow the requested action. Use an admin API key or add an appropriate FGA tuple.

### Record submission returns `422`

The Agent ID record failed schema validation. Check required sections:

- `agent_id_protocol_version`
- `agent.did`
- `agent.display_name`
- `authorization`
- `governance`
- `bindings`

Compare your payload with `schemas/agent-id-record.yaml` or `examples/`.

### Port `8000` is already in use

Run uvicorn on a different port:

```bash
python3 -m uvicorn app.main:app --reload --port 8012
```

Or use Docker Compose with an alternate app port:

```bash
APP_PORT=8012 docker compose up --build
```

## Next steps

After completing this guide, review:

- `docs/agent-id-spec.md` for the protocol draft
- `docs/product-documentation.md` for full product and API reference details
- `docs/openid-alignment.md` for OpenID alignment rationale
- `docs/compatibility.md` for compatibility and evolution rules
