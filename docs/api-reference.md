# Agent Identity API Reference

Complete reference for the Agent Identity REST API.

## Base URL

```
http://localhost:8000
```

## Authentication

Agent Identity supports two authentication methods:

### API Key Authentication

Include your API key in the `X-API-Key` header:

```bash
curl -H "X-API-Key: your_api_key" ...
```

### Bearer Token Authentication

Use bearer tokens for OIDC/SAML sessions:

```bash
curl -H "Authorization: Bearer your_token" ...
```

---

## Organizations

### List Organizations

```http
GET /v1/organizations
```

**Response:**
```json
{
  "items": [
    {
      "id": "org_abc123",
      "name": "My Company",
      "slug": "mycompany",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1
}
```

---

## Agent Records

### Create Agent Record

```http
POST /v1/agent-records
```

**Request Body:**
```json
{
  "did": "did:web:example.com/agent-1",
  "display_name": "My AI Agent",
  "environment": "production",
  "protocol_version": "2024-1",
  "record_json": {
    "agent": {
      "name": "My AI Agent",
      "capabilities": ["chat", "code_execution"]
    },
    "authorization": {
      "mode": "autonomous"
    },
    "governance": {
      "status": "active"
    }
  }
}
```

### Get Agent Record

```http
GET /v1/agent-records/{record_id}
```

### List All Agent Records

```http
GET /v1/agent-records
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status |
| `environment` | string | Filter by environment |
| `limit` | int | Page size (default: 50) |
| `offset` | int | Page offset |

### Update Agent Record

```http
PATCH /v1/agent-records/{record_id}
```

### Deprovision Agent

```http
POST /v1/agent-records/{record_id}/deprovision
```

---

## Blueprints

### Create Blueprint

```http
POST /v1/blueprints
```

**Request Body:**
```json
{
  "blueprint_id": "bp-customer-service",
  "display_name": "Customer Service Agent",
  "description": "Standard customer service agent template",
  "publisher": "mycompany.com",
  "sign_in_audience": "single_tenant",
  "credential_policy": {
    "rotation_interval_days": 90,
    "require_rotation": true
  }
}
```

### List Blueprints

```http
GET /v1/blueprints
```

### Get Blueprint

```http
GET /v1/blueprints/{blueprint_id}
```

### Add Agent to Blueprint

```http
POST /v1/blueprints/{blueprint_id}/agent-records
```

### Disable Blueprint

```http
POST /v1/blueprints/{blueprint_id}/disable
```

### Enable Blueprint

```http
POST /v1/blueprints/{blueprint_id}/enable
```

---

## Credentials

### Create Credential

```http
POST /v1/blueprints/{blueprint_id}/credentials
```

**Request Body:**
```json
{
  "credential_id": "cred-prod-1",
  "credential_type": "client_secret",
  "display_name": "Production API Key",
  "expires_at": "2025-01-15T10:30:00Z"
}
```

### Rotate Credential

```http
POST /v1/blueprints/{blueprint_id}/credentials/{credential_id}/rotate
```

### Delete Credential

```http
DELETE /v1/blueprints/{blueprint_id}/credentials/{credential_id}
```

---

## Lifecycle

### Submit for Review

```http
POST /v1/agent-records/{record_id}/submit-review
```

### Approve

```http
POST /v1/agent-records/{record_id}/approve
```

### Activate

```http
POST /v1/agent-records/{record_id}/activate
```

### Suspend

```http
POST /v1/agent-records/{record_id}/suspend
```

### Resume

```http
POST /v1/agent-records/{record_id}/resume
```

### Quarantine

```http
POST /v1/agent-records/{record_id}/quarantine
```

### Renew

```http
POST /v1/agent-records/{record_id}/renew
```

### Archive

```http
DELETE /v1/agent-records/{record_id}
```

---

## Audit

### List Audit Events

```http
GET /v1/audit-events
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `agent_record_id` | string | Filter by agent |
| `action` | string | Filter by action type |
| `limit` | int | Page size |
| `offset` | int | Page offset |

### Lifecycle Events

```http
GET /v1/audit/lifecycle-events
```

---

## Identity Providers

### Create OIDC Provider

```http
POST /v1/identity-providers/oidc
```

**Request Body:**
```json
{
  "organization_id": "org_abc123",
  "client_id": "my-client-id",
  "client_secret": "secret",
  "issuer": "https://login.microsoftonline.com/{tenant}/v2.0",
  " scopes": ["openid", "profile", "email"]
}
```

### Create SAML Provider

```http
POST /v1/identity-providers/saml
```

---

## Error Responses

### 400 Bad Request

```json
{
  "detail": "Invalid request body"
}
```

### 401 Unauthorized

```json
{
  "detail": "Invalid or missing authentication"
}
```

### 403 Forbidden

```json
{
  "detail": "Insufficient permissions"
}
```

### 404 Not Found

```json
{
  "detail": "Resource not found"
}
```

### 409 Conflict

```json
{
  "detail": "Resource already exists"
}
```

---

## Rate Limiting

The API implements in-memory rate limiting:

- **Default limit**: 100 requests per minute
- **Headers**:
  - `X-RateLimit-Limit`: Maximum requests
  - `X-RateLimit-Remaining`: Remaining in window
  - `X-RateLimit-Reset`: Unix timestamp reset
