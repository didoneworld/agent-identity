# Get Started with Agent Identity

This guide walks you through setting up Agent Identity and creating your first agent.

## Prerequisites

Before you begin, ensure you have:

- **Docker** (version 20.10 or later) and Docker Compose, OR
- **Python** 3.11 or later with pip

## Option 1: Run with Docker (Recommended)

### Step 1: Pull the Docker Image

```bash
docker pull ghcr.io/didoneworld/agent-identity:latest
```

### Step 2: Start the Container

```bash
docker run -d \
  --name agent-identity \
  -p 8000:8000 \
  -v agent-identity-data:/app/data \
  ghcr.io/didoneworld/agent-identity:latest
```

### Step 3: Verify the Service

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{"status": "ok", "version": "1.0.0"}
```

### Step 4: Bootstrap Your Organization

```bash
curl -X POST http://localhost:8000/v1/bootstrap \
  -H "Content-Type: application/json" \
  -d '{
    "organization_name": "My Company",
    "organization_slug": "mycompany",
    "api_key_label": "admin-key"
  }'
```

Response:
```json
{
  "organization_id": "org_abc123",
  "api_key": "aid_live_xxx...",
  "api_key_id": "key_xxx",
  "organization_slug": "mycompany"
  }
}
```

**⚠️ Important**: Save the `api_key` - this is the only time it will be shown!

---

## Option 2: Run with Python

### Step 1: Clone the Repository

```bash
git clone https://github.com/didoneworld/agent-did.git
cd agent-did
```

### Step 2: Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Start the Server

```bash
python -m uvicorn app.main:app --reload --port 8000
```

### Step 5: Bootstrap

Follow Step 4 from Docker instructions above.

---

## Access the Admin Console

Open your browser to:
```
http://localhost:8000/
```

Use your API key to authenticate:
- **Header**: `X-API-Key`
- **Value**: Your admin key from bootstrap

---

## Create Your First Agent

### Using cURL

```bash
curl -X POST http://localhost:8000/v1/agent-records \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:web:mycompany.com/chat-assistant",
    "display_name": "Customer Chat Assistant",
    "environment": "production",
    "protocol_version": "2024-1",
    "record_json": {
      "agent": {
        "name": "Customer Chat Assistant",
        "capabilities": ["chat", "knowledge_retrieval"]
      },
      "authorization": {
        "mode": "autonomous"
      },
      "governance": {
        "status": "active"
      }
    }
  }'
```

### Using the Admin Console

1. Navigate to `/`
2. Click **Agent Records**
3. Click **New Agent**
4. Fill in the form

---

## Next Steps

| Task | Guide |
|------|-------|
| Learn lifecycle management | [Lifecycle Management](./lifecycle-management.md) |
| Configure blueprints | [Blueprint Guide](./entra-blueprint-alignment.md) |
| Explore the API | [API Reference](./product-documentation.md) |
| Understand the protocol | [Protocol Spec](./agent-id-spec.md) |

---

## Troubleshooting

### Port Already in Use

If port 8000 is taken:

```bash
# Docker
docker run -d -p 8080:8000 ghcr.io/didoneworld/agent-identity:latest

# Python
python -m uvicorn app.main:app --reload --port 8080
```

### Database Permission Errors

Ensure the data directory is writable:

```bash
chmod 755 data/  # Linux/macOS
```

### Cannot Connect

Check the container is running:

```bash
docker ps | grep agent-identity
docker logs agent-identity
```

---

## Stopping the Service

### Docker

```bash
docker stop agent-identity
# To remove: docker rm agent-identity
```

### Python

Press `Ctrl+C` in the terminal, or:

```bash
# Find the process
ps aux | grep uvicorn
# Kill it
kill <PID>
```
