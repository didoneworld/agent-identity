# Agent DID Python SDK

The Python SDK is a small, adapter-friendly client for the Agent DID control plane. It intentionally stays vendor-neutral and DID-first: callers can supply an API key, bearer token, or dynamic auth provider from their own identity stack.

## Install locally

```bash
pip install -e sdk/python
```

## Quick start

```python
from agentdid_sdk import AgentDidClient, LifecycleRequest

with AgentDidClient.from_env() as client:
    report = client.validate_agent("agent-record-id")
    if report.passed:
        transition = client.activate_agent(
            "agent-record-id",
            reason="production launch",
            ticket_id="SEC-1234",
            requested_by="owner@example.com",
            approved_by="approver@example.com",
        )
        print(transition.new_state)

    dry_run = client.deprovision_agent(
        "agent-record-id",
        request=LifecycleRequest(
            reason="offboarding preview",
            requested_by="secops@example.com",
            dry_run=True,
            idempotency_key="offboard-agent-record-id",
        ),
    )
    print(dry_run.deprovisioning_report)
```

## Authentication adapters

```python
client = AgentDidClient(
    "https://agentdid.example.com",
    auth_provider=lambda: my_identity_platform.current_access_token(),
    headers={"X-Correlation-ID": "corr-123"},
)
```

## Supported operations

- Agent records: list, get, get by DID, upsert.
- Agent lifecycle: validate, submit review, approve, activate, suspend, resume, quarantine, renew, rotate credentials, deprovision, delete.
- Blueprints: get, disable, deprovision children, delete, and generic lifecycle transitions.
- Audit: list all lifecycle events or events scoped to an agent/blueprint.

Use `transition_agent()` or `transition_blueprint()` for future server-side actions without waiting for an SDK release.
