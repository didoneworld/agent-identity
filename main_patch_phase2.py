"""
app/main_patch_phase2.py

Exact additions to make to app/main.py for Phase 2.
This is documentation only — not a standalone runnable file.

---

1. ADD these imports:

    from app.routers.scim_router import router as scim_router
    from app.ssf.emitter import ssf_router
    from app.approval.gate import approval_router

2. ADD these include_router calls (after Phase 1 routers):

    # SCIM 2.0 AgenticIdentity lifecycle (RFC 7643 + RFC 7644 + draft-wahl-scim-agent-schema)
    app.include_router(scim_router, prefix="/v1/scim/v2", tags=["SCIM"])

    # SSF CAEP event receiver management + push/poll delivery
    app.include_router(ssf_router, prefix="/v1/ssf", tags=["SSF"])

    # M-of-N agent provisioning approval gate (WP §3.4)
    app.include_router(approval_router, prefix="/v1/approvals", tags=["Approvals"])

3. WIRE the existing deprovision endpoint to emit SSF events.
   In your existing handler for POST /v1/agent-records/{id}/deprovision,
   add after the DB update:

    from app.ssf.emitter import emit_agent_deprovisioned
    await emit_agent_deprovisioned(
        agent_id=record_id,
        agent_did=record.did,
        organization_slug=org_slug,
        reason="admin_deprovision",
    )

4. ADD to requirements.txt:

    httpx>=0.27.0          # already added in Phase 1

5. ADD environment variables to .env.example:

    # CAAS decision-service URL (for M-of-N approval gate)
    CAAS_API_GATEWAY_URL=http://localhost:3001

---

Full route inventory after Phase 2:

  SCIM:
    GET    /v1/scim/v2/ServiceProviderConfig
    GET    /v1/scim/v2/ResourceTypes
    GET    /v1/scim/v2/Schemas
    GET    /v1/scim/v2/AgenticIdentities              ?filter= &startIndex= &count=
    POST   /v1/scim/v2/AgenticIdentities              → triggers approval gate
    GET    /v1/scim/v2/AgenticIdentities/{id}
    PUT    /v1/scim/v2/AgenticIdentities/{id}
    PATCH  /v1/scim/v2/AgenticIdentities/{id}         PatchOp
    DELETE /v1/scim/v2/AgenticIdentities/{id}         → SSF broadcast

  SSF:
    POST   /v1/ssf/receivers                          register receiver
    DELETE /v1/ssf/receivers/{id}                     deregister
    GET    /v1/ssf/receivers/{id}/events               poll

  Approvals:
    GET    /v1/approvals/                             list pending
    GET    /v1/approvals/{request_id}                 status
    POST   /v1/approvals/{request_id}/decisions       submit vote
"""
