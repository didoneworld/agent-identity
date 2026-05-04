# Roadmap

## Near Term

- Clarify recommended W3C DID methods by deployment model
- Add JSON Schema representations alongside YAML examples
- Define binding guidance for A2A, ACP, and ANP more formally
- Add examples for registry, tracing, and approval records

## Medium Term

- Publish compatibility and deprecation policy in more detail
- Add protocol test vectors and validation fixtures
- Define extension namespaces and collision rules

## Longer Term

- Evaluate coexistence with future identity protocols without breaking DID-first consumers
- Add reference implementations in multiple languages

---

## Phase 1 — Identity Core Hardening ✅

Completed on `feature/phase1-3-authzen-integration`.

- Real OAuth 2.1 / PKCE authorization-code exchange replacing trusted-callback stub
- JWKS validation with key rotation support and TTL cache
- OpenID Discovery (`/.well-known/openid-configuration`) with OIDC-A agent claims
- JWKS endpoint + Client ID Metadata Document (draft-parecki)
- SAML SP hardening: certificate validation, signed metadata ingestion, full assertion checks
- RFC 7009 token revocation, RFC 7662 introspection, OIDC RP-Initiated Logout
- SSF CAEP SessionRevoked emitter (stub upgraded to real delivery in Phase 2)

## Phase 2 — SCIM AgenticIdentity Lifecycle ✅

Completed on `feature/phase1-3-authzen-integration`.

- SCIM 2.0 `AgenticIdentity` resource type (draft-wahl-scim-agent-schema)
- Full CRUD: GET/POST/PUT/PATCH/DELETE `/v1/scim/v2/AgenticIdentities`
- SCIM DELETE triggers SSF CAEP `agent.deprovisioned` broadcast to all registered receivers
- SCIM PATCH `active=false` emits `agent.status-change` (Active → Suspended)
- M-of-N provisioning approval gate with CAAS decision-service bridge
- SSF receiver registry with push (HTTP) and poll delivery modes

## Phase 3 — Agent-Auth / AuthZEN SDK Wiring ✅

Completed on `feature/phase1-3-authzen-integration`.

- `app/authzen/` package: async AuthZEN 1.0 PEP client using `app.config.settings`
- Canonical vocabulary: `AgentSubject`, `AgentAction`, `AgentResource`, `AgentContext`
- FastAPI `require_authzen()` Depends() factory for route-level enforcement
- Approval gate wired: AuthZEN pre-flight on `PROVISION` + `APPROVE`/`REJECT` votes
- Fail-open/fail-closed controlled by `AUTHZEN_FAIL_OPEN` env var
- `AgentAction.DELEGATE` + `IMPERSONATE` pre-wired for Phase 4 OBO/token-exchange

## Phase 4 — RFC 8693 Token Exchange + CIBA + OpenFGA (Planned)

- OAuth 2.0 Token Exchange (RFC 8693) — `POST /v1/token-exchange`
- CIBA poll/ping/push modes for async agent operations
- Recursive delegation chain with scope attenuation
- AuthZEN `POST /access/v1/evaluation` server endpoint on CAAS
- OpenFGA-compatible FGA model (groups, inheritance, versioning)
- OpenID Federation trust chain for cross-org agent-to-agent trust
- OpenAPI 3.1 conformance test suite
