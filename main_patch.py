"""
app/main_patch.py

This file shows ONLY the additions to make to the existing app/main.py.
It is NOT a replacement — add these lines to the existing file.

---

1. ADD these imports near the top of app/main.py:

    from app.routers.discovery import router as discovery_router
    from app.routers.oidc_router import router as oidc_router
    from app.routers.saml_router import router as saml_router
    from app.routers.session_router import router as session_router

2. REPLACE the existing OIDC/SAML include lines with:

    # OIDC — real authorization-code exchange + JWKS validation
    app.include_router(oidc_router, prefix="/v1/sso/oidc", tags=["SSO – OIDC"])

    # SAML — full SP with certificate validation + signed metadata
    app.include_router(saml_router, prefix="/v1/sso/saml", tags=["SSO – SAML"])

    # Session revocation + RP-Initiated Logout + RFC 7009/7662
    app.include_router(session_router, prefix="/v1", tags=["Sessions"])

    # OpenID Discovery + JWKS + Client ID Metadata (must be at root, no prefix)
    app.include_router(discovery_router)

3. ADD required environment variables to .env.example:

    # Server identity
    BASE_URL=https://agent-id.openautonomyx.com

    # RS256 signing key pair (generate with: openssl genrsa -out key.pem 2048)
    SIGNING_KEY_PRIVATE_PEM=
    SIGNING_KEY_PUBLIC_PEM=
    SIGNING_KEY_ID=agent-did-key-1

    # Session TTL
    SESSION_TTL_SECONDS=3600
    POST_LOGOUT_REDIRECT=https://agent-id.openautonomyx.com/logged-out

    # SAML SP certificate + key (generate with: openssl req -x509 -newkey rsa:2048 ...)
    SAML_SP_CERT=
    SAML_SP_KEY=

    # OIDC provider defaults (overridden per-org from DB in production)
    OIDC_ISSUER=
    OIDC_CLIENT_ID=
    OIDC_CLIENT_SECRET=

4. ADD to requirements.txt:

    python-jose[cryptography]>=3.3.0
    httpx>=0.27.0
    python3-saml>=1.16.0
    lxml>=5.2.0
    cryptography>=42.0.0

---

The routes registered after this patch:

  GET  /.well-known/openid-configuration       OpenID Discovery (RFC 8414)
  GET  /.well-known/jwks.json                  JWKS (public keys for JWT verify)
  GET  /.well-known/oauth-client/{client_id}   Client ID Metadata (draft-parecki)

  GET  /v1/sso/oidc/start/{org}                OIDC: initiate (PKCE + state)
  GET  /v1/sso/oidc/callback/{org}             OIDC: exchange + validate + issue

  GET  /v1/sso/saml/metadata/{org}             SAML: SP metadata XML
  POST /v1/sso/saml/register-idp              SAML: ingest + validate IdP metadata
  GET  /v1/sso/saml/start/{org}               SAML: initiate AuthnRequest
  POST /v1/sso/saml/acs/{org}                 SAML: ACS (full assertion validation)
  POST /v1/sso/saml/slo/{org}                 SAML: Single Logout

  POST /v1/session/revoke                      Session revoke (jti-based)
  POST /v1/token/revoke                        RFC 7009 token revocation
  POST /v1/token/introspect                    RFC 7662 token introspection
  GET  /v1/session/logout                      OIDC RP-Initiated Logout
  GET  /v1/sessions                            List active sessions
"""

# This file is documentation only — nothing to execute.
