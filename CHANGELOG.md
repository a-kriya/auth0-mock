# Changelog

## 0.1.1 (2026-10-08)

- `client_credentials` tokens for APIs using the `access_token_authz` dialect now carry the granted scopes in
  the `permissions` claim, as Auth0 does.

## 0.1.0 (2026-10-08)

Initial release.

- OIDC/OAuth 2.0: JWKS, discovery, `/oauth/token` (`client_credentials`, `password`, `password-realm`,
  `authorization_code` with PKCE, rotating `refresh_token`), `/authorize` (`query`, `fragment`, `form_post`,
  `web_message`), Universal-Login-shaped `/u/login`, `/v2/logout`, `/oidc/logout`, `/userinfo`,
  password-change and email-verification ticket pages.
- Management API v2 for tenants, connections, attack protection, resource servers, clients, client grants,
  roles, users (Lucene `q` search), actions (deploy, versions, trigger bindings), prompts, branding,
  email templates, tickets — enough for the `auth0/auth0` Terraform provider to apply a tenant.
- Post-login Actions runtime executing uploaded code with a store-backed `require('auth0')` facade.
- RBAC (`enforce_policies`, `token_dialect`), brute-force protection, blocked users, Auth0 error envelopes.
- Auto-generated local CA, static admin token, identifier pinning, seed/snapshot import and export.
