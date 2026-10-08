# auth0-mock

A configurable, self-contained emulator of [Auth0](https://auth0.com) for local development and end-to-end
testing. It serves the OIDC/OAuth 2.0 endpoints applications use to log in, enough of the Management API v2
for the [`auth0/auth0` Terraform provider](https://registry.terraform.io/providers/auth0/auth0) to provision a
tenant, and a runtime that executes your **post-login Actions** on every login.

> auth0-mock is an independent open-source project and is not affiliated with, endorsed by, or supported by
> Okta or Auth0. Auth0 is a trademark of Okta, Inc.

## Why

Test suites that log in against a real Auth0 tenant pay for it with rate limits, shared mutable users,
secrets to distribute and a network dependency. auth0-mock replaces the tenant with a process you own, while
keeping the parts that matter faithful: the same endpoints and payload shapes, RS256 JWTs validated through
JWKS, RBAC scope filtering, brute-force blocking, Auth0's error envelopes, and your real Action code.

Because the Management API is broad enough for Terraform, the emulator can be provisioned by the **same
Terraform module that configures your real tenants**, so roles, permissions, clients, grants and Actions never
drift from production.

## Quick start

```bash
# Docker
docker run --rm -p 4400:4400 -v "$PWD/certs:/certs" \
  -e AUTH0_MOCK_ADMIN_TOKEN=change-me ghcr.io/a-kriya/auth0-mock

# or from a checkout (the npm package is not published yet)
npm install && npm start -- --admin-token change-me
```

The emulator now answers on `https://localhost:4400/` with a locally generated certificate authority written to
`./certs/rootCA.pem` (see [TLS](#tls-and-trust)). Check it:

```bash
curl --cacert certs/rootCA.pem https://localhost:4400/.well-known/openid-configuration
curl --cacert certs/rootCA.pem -H 'Authorization: Bearer change-me' https://localhost:4400/api/v2/tenants/settings
```

Then provision a tenant, either with Terraform ([examples/terraform](examples/terraform)), with a seed file
(`--seed examples/seed.json`, see [Seeds and snapshots](#seeds-and-snapshots)), or by calling the Management
API directly.

Programmatic use (for example in a vitest/jest global setup):

```ts
import { createAuth0Mock } from 'auth0-mock';

const mock = await createAuth0Mock({ tls: 'off', port: 0, adminToken: 'test' });
const server = await mock.listen(); // server.issuer === 'http://localhost:<port>/'
// ... call server.url + '/api/v2/...' with the admin token, or mock.importSeed(seed)
await server.close();
```

## Configuration

Every option can be given as an environment variable, a CLI flag, or a key in a JSON config file
(`--config auth0-mock.config.json`). Flags override environment variables, which override the file.

| Key (file / programmatic) | Environment variable                        | Flag                         | Default                                    | Description                                                                                                                                                             |
| ------------------------- | ------------------------------------------- | ---------------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `port`                    | `AUTH0_MOCK_PORT`                           | `--port`                     | `4400`                                     | TCP port                                                                                                                                                                |
| `host`                    | `AUTH0_MOCK_HOST`                           | `--host`                     | `0.0.0.0`                                  | Bind address                                                                                                                                                            |
| `issuer`                  | `AUTH0_MOCK_ISSUER`                         | `--issuer`                   | `https://localhost:<port>/`                | Issuer placed in tokens and used for the Management API audience (`<issuer>api/v2/`). Set it to the address your clients use, e.g. `https://host.docker.internal:4400/` |
| `tls`                     | `AUTH0_MOCK_TLS`                            | `--tls`                      | `auto`                                     | `auto` (generate a local CA), `provided` (`tlsCert`/`tlsKey`), `off` (plain HTTP)                                                                                       |
| `tlsDir`                  | `AUTH0_MOCK_TLS_DIR`                        | `--tls-dir`                  | `./certs`                                  | Where generated TLS material and the JWT signing key are stored                                                                                                         |
| `tlsSans`                 | `AUTH0_MOCK_TLS_SANS`                       | `--tls-sans`                 | `localhost,127.0.0.1,host.docker.internal` | Subject alternative names of the generated certificate                                                                                                                  |
| `tlsCert`, `tlsKey`       | `AUTH0_MOCK_TLS_CERT`, `AUTH0_MOCK_TLS_KEY` | `--tls-cert`, `--tls-key`    |                                            | PEM files for `tls=provided`                                                                                                                                            |
| `signingKey`              | `AUTH0_MOCK_SIGNING_KEY`                    | `--signing-key`              | `<tlsDir>/jwt-signing-key.pem`             | RS256 private key (PKCS#8 PEM); generated when missing                                                                                                                  |
| `adminToken`              | `AUTH0_MOCK_ADMIN_TOKEN`                    | `--admin-token`              |                                            | Static bearer accepted by the Management API with every scope                                                                                                           |
| `seed`                    | `AUTH0_MOCK_SEED`                           | `--seed`                     |                                            | Seed/snapshot JSON loaded at boot and on `/__mock/reset`                                                                                                                |
| `idPins`                  | `AUTH0_MOCK_ID_PINS`                        | `--id-pins`                  |                                            | JSON file pinning generated identifiers by name                                                                                                                         |
| `acceptAnyClientSecret`   | `AUTH0_MOCK_ACCEPT_ANY_CLIENT_SECRET`       | `--accept-any-client-secret` | `false`                                    | Skip client secret verification                                                                                                                                         |
| `accessTokenTtl`          | `AUTH0_MOCK_ACCESS_TOKEN_TTL`               | `--access-token-ttl`         | `86400`                                    | Lifetime (s) when the audience has no resource server                                                                                                                   |
| `idTokenTtl`              | `AUTH0_MOCK_ID_TOKEN_TTL`                   | `--id-token-ttl`             | `36000`                                    | Fallback ID token lifetime (s)                                                                                                                                          |
| `refreshTokenTtl`         | `AUTH0_MOCK_REFRESH_TOKEN_TTL`              | `--refresh-token-ttl`        | `2592000`                                  | Fallback refresh token lifetime (s)                                                                                                                                     |
| `bruteForceMaxAttempts`   | `AUTH0_MOCK_BRUTE_FORCE_MAX_ATTEMPTS`       | `--brute-force-max-attempts` | `10`                                       | Used when attack protection has no `max_attempts`                                                                                                                       |
| `logLevel`                | `AUTH0_MOCK_LOG_LEVEL`                      | `--log-level`                | `info`                                     | `silent`, `error`, `warn`, `info`, `debug` (logs every request)                                                                                                         |

Keep the **issuer consistent** across everything that talks to the emulator: browsers, backends validating
tokens (`iss` must match) and Terraform (`AUTH0_DOMAIN` must be the issuer's host and port). In Docker
Compose that usually means `https://host.docker.internal:4400/` or the service name.

## TLS and trust

Auth0 SDKs, `auth0-spa-js`, the `auth0` Node/Go/Python libraries and the Terraform provider all hard-code
`https://`, so the emulator serves TLS by default. In `auto` mode it creates a certificate authority
(`rootCA.pem`), a server certificate covering `tlsSans`, and the JWT signing key in `tlsDir`, reusing them on
restart. Trust the CA where needed:

| Consumer                     | How                                                                                                                                                                 |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Node.js                      | `NODE_EXTRA_CA_CERTS=/path/to/rootCA.pem`                                                                                                                           |
| Python (`requests`, `httpx`) | `REQUESTS_CA_BUNDLE=... SSL_CERT_FILE=...`                                                                                                                          |
| Go (Terraform) on Linux      | `SSL_CERT_FILE=/path/to/rootCA.pem`                                                                                                                                 |
| Go (Terraform) on macOS      | Go trusts only the keychain: `security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db rootCA.pem`, or run Terraform in a Linux container |
| Browsers                     | Import `rootCA.pem`, or generate the material with [mkcert](https://github.com/FiloSottile/mkcert) (`mkcert -install`) and use `tls=provided`                       |
| curl                         | `--cacert rootCA.pem`                                                                                                                                               |

The CA is also served at `GET /__mock/ca.pem`. Clients that accept plain HTTP (for example `auth0-spa-js`
with an `http://` domain) can use `tls=off`.

## Provisioning with Terraform

```hcl
provider "auth0" {}  # AUTH0_DOMAIN=localhost:4400  AUTH0_API_TOKEN=<adminToken>
```

The provider adds `https://` itself; give it the issuer's host and port and the static admin token (which the
Management API accepts with every scope). On Linux set `SSL_CERT_FILE` to the CA; on macOS trust the CA in the
keychain or run Terraform in a container (see [examples/docker-compose.yml](examples/docker-compose.yml)).

State is meaningful only while the emulator runs (state lives in memory), so treat it like Localstack: start
the emulator, `terraform init && terraform apply -auto-approve` with a fresh local state, and export a
snapshot if you want to boot faster next time.

Resources known to apply cleanly with `auth0/auth0` ≥ 1.33: `auth0_tenant`, `auth0_connection`,
`auth0_connection_clients`, `auth0_attack_protection`, `auth0_resource_server`,
`auth0_resource_server_scopes`, `auth0_client`, `auth0_client_credentials`, `data.auth0_client`,
`auth0_client_grant`, `auth0_role`, `auth0_role_permissions`, `auth0_user`, `auth0_user_roles`,
`auth0_action`, `auth0_trigger_actions`, `auth0_prompt`, `auth0_branding_theme`, `auth0_email_template`.
After apply, `terraform plan` reports no changes (the first plan after creating a connection shows Auth0's
usual "changed outside Terraform" note for option defaults).

## Seeds and snapshots

`GET /__mock/snapshot` exports the provisioned tenant as one JSON document; `POST /__mock/snapshot` (or
`--seed file.json`, or `mock.importSeed(doc)`) loads it. The same format doubles as a **declarative seed**:
every section is an array of Management API objects and entries may be partial. Identifiers you provide are
kept; missing ones are generated (or pinned, see below); users may carry a plain `password` and a `roles`
list (by id or name); actions may set `"deploy": true`; trigger bindings may reference actions by name.
As on Auth0, a database connection only authenticates clients listed in its `enabled_clients`, so give
clients fixed `client_id`s and list them there. See [examples/seed.json](examples/seed.json).

```jsonc
{
  "version": 1,
  "tenant": { "default_directory": "Username-Password-Authentication" },
  "connections": [{ "name": "Username-Password-Authentication", "strategy": "auth0" }],
  "resourceServers": [
    { "identifier": "https://api.example.com", "enforce_policies": true, "scopes": [{ "value": "read:things" }] },
  ],
  "roles": [{ "name": "Reader" }],
  "rolePermissions": {
    "Reader": [{ "permission_name": "read:things", "resource_server_identifier": "https://api.example.com" }],
  },
  "clients": [{ "name": "Example SPA", "app_type": "spa", "callbacks": ["http://localhost:3000"] }],
  "users": [
    {
      "connection": "Username-Password-Authentication",
      "email": "bob@example.com",
      "password": "Passw0rd!Passw0rd!",
      "roles": ["Reader"],
    },
  ],
}
```

### Pinning identifiers

Auth0 generates client and role identifiers, and so does the emulator. When configuration outside the
emulator hard-codes identifiers (environment files with client IDs, test fixtures with role IDs), pin them by
resource name so Terraform-created resources receive the values you expect:

```json
{
  "clients": { "Example SPA": "exampleSpaClientId00000000000000" },
  "clientSecrets": { "Example Backend": "example-backend-secret" },
  "roles": { "Reader": "rol_reader00000000" },
  "resourceServers": {},
  "connections": {}
}
```

## What is emulated

**Authentication API**

- `GET /.well-known/jwks.json`, `GET /.well-known/openid-configuration`
- `POST /oauth/token`: `client_credentials`, `password`, `http://auth0.com/oauth/grant-type/password-realm`,
  `authorization_code` (PKCE `S256`/`plain`, single-use codes), `refresh_token` (rotating or not, reuse detection);
  `POST /oauth/revoke`
- `GET /authorize` with `response_type` `code` / `token` / `id_token` and `response_mode` `query`, `fragment`,
  `form_post`, `web_message` (silent authentication for `auth0-spa-js`), `prompt=none|login`, `login_hint`,
  session cookie based SSO
- `GET|POST /u/login`: identifier-first login page with New Universal Login selectors
  (`input[name=username]`, `input[name=password]`, `button[name=action][value=default]`, `#error-element-password`)
- `GET /v2/logout`, `GET /oidc/logout` (with `returnTo` validation), `GET /userinfo`
- `GET|POST /lo/reset?ticket=` (password change), `GET /u/email-verification?ticket=`

**Tenant behaviour**

- RBAC: with `enforce_policies` the `scope` is the intersection of requested scopes and the user's role
  permissions; with `token_dialect = access_token_authz` a `permissions` claim lists them all
- Token lifetimes from the resource server (`token_lifetime`) and client (`jwt_configuration`, `refresh_token`)
- Clients must hold the grant type, be enabled on the connection, use a registered callback, and (when
  confidential) present their secret
- Brute-force protection from `attack-protection/brute-force-protection` (`max_attempts`, per identifier and IP,
  `blocked_for` on the user, `429 too_many_attempts` with Auth0's message), `blocked` users
  (`403 unauthorized: user is blocked`), `403 invalid_grant: Wrong email or password.`
- Auth0's error envelopes: `{ error, error_description }` for authentication,
  `{ statusCode, error, message, errorCode }` for the Management API

**Post-login Actions**

Every deployed action bound to the `post-login` trigger runs, in binding order, on password, code, refresh
token and silent logins. The `event` (`user`, `client`, `connection`, `authorization.roles`, `request`,
`secrets`, `transaction`, `session`, `stats`, `tenant`) and `api` (`access.deny`, `accessToken.setCustomClaim`/
`addScope`/`removeScope`, `idToken.setCustomClaim`, `user.setAppMetadata`/`setUserMetadata`, `session.revoke`,
`validation.error`, `cache`) follow Auth0's post-login `v3` contract; MFA and redirect APIs are no-ops.
`require('auth0')` returns a facade over the emulator's own store with the `{ data }` response shape of the
v4+ SDK (`users.get/getRoles/getPermissions/update/getAll/assignRoles/deleteRoles`, `usersByEmail.getByEmail`,
`roles.getAll/get`, `connections.getAll`, `AuthenticationClient.database.changePassword`). Node built-ins
(`crypto`, `url`, `util`, ...) can be required; other packages throw.

**Management API v2** (`Authorization: Bearer` with the admin token, or a `client_credentials` token for the
`<issuer>api/v2/` audience checked against the client grant's scopes)

- `tenants/settings`; `attack-protection/{brute-force-protection,suspicious-ip-throttling,breached-password-detection,bot-detection,captcha}`; `prompts`; `branding`, `branding/themes`; `emails/provider`; `email-templates`
- `connections` (+ `/clients` with checkpoint pagination, `/users`), `resource-servers` (by id or identifier),
  `clients` (+ `rotate-secret`), `client-grants`, `roles` (+ `/permissions`, `/users`)
- `users` (Lucene `q` with `search_engine=v3`, `sort`, `fields`, pagination), `users-by-email`,
  `users/:id/{roles,permissions,enrollments,logs}`, `user-blocks`, `tickets/{password-change,email-verification}`
- `actions/actions` (+ `/deploy`, `/versions`), `actions/triggers`, `actions/triggers/:id/bindings`

Lists return a bare array by default and `{ start, limit, length, total, <items> }` with
`include_totals=true`; Actions endpoints return `{ <items>, total, per_page, page, start, limit, length }`.

**Control plane** (`/__mock`, never part of a real tenant)

`GET /__mock/health`, `GET /__mock/ca.pem`, `POST /__mock/reset`, `GET|POST /__mock/snapshot`,
`POST /__mock/users/:id/unblock`.

### Not emulated

MFA, passwordless, social and enterprise connections, organizations, log streams, custom domains, email
delivery (templates are stored, nothing is sent), Actions triggers other than `post-login`, hooks and rules,
device authorization, token exchange.

## Development

```bash
npm install
npm run dev        # node --watch, https://localhost:4400/
npm test           # vitest (black-box over HTTP)
npm run lint       # tsc, oxlint, oxfmt --check
npm run build      # tsdown → dist/
```

## License

[MIT](LICENSE)
