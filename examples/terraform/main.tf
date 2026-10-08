# Minimal tenant provisioned against a running auth0-mock instance.
#
#   export AUTH0_DOMAIN=localhost:4400          # host:port of the emulator (https is implied by the provider)
#   export AUTH0_API_TOKEN=<AUTH0_MOCK_ADMIN_TOKEN>
#   export SSL_CERT_FILE=../../certs/rootCA.pem # Linux: trust the emulator CA; macOS: trust it in the keychain
#   terraform init && terraform apply

terraform {
  required_providers {
    auth0 = {
      source  = "auth0/auth0"
      version = ">= 1.33.0"
    }
  }
  required_version = ">= 1.3.0"
}

provider "auth0" {}

resource "auth0_tenant" "tenant" {
  friendly_name     = "auth0-mock example"
  default_directory = auth0_connection.database.name
  support_email     = "support@example.com"
}

resource "auth0_connection" "database" {
  name     = "Username-Password-Authentication"
  strategy = "auth0"

  options {
    disable_signup         = true
    password_policy        = "good"
    brute_force_protection = true
  }
}

resource "auth0_connection_clients" "database" {
  connection_id   = auth0_connection.database.id
  enabled_clients = [auth0_client.spa.client_id, auth0_client.backend.client_id]
}

resource "auth0_resource_server" "api" {
  name             = "Example API"
  identifier       = "https://api.example.com"
  signing_alg      = "RS256"
  enforce_policies = true
  token_dialect    = "access_token_authz"
  token_lifetime   = 900
}

resource "auth0_resource_server_scopes" "api" {
  resource_server_identifier = auth0_resource_server.api.identifier

  scopes {
    name        = "read:things"
    description = "Read things"
  }
  scopes {
    name        = "write:things"
    description = "Write things"
  }
}

resource "auth0_role" "admin" {
  name        = "Administrator"
  description = "Full access"
}

resource "auth0_role_permissions" "admin" {
  role_id = auth0_role.admin.id

  permissions {
    name                       = "read:things"
    resource_server_identifier = auth0_resource_server.api.identifier
  }
  permissions {
    name                       = "write:things"
    resource_server_identifier = auth0_resource_server.api.identifier
  }

  depends_on = [auth0_resource_server_scopes.api]
}

resource "auth0_client" "spa" {
  name            = "Example SPA"
  app_type        = "spa"
  callbacks       = ["http://localhost:3000"]
  web_origins     = ["http://localhost:3000"]
  oidc_conformant = true
  grant_types = [
    "authorization_code",
    "refresh_token",
    "http://auth0.com/oauth/grant-type/password-realm",
  ]

  jwt_configuration {
    alg = "RS256"
  }

  refresh_token {
    rotation_type   = "rotating"
    expiration_type = "expiring"
    token_lifetime  = 43200
  }
}

resource "auth0_client_credentials" "spa" {
  client_id             = auth0_client.spa.id
  authentication_method = "none"
}

resource "auth0_client" "backend" {
  name            = "Example Backend"
  app_type        = "non_interactive"
  oidc_conformant = true
  grant_types     = ["client_credentials"]

  jwt_configuration {
    alg = "RS256"
  }
}

resource "auth0_client_credentials" "backend" {
  client_id             = auth0_client.backend.id
  authentication_method = "client_secret_post"
}

resource "auth0_client_grant" "backend_api" {
  client_id = auth0_client.backend.id
  audience  = auth0_resource_server.api.identifier
  scopes    = ["read:things"]

  depends_on = [auth0_resource_server_scopes.api]
}

resource "auth0_client_grant" "backend_management" {
  client_id = auth0_client.backend.id
  audience  = "https://${var.auth0_domain}/api/v2/"
  scopes    = ["read:users", "create:users", "update:users", "delete:users", "read:roles"]
}

resource "auth0_user" "alice" {
  connection_name = auth0_connection.database.name
  user_id         = "alice"
  email           = "alice@example.com"
  email_verified  = true
  name            = "Alice Example"
  given_name      = "Alice"
  family_name     = "Example"
  password        = var.user_password
}

resource "auth0_user_roles" "alice" {
  user_id = auth0_user.alice.id
  roles   = [auth0_role.admin.id]
}

variable "auth0_domain" {
  description = "host:port of the emulator, as given to the provider (AUTH0_DOMAIN)"
  type        = string
  default     = "localhost:4400"
}

variable "user_password" {
  type      = string
  sensitive = true
  default   = "Passw0rd!Passw0rd!"
}

output "spa_client_id" {
  value = auth0_client.spa.client_id
}

output "backend_client_id" {
  value = auth0_client.backend.client_id
}

output "backend_client_secret" {
  value     = auth0_client_credentials.backend.client_secret
  sensitive = true
}

output "admin_role_id" {
  value = auth0_role.admin.id
}
