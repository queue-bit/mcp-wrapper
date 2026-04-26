# MCP Security Wrapper

A security and monitoring proxy that sits between LLM agents and MCP servers. Enforces credential isolation, action whitelisting, and structured audit logging without modifying upstream MCP servers or downstream clients.

**Core principle:** The LLM agent never holds credentials directly. It expresses intent; the wrapper validates, executes, and records.

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Server](#server)
  - [Logging](#logging)
  - [Secret backends](#secret-backends)
  - [HashiCorp Vault](#hashicorp-vault)
  - [MCP servers](#mcp-servers)
  - [Agents](#agents)
- [Running](#running)
- [Verifying the setup](#verifying-the-setup)
- [Network security](#network-security)
- [Development](#development)

---

## Overview

```
Agent (Bearer token) → MCP Security Wrapper → MCP Server (injected credential)
                              │
                         Audit log (SQLite)
```

The wrapper:

1. Authenticates the agent via `Authorization: Bearer <token>`
2. Looks up the agent's permission profile
3. (Phase 2+) Validates the requested tool call against the whitelist
4. Retrieves the MCP server's credential from a secret store at call time
5. Forwards the call to the downstream MCP server
6. Logs the request, decision, and response

---

## Prerequisites

- Python 3.11+
- One or more running MCP servers to proxy
- (Optional) HashiCorp Vault for secret storage

---

## Installation

```bash
git clone <repo>
cd mcp-wrapper
python3 -m venv .venv
source .venv/bin/activate

# Core install
pip install -e .

# With AWS IAM Vault auth
pip install -e ".[vault-aws]"

# With GCP Vault auth
pip install -e ".[vault-gcp]"

# Development (includes test dependencies)
pip install -e ".[dev]"
```

---

## Configuration

All configuration lives in `config/wrapper.toml`. Copy the provided file and edit it for your environment.

### Secret reference format

Anywhere a credential value appears in config, you can use:

| Format | Description |
|---|---|
| `env:VAR_NAME` | Read from environment variable |
| `keyring:service:username` | Read from system keyring (macOS Keychain, libsecret) |
| `vault:path/to/secret#field` | Read from HashiCorp Vault KV (separator is configurable) |
| `literal-value` | Plaintext — **dev/testing only**, logs a warning |

---

### Server

```toml
[server]
host = "127.0.0.1"   # loopback only; use Tailscale IP for LAN access
port = 8080
# tls_cert = "/etc/mcp-wrapper/cert.pem"
# tls_key  = "/etc/mcp-wrapper/key.pem"
```

For LAN deployments, set `host` to your Tailscale IP (`100.x.x.x`) and restrict access to your Tailnet. See [Network security](#network-security).

---

### Logging

```toml
[logging]
db_path   = "audit.db"       # SQLite audit log
# jsonl_path = "audit.jsonl" # optional append-only JSONL alongside SQLite
level     = "INFO"
```

---

### Secret backends

#### Environment variables (simplest)

Set the variable before starting the wrapper:

```bash
export HA_TOKEN="your-homeassistant-token"
export DEFAULT_AGENT_TOKEN="$(openssl rand -base64 32)"
```

Reference in config:

```toml
[mcp_servers.homeassistant]
url        = "http://localhost:8123/mcp"
credential = "env:HA_TOKEN"
```

#### System keyring

Store secrets in your OS keyring (macOS Keychain, GNOME Keyring, KDE Wallet):

```bash
# macOS
security add-generic-password -s mcp-wrapper -a homeassistant -w "your-token"

# Linux (requires python3-keyring or secret-tool)
secret-tool store --label="MCP HA Token" service mcp-wrapper username homeassistant
```

Reference in config:

```toml
credential = "keyring:mcp-wrapper:homeassistant"
```

---

### HashiCorp Vault

#### Storing secrets in Vault

```bash
# Enable KV v2 (if not already enabled)
vault secrets enable -version=2 -path=secret kv

# Store an MCP server credential
vault kv put secret/mcp-wrapper/homeassistant token="your-ha-token"

# Store an agent token
vault kv put secret/mcp-wrapper/agents/personal-assistant token="$(openssl rand -base64 32)"
```

Reference in config with the default `#` separator:

```toml
[mcp_servers.homeassistant]
credential = "vault:mcp-wrapper/homeassistant#token"

[agents.personal-assistant]
token = "vault:mcp-wrapper/agents/personal-assistant#token"
```

The separator is configurable — if your org prefers colons:

```toml
[secrets.vault]
path_field_separator = ":"
# then use: credential = "vault:mcp-wrapper/homeassistant:token"
```

#### Auth method: Token

Simplest option. Good for development.

```toml
[secrets.vault]
addr     = "https://vault.example.com:8200"
kv_mount = "secret"

[secrets.vault.auth]
method = "token"
token  = "env:VAULT_TOKEN"
```

```bash
export VAULT_TOKEN="hvs.your-vault-token"
```

#### Auth method: AppRole

Recommended for on-prem services where you control the credential delivery.

```bash
# In Vault — create a policy
vault policy write mcp-wrapper - <<EOF
path "secret/data/mcp-wrapper/*" { capabilities = ["read"] }
EOF

# Enable AppRole and create a role
vault auth enable approle
vault write auth/approle/role/mcp-wrapper \
    token_policies="mcp-wrapper" \
    token_ttl=1h \
    token_max_ttl=4h

# Get the role_id (not secret — safe to store in config)
vault read auth/approle/role/mcp-wrapper/role-id

# Generate a secret_id (treat as a password)
vault write -f auth/approle/role/mcp-wrapper/secret-id
```

```toml
[secrets.vault]
addr     = "https://vault.example.com:8200"
kv_mount = "secret"

[secrets.vault.auth]
method    = "approle"
role_id   = "env:VAULT_ROLE_ID"
secret_id = "env:VAULT_SECRET_ID"
mount     = "approle"   # default; omit if using the standard mount
```

```bash
export VAULT_ROLE_ID="your-role-id"
export VAULT_SECRET_ID="your-secret-id"
```

#### Auth method: AWS IAM

For EC2 instances, ECS tasks, Lambda functions, or EKS pods with IRSA. No static credentials needed — uses the instance/task/pod IAM role automatically.

```bash
# Requires vault-aws extra
pip install mcp-wrapper[vault-aws]
```

```bash
# In Vault — enable AWS auth and bind to your IAM role or instance profile
vault auth enable aws
vault write auth/aws/role/mcp-wrapper \
    auth_type=iam \
    bound_iam_principal_arn="arn:aws:iam::123456789:role/MyServiceRole" \
    token_policies="mcp-wrapper" \
    token_ttl=1h
```

```toml
[secrets.vault]
addr     = "https://vault.example.com:8200"
kv_mount = "secret"

[secrets.vault.auth]
method = "aws"
role   = "mcp-wrapper"   # Vault role name
mount  = "aws"           # default; omit if using the standard mount
# No credentials in config — boto3 uses the instance/task/pod IAM role
```

boto3 credential resolution order: instance profile → ECS task role → IRSA → environment variables → `~/.aws/credentials`.

#### Auth method: Kubernetes

For pods running in Kubernetes, using the projected service account token.

```bash
# In Vault — enable Kubernetes auth
vault auth enable kubernetes
vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

vault write auth/kubernetes/role/mcp-wrapper \
    bound_service_account_names=mcp-wrapper \
    bound_service_account_namespaces=default \
    token_policies="mcp-wrapper" \
    token_ttl=1h
```

```toml
[secrets.vault]
addr     = "https://vault.example.com:8200"
kv_mount = "secret"

[secrets.vault.auth]
method   = "kubernetes"
role     = "mcp-wrapper"
jwt_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"   # default
mount    = "kubernetes"   # default
```

#### Auth method: GCP

For Compute Engine VMs or workloads using Application Default Credentials (ADC).

```bash
# Requires vault-gcp extra
pip install mcp-wrapper[vault-gcp]
```

```bash
# In Vault — enable GCP auth
vault auth enable gcp
vault write auth/gcp/role/mcp-wrapper \
    type="iam" \
    project_id="my-gcp-project" \
    bound_service_accounts="mcp-wrapper@my-gcp-project.iam.gserviceaccount.com" \
    token_policies="mcp-wrapper" \
    token_ttl=1h
```

```toml
[secrets.vault]
addr     = "https://vault.example.com:8200"
kv_mount = "secret"

[secrets.vault.auth]
method        = "gcp"
role          = "mcp-wrapper"
gcp_auth_type = "iam"   # "iam" for service account ADC, "gce" for metadata server
mount         = "gcp"   # default
```

For `gcp_auth_type = "iam"`, authenticate locally first:

```bash
gcloud auth application-default login
# or for a service account:
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
```

For `gcp_auth_type = "gce"`, no extra setup is needed — the wrapper reads the instance identity token from the GCE metadata server automatically.

#### Vault Enterprise namespaces

```toml
[secrets.vault]
addr      = "https://vault.example.com:8200"
namespace = "admin/my-team"   # omit or leave empty for open-source Vault
```

#### KV v1 (legacy)

```toml
[secrets.vault]
kv_version = 1   # default is 2
kv_mount   = "secret"
```

---

### MCP servers

```toml
[mcp_servers.homeassistant]
url        = "http://localhost:8123/mcp"
credential = "env:HA_TOKEN"

[mcp_servers.gmail]
url        = "https://gmail-mcp.example.com/mcp"
credential = "vault:mcp-wrapper/gmail#token"
```

---

### Agents

Each agent needs a token and a list of MCP servers it can reach:

```toml
[agents.personal-assistant]
token       = "env:PA_TOKEN"
mcp_servers = ["homeassistant", "gmail"]
log_only    = false   # set true during initial observation (Phase 1 mode)
```

Generate agent tokens with sufficient entropy:

```bash
openssl rand -base64 32
```

Store them in environment variables, the system keyring, or Vault. Configure the agent (Claude Code, or any MCP client) to send:

```
Authorization: Bearer <token>
```

---

## Running

```bash
# Set required environment variables
export DEFAULT_AGENT_TOKEN="your-agent-token"
export HA_TOKEN="your-ha-token"          # if using env: backend

# Start the wrapper
source .venv/bin/activate
mcp-wrapper --config config/wrapper.toml

# Override log level
mcp-wrapper --config config/wrapper.toml --log-level DEBUG
```

---

## Verifying the setup

```bash
# Health check (no auth required)
curl http://localhost:8080/health

# List tools available to your agent
curl -H "Authorization: Bearer $DEFAULT_AGENT_TOKEN" \
     http://localhost:8080/mcp/tools/list

# View recent audit log entries
curl -H "Authorization: Bearer $DEFAULT_AGENT_TOKEN" \
     "http://localhost:8080/audit/recent?limit=20"

# Query the SQLite audit log directly
sqlite3 audit.db "SELECT timestamp, agent_id, tool, decision FROM audit_log ORDER BY id DESC LIMIT 20;"
```

---

## Network security

| Deployment | Recommendation |
|---|---|
| Loopback only (agent and wrapper on the same machine) | Default config. Token is sufficient. |
| Trusted LAN | Set `host` to your LAN IP. Use Tailscale — wrapper listens on Tailscale interface only (`100.x.x.x`). |
| Untrusted or mixed LAN | Tailscale required. Configure Tailscale ACLs to restrict which devices can reach the wrapper. |
| Across the internet | Never expose directly. Use Tailscale or WireGuard. Wrapper listens on VPN interface only. |

**Tailscale (recommended for home/small-team):**

```toml
[server]
host = "100.x.x.x"   # your Tailscale IP — find with: tailscale ip -4
port = 8080
```

**TLS (if not using Tailscale):**

```toml
[server]
host     = "0.0.0.0"
port     = 8443
tls_cert = "/etc/mcp-wrapper/cert.pem"
tls_key  = "/etc/mcp-wrapper/key.pem"
```

Use [Caddy](https://caddyserver.com) as a reverse proxy for automatic certificate management.

---

## Development

```bash
source .venv/bin/activate
pip install -e ".[dev]"

# Run all tests
pytest

# Run with output
pytest -v

# Run a specific file
pytest tests/test_credentials.py -v
```

Tests mock all external dependencies (Vault, boto3, google-auth) — no running services required.
