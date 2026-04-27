# MCP Security Wrapper

A security and monitoring proxy that sits between LLM agents and MCP servers. Enforces credential isolation, action whitelisting, parameter validation, rate limiting, and structured audit logging without modifying upstream MCP servers or downstream clients.

**Core principle:** The LLM agent never holds credentials directly. It expresses intent; the wrapper validates, executes, and records.

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Config files](#config-files)
  - [Secret reference format](#secret-reference-format)
  - [Server](#server)
  - [Logging](#logging)
  - [Secret backends](#secret-backends)
  - [HashiCorp Vault](#hashicorp-vault)
  - [MCP servers](#mcp-servers)
  - [Agents](#agents)
  - [Rules](#rules)
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
3. Checks the requested tool against the agent's whitelist (default-deny)
4. Validates tool parameters against per-rule constraints
5. Enforces per-agent, per-tool rate limits
6. Retrieves the MCP server's credential from a secret store at call time
7. Forwards the call to the downstream MCP server via JSON-RPC 2.0
8. Logs every request, decision, and response — tagged with agent and MCP server

Tools listed via `/mcp/tools/list` are filtered to only those the agent is permitted to call, so the LLM never sees tools it can't use.

---

## Prerequisites

- Python 3.11+
- One or more running MCP servers to proxy
- (Optional) HashiCorp Vault for secret storage

### Home Assistant

The HA MCP server is available at `http://<host>:8123/api/mcp` and requires the **Model Context Protocol** integration to be enabled:

1. Go to **Settings → Devices & Services → Add Integration**
2. Search for **Model Context Protocol** and add it
3. Generate a Long-Lived Access Token at `http://<host>:8123/profile/security`

Requires Home Assistant 2025.1 or later.

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

### Config files

Configuration is split across two files that are **not committed to git** — copy the examples and edit them for your environment:

```bash
cp config/wrapper.toml.example config/wrapper.toml
cp config/rules.toml.example   config/rules.toml
```

| File | Purpose |
|---|---|
| `config/wrapper.toml` | Server, logging, secret backends, MCP servers, agent identity |
| `config/rules.toml` | Per-agent tool whitelist, parameter constraints, rate limits |

---

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

Every audit log entry includes the agent ID, session ID, MCP server name, tool, parameters, decision, and latency. Denied calls include a `denial_reason`.

---

### Secret backends

#### Environment variables (simplest)

```bash
export HA_TOKEN="your-homeassistant-token"
export DEFAULT_AGENT_TOKEN="$(openssl rand -base64 32)"
```

```toml
[mcp_servers.homeassistant]
url        = "http://localhost:8123/api/mcp"
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

```toml
[mcp_servers.homeassistant]
credential = "vault:mcp-wrapper/homeassistant#token"

[agents.personal-assistant]
token = "vault:mcp-wrapper/agents/personal-assistant#token"
```

The separator is configurable:

```toml
[secrets.vault]
path_field_separator = ":"
# then use: credential = "vault:mcp-wrapper/homeassistant:token"
```

#### Auth method: Token

```toml
[secrets.vault]
addr     = "https://vault.example.com:8200"
kv_mount = "secret"

[secrets.vault.auth]
method = "token"
token  = "env:VAULT_TOKEN"
```

#### Auth method: AppRole

```toml
[secrets.vault]
addr     = "https://vault.example.com:8200"
kv_mount = "secret"

[secrets.vault.auth]
method    = "approle"
role_id   = "env:VAULT_ROLE_ID"
secret_id = "env:VAULT_SECRET_ID"
mount     = "approle"
```

#### Auth method: AWS IAM

```bash
pip install mcp-wrapper[vault-aws]
```

```toml
[secrets.vault.auth]
method = "aws"
role   = "mcp-wrapper"
mount  = "aws"
# No credentials in config — boto3 uses the instance/task/pod IAM role
```

boto3 credential resolution order: instance profile → ECS task role → IRSA → environment variables → `~/.aws/credentials`.

#### Auth method: Kubernetes

```toml
[secrets.vault.auth]
method   = "kubernetes"
role     = "mcp-wrapper"
jwt_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
mount    = "kubernetes"
```

#### Auth method: GCP

```bash
pip install mcp-wrapper[vault-gcp]
```

```toml
[secrets.vault.auth]
method        = "gcp"
role          = "mcp-wrapper"
gcp_auth_type = "iam"   # "iam" for service account ADC, "gce" for metadata server
mount         = "gcp"
```

#### Vault Enterprise namespaces

```toml
[secrets.vault]
namespace = "admin/my-team"   # omit or leave empty for open-source Vault
```

#### KV v1 (legacy)

```toml
[secrets.vault]
kv_version = 1
kv_mount   = "secret"
```

---

### MCP servers

```toml
[mcp_servers.homeassistant]
url        = "http://localhost:8123/api/mcp"
credential = "env:HA_TOKEN"

[mcp_servers.gmail]
url        = "https://gmail-mcp.example.com/mcp"
credential = "vault:mcp-wrapper/gmail#token"
```

---

### Agents

Each agent needs a token, a list of MCP servers it can reach, and an enforcement mode:

```toml
[agents.personal-assistant]
token       = "env:PA_TOKEN"
mcp_servers = ["homeassistant", "gmail"]
log_only    = false   # set true to observe without enforcing (Phase 1 mode)
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

### Rules

Rules live in `config/rules.toml` and are loaded automatically alongside `wrapper.toml`. Each agent has its own ruleset. Anything not explicitly listed is **denied by default**.

#### Basic allowlist

```toml
[[agents.personal-assistant.rules]]
tool = "GetDateTime"

[[agents.personal-assistant.rules]]
tool = "Hass*"          # fnmatch glob — matches all Hass* tools
```

#### Parameter constraints

Constrain what values a tool can receive. All constraints are optional and combinable:

```toml
[[agents.personal-assistant.rules]]
tool = "HassLightSet"
allowed_params = {brightness = {minimum = 0, maximum = 80}}

[[agents.personal-assistant.rules]]
tool = "gmail.send"
allowed_params = {to = {allowlist = ["known@example.com"]}}

[[agents.personal-assistant.rules]]
tool = "homeassistant.turn_on"
allowed_params = {entity_id = {pattern = "^light\\..*"}}
```

| Constraint | Type | Description |
|---|---|---|
| `allowlist` | list of strings | Value must be one of these |
| `pattern` | string (regex) | Value must match — applied to `str(value)` |
| `minimum` | number | Numeric lower bound (inclusive) |
| `maximum` | number | Numeric upper bound (inclusive) |

#### Rate limits

```toml
[[agents.personal-assistant.rules]]
tool = "HassLightSet"
rate_limit = {per_minute = 5}

[[agents.personal-assistant.rules]]
tool = "gmail.send"
rate_limit = {per_minute = 2, per_hour = 10}
```

Rate limits are per-agent and per-tool, tracked in-memory with a moving window. Limits reset on wrapper restart.

#### `log_only` mode

Set `log_only = true` on an agent in `wrapper.toml` to bypass all enforcement and observe traffic before writing rules. Useful when onboarding a new agent or MCP server.

---

## Running

```bash
# Set required environment variables
export DEFAULT_AGENT_TOKEN="your-agent-token"
export HA_TOKEN="your-ha-token"

# Start the wrapper
source .venv/bin/activate
mcp-wrapper --config config/wrapper.toml

# Override log level
mcp-wrapper --config config/wrapper.toml --log-level DEBUG
```

`rules.toml` is loaded automatically from the same directory as `wrapper.toml`.

---

## Verifying the setup

A `test.sh` helper is included for manual testing. Source it to load helper functions into your shell:

```bash
source test.sh

health           # GET /health — no auth required
tools_list       # list tools visible to your agent (filtered by rules)
audit [limit]    # view recent audit log entries
call_tool <name> [json_params]   # call a tool through the wrapper
```

Or run commands directly:

```bash
./test.sh health
./test.sh tools_list
./test.sh call_tool GetDateTime '{}'
./test.sh audit 20
```

Manual curl:

```bash
# Health check
curl http://localhost:8080/health

# List tools
curl -H "Authorization: Bearer $DEFAULT_AGENT_TOKEN" http://localhost:8080/mcp/tools/list

# Call a tool
curl -H "Authorization: Bearer $DEFAULT_AGENT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"tool": "GetDateTime", "params": {}}' \
     http://localhost:8080/mcp/tools/call

# View audit log
curl -H "Authorization: Bearer $DEFAULT_AGENT_TOKEN" "http://localhost:8080/audit/recent?limit=20"

# Query SQLite directly
sqlite3 audit.db "SELECT timestamp, agent_id, mcp_server, tool, decision, denial_reason FROM audit_log ORDER BY id DESC LIMIT 20;"
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
