# MCP Security Wrapper

A security and monitoring proxy that sits between LLM agents and MCP servers. Enforces credential isolation, action whitelisting, parameter validation, rate limiting, DLP scanning, and structured audit logging without modifying upstream MCP servers or downstream clients.

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
  - [Human approval gate](#human-approval-gate)
    - [Mobile approvals via Slack or Telegram](#mobile-approvals-via-slack-or-telegram)
  - [Anomaly detection](#anomaly-detection)
  - [DLP](#dlp)
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
3. Checks the requested tool against the agent's allowlist (default-deny)
4. Validates tool parameters against per-rule constraints
5. Enforces per-agent, per-tool rate limits
6. Runs outbound DLP — scans params for secrets, PII, and sensitive data before forwarding
7. Optionally pauses for human approval (`require_approval` on a rule, or a DLP `approve` pattern)
8. Retrieves the MCP server's credential from a secret store at call time
9. Forwards the call to the downstream MCP server via JSON-RPC 2.0
10. Runs inbound DLP — scans the response for prompt-injection attempts before returning it to the agent
11. Logs every request, decision, and response — tagged with agent and MCP server
12. Flags anomalies: denial bursts, first-time tool use, and off-hours calls

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
cp config/mcp-servers.toml.example  config/mcp-servers.toml
cp config/rules-defaults.toml.example config/rules-defaults.toml
cp config/rules-agents.toml.example  config/rules-agents.toml
```

| File | Purpose |
|---|---|
| `config/mcp-servers.toml` | Server, logging, secret backends, MCP servers, agent identity |
| `config/rules-defaults.toml` | Default rules per MCP server (tool whitelist, param constraints, rate limits) |
| `config/rules-agents.toml` | Per-agent rule overrides (replaces server defaults for that agent) |

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

Rules live in two files that are loaded automatically from the same directory as `mcp-servers.toml`:

| File | Purpose |
|---|---|
| `rules-defaults.toml` | Default rules per MCP server — shared across all agents |
| `rules-agents.toml` | Per-agent overrides — replaces the server default for that agent |

Anything not explicitly listed is **denied by default**. Tools visible via `/mcp/tools/list` are filtered to only those the agent is permitted to call.

#### `rules-defaults.toml` — server defaults

Each top-level section is the MCP server name. `allow` lists tools that pass through without constraints. `constrain` lists tools that are allowed but subject to parameter validation or rate limits.

```toml
[homeassistant]
allow = [
  "GetDateTime",
  "GetLiveContext",
  "Hass*",          # fnmatch glob — matches all tools starting with Hass
]

[homeassistant.constrain.HassLightSet]
allowed_params = {brightness = {minimum = 0, maximum = 80}}
rate_limit = {per_minute = 5}

[homeassistant.constrain.HassTurnOn]
allowed_params = {entity_id = {pattern = "^light\\..*"}}
rate_limit = {per_minute = 10, per_hour = 60}
```

#### `rules-agents.toml` — per-agent overrides

Structure mirrors `rules-defaults.toml` but nested under the agent ID. An override **replaces** the server default for that agent entirely — there is no merging.

```toml
[personal-assistant.homeassistant]
allow = ["GetDateTime"]   # this agent only gets GetDateTime; Hass* denied

[restricted-bot.homeassistant]
allow = ["GetDateTime", "GetLiveContext"]

[restricted-bot.homeassistant.constrain.HassLightSet]
allowed_params = {brightness = {minimum = 0, maximum = 50}}
rate_limit = {per_minute = 2}
```

#### Parameter constraints

All constraints are optional and combinable:

| Constraint | Type | Description |
|---|---|---|
| `allowlist` | list of strings | Value must be one of these |
| `pattern` | string (regex) | Value must match — applied to `str(value)` |
| `minimum` | number | Numeric lower bound (inclusive) |
| `maximum` | number | Numeric upper bound (inclusive) |

```toml
[gmail.constrain.send_message]
allowed_params = {to = {allowlist = ["known@example.com", "team@example.com"]}}
rate_limit = {per_minute = 2, per_hour = 10}
```

#### Rate limits

Rate limits are per-agent and per-tool, tracked in-memory with a moving window. Limits reset on wrapper restart.

```toml
[github.constrain.create_pull_request]
rate_limit = {per_minute = 2, per_hour = 10}
```

See `config/rules-defaults.toml.extended.example` for ready-to-use defaults covering GitHub, GitLab, Jira, Confluence, Google Drive, Gmail, Google Calendar, Slack, Linear, Notion, PostgreSQL, Filesystem, Brave Search, and Puppeteer.

#### Agent-provided call reason

The wrapper recognises an optional `_reason` parameter in any tool call. The wrapper strips it before forwarding to the downstream MCP server and records it in the audit log as the `reason` column. This lets you see *why* the agent chose to call a tool, not just *that* it did.

To enable this, add an instruction to the agent's system prompt:

```
When calling MCP tools, always include a "_reason" field explaining why you are calling the tool.
```

The audit log will then show entries like:

```
tool: HassLightSet | reason: "user asked to dim lights for movie night" | decision: allowed
```

#### `log_only` mode

Set `log_only = true` on an agent in `mcp-servers.toml` to bypass all enforcement and observe traffic before writing rules. Useful when onboarding a new agent or MCP server.

---

### Human approval gate

Any tool can be configured to pause and require explicit human sign-off before execution. The wrapper blocks the agent until a human approves or denies via HTTP, or the request times out.

#### Configuring a rule to require approval

In `rules-defaults.toml` or `rules-agents.toml`:

```toml
[homeassistant.constrain.HassTurnOff]
require_approval = true
```

#### Approval gate settings

In `mcp-servers.toml`:

```toml
[approval]
base_url        = "http://localhost:8080"   # used to build the approve URL in notifications
timeout_seconds = 300                       # auto-deny after this many seconds
# webhook_url   = "env:APPROVAL_WEBHOOK_URL"  # HTTP POST with approval details on each request
```

Without a webhook, approval requests are printed to stderr:

```
APPROVAL REQUIRED
  agent:       default
  tool:        HassTurnOff
  approval_id: abc123
  approve:     POST http://localhost:8080/approval/abc123 {"approved": true, "note": "ok"}
  deny:        POST http://localhost:8080/approval/abc123 {"approved": false}
```

#### Mobile approvals via Slack or Telegram

For approvals from your phone, configure one or both notification providers. The wrapper sends an interactive message with **Approve** / **Deny** buttons and updates the message once a decision is made. Sensitive values (SSNs, card numbers, API keys, …) are always redacted from notification payloads — the raw parameters are never sent to Slack or Telegram.

**Slack setup**

1. Create a Slack app with `chat:write` OAuth scope and install it to your workspace.
2. Invite the bot to the channel: `/invite @your-bot-name`.
3. Enable **Interactivity** and set the Request URL to `https://<your-host>/slack/interact`.
4. Add the credentials to `mcp-servers.toml`:

```toml
[notifications.slack]
bot_token      = "env:SLACK_BOT_TOKEN"      # xoxb-… from OAuth & Permissions
channel        = "C0XXXXXXXXX"              # channel ID (not name)
signing_secret = "env:SLACK_SIGNING_SECRET" # from Basic Information
```

**Telegram setup**

1. Chat with `@BotFather`, create a bot, and copy its token.
2. Send any message to your new bot, then fetch your chat ID:
   ```bash
   curl "https://api.telegram.org/bot<TOKEN>/getUpdates" | python3 -m json.tool
   # look for result[].message.chat.id
   ```
3. Add the credentials to `mcp-servers.toml`:

```toml
[notifications.telegram]
bot_token    = "env:TELEGRAM_BOT_TOKEN"
chat_id      = "env:TELEGRAM_CHAT_ID"
secret_token = "env:TELEGRAM_SECRET_TOKEN"  # optional but recommended
```

The wrapper automatically calls `setWebhook` on startup pointing at `<base_url>/telegram/webhook`. Make sure `base_url` under `[approval]` is publicly reachable by Telegram.

Both providers can be active simultaneously — the first button press on either platform resolves the request; the second is safely ignored.

**Network accessibility requirement**

Outbound notifications (sending the message to Slack or Telegram) work from any network. However, button clicks require Slack/Telegram to POST back to the wrapper, so the `/slack/interact` and `/telegram/webhook` endpoints must be reachable from the internet.

If the wrapper runs on a home server or behind NAT, use a tunnel to expose it without opening firewall ports:

| Option | Notes |
|---|---|
| [Tailscale Funnel](https://tailscale.com/kb/1223/funnel) | `tailscale funnel 8080` — stable public URL, recommended if you already use Tailscale |
| [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) | `cloudflared tunnel` — free, permanent, no firewall changes |
| [ngrok](https://ngrok.com/) | `ngrok http 8080` — easy to set up, URL changes on free tier |

Set `base_url` in `[approval]` to the public URL provided by the tunnel.

#### Responding to an approval request (REST fallback)

```bash
# Approve
curl -X POST http://localhost:8080/approval/<id> \
     -H "Content-Type: application/json" \
     -d '{"approved": true, "note": "confirmed by operator"}'

# Deny
curl -X POST http://localhost:8080/approval/<id> \
     -H "Content-Type: application/json" \
     -d '{"approved": false, "note": "not authorised"}'
```

The approval ID is a one-time UUID that acts as the credential — no separate auth header is required on the approval endpoint.

---

### Anomaly detection

The wrapper watches for unusual patterns in tool traffic and logs them as `WARNING`. Detected anomalies are also returned to the agent in a `_anomalies` field on the tool call response.

```toml
[anomaly]
denial_burst_threshold      = 5     # alert after N denials …
denial_burst_window_seconds = 60    # … within this many seconds

# Off-hours alerting (disabled by default)
business_hours_enabled  = false
business_hours_start    = 9                    # 0–23, inclusive
business_hours_end      = 18                   # 0–23, exclusive
business_hours_timezone = "America/Vancouver"
business_days           = [0, 1, 2, 3, 4]     # 0=Monday … 6=Sunday
```

| Signal | Description |
|---|---|
| Denial burst | N or more denied calls within the rolling window for one agent |
| New tool | First time this agent has ever called this tool |
| Off-hours | Tool call outside configured business hours/days |

---

### DLP

The wrapper scans both directions of every tool call:

- **Outbound** — params are scanned before being forwarded to MCP servers
- **Inbound** — responses are scanned before being returned to the agent

#### Actions

| Action | Effect |
|---|---|
| `block` | Deny the call / drop the response immediately |
| `redact` | Replace the match with `[REDACTED:<name>]` and continue |
| `warn` | Allow through; add to `_security_warnings` in the response |
| `approve` | Pause and require human sign-off via the approval gate |

#### Built-in outbound patterns

These are active by default (`use_builtin_outbound = true`):

| Pattern | Matches | Action |
|---|---|---|
| `private_key` | PEM private key blocks | block |
| `aws_access_key` | `AKIA…` AWS access keys | block |
| `github_token` | `ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_` tokens | block |
| `api_key_sk` | `sk-…` API keys (OpenAI, Anthropic) | block |
| `credit_card` | Visa, Mastercard, Amex card numbers | warn |
| `ssn` | US Social Security numbers (`123-45-6789`) | warn |

#### Built-in inbound patterns

These are active by default (`use_builtin_inbound = true`):

| Pattern | Matches | Action |
|---|---|---|
| `ignore_instructions` | "ignore all previous instructions/rules/prompts" | redact |
| `system_tag` | `<system>`, `[SYSTEM]`, `### System` injection markers | redact |
| `jailbreak` | "DAN mode", "do anything now", "jailbreak mode" | redact |
| `prompt_leak` | "reveal/print your system prompt/instructions" | redact |
| `indirect_injection` | "tell the user to…" redirection attempts | warn |

#### Configuration

```toml
[dlp]
enabled              = true
use_builtin_outbound = true   # false to disable all built-in outbound patterns
use_builtin_inbound  = true   # false to disable all built-in inbound patterns
```

Override a built-in by re-declaring it with the same `name`. The user entry wins.

```toml
# Escalate SSN and credit card from warn → approve
[[dlp.outbound]]
name    = "ssn"
pattern = "\\b\\d{3}-\\d{2}-\\d{4}\\b"
action  = "approve"

[[dlp.outbound]]
name    = "credit_card"
pattern = "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b"
action  = "approve"

# Add a custom outbound pattern
[[dlp.outbound]]
name    = "internal_ref"
pattern = "\\bINT-\\d{6}\\b"
action  = "block"

# Disable a single built-in without turning off the whole list
[[dlp.outbound]]
name    = "credit_card"
pattern = "."
enabled = false
```

Custom inbound patterns work the same way under `[[dlp.inbound]]`.

#### Response fields

Successful tool call responses may include these wrapper-added fields:

| Field | When present |
|---|---|
| `_warning` | Agent omitted the `_reason` parameter |
| `_anomalies` | One or more anomaly signals fired |
| `_security_warnings` | DLP `warn` or `redact` violations found in the response |

---

## Running

```bash
# Set required environment variables
export DEFAULT_AGENT_TOKEN="your-agent-token"
export HA_TOKEN="your-ha-token"

# Start the wrapper
source .venv/bin/activate
mcp-wrapper --config config/mcp-servers.toml

# Override log level
mcp-wrapper --config config/mcp-servers.toml --log-level DEBUG
```

`rules-defaults.toml / rules-agents.toml` is loaded automatically from the same directory as `mcp-servers.toml`.

---

## Verifying the setup

A `test.sh` helper is included for manual testing. Source it to load helper functions into your shell:

```bash
source test.sh

health                              # GET /health — no auth required
tools_list                          # list tools visible to your agent (filtered by rules)
audit [limit]                       # view recent audit log entries
audit_filter [key=value ...]        # filtered audit log (e.g. decision=denied tool=Hass*)
stats [since=ISO] [until=ISO]       # summary statistics
call_tool <name> [json_params]      # call a tool through the wrapper
approve <approval_id> [note]        # approve a pending human-gate request
deny_approval <approval_id> [note]  # deny a pending human-gate request
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

# View audit log (most recent 20 entries)
curl -H "Authorization: Bearer $DEFAULT_AGENT_TOKEN" "http://localhost:8080/audit/recent?limit=20"

# Filter audit log
curl -H "Authorization: Bearer $DEFAULT_AGENT_TOKEN" \
  "http://localhost:8080/audit/recent?decision=denied&tool=Hass*&since=2025-01-01T00:00:00"

# Summary statistics
curl -H "Authorization: Bearer $DEFAULT_AGENT_TOKEN" "http://localhost:8080/audit/stats"

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
