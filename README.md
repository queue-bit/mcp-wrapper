# MCP Security Wrapper

A security and monitoring proxy that sits between LLM agents and MCP servers. Enforces credential isolation, action whitelisting, parameter validation, rate limiting, DLP scanning, and structured audit logging without modifying upstream MCP servers or downstream clients.

**Core principle:** The LLM agent never holds credentials directly. It expresses intent; the wrapper validates, executes, and records.

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Connecting agents](#connecting-agents)
  - [REST API (default)](#rest-api-default)
  - [MCP protocol — SSE](#mcp-protocol--sse)
  - [MCP protocol — Streamable HTTP](#mcp-protocol--streamable-http)
  - [Claude API tool_use format](#claude-api-tool_use-format)
- [Configuration](#configuration)
  - [Config files](#config-files)
  - [Secret reference format](#secret-reference-format)
  - [Server](#server)
  - [Logging](#logging)
  - [Secret backends](#secret-backends)
  - [HashiCorp Vault](#hashicorp-vault)
  - [MCP servers](#mcp-servers)
  - [Native tools](#native-tools)
  - [Plugin tools](#plugin-tools)
  - [Gateway API](#gateway-api)
  - [Agents](#agents)
  - [Rules](#rules)
  - [Human approval gate](#human-approval-gate)
    - [Mobile approvals via Slack or Telegram](#mobile-approvals-via-slack-or-telegram)
  - [Anomaly detection](#anomaly-detection)
  - [DLP](#dlp)
- [Running](#running)
- [Admin UI](#admin-ui)
- [Verifying the setup](#verifying-the-setup)
- [Network security](#network-security)
- [Development](#development)

---

## Overview

```
                          ┌─────────────────────────────────────┐
  MCP SSE/HTTP  ──────────►                                     ├──► MCP Server (injected cred)
  Claude API    ──────────►   MCP Security Wrapper              ├──► Native HTTP API (injected cred)
  REST API      ──────────►                                     ├──► Gateway Tools (Python/Shell/HTTP)
  Gateway API   ──────────►         Audit log (SQLite)          │
                          └─────────────────────────────────────┘
```

The wrapper accepts connections from agents over three protocols and can route tool calls to downstream MCP servers, execute HTTP API calls directly from config, or run operator-defined scripts and commands — no downstream MCP server required for any of these.

Every tool call — regardless of how it arrives or where it goes — passes through the same enforcement pipeline:

1. Authenticates the agent via `Authorization: Bearer <token>`
2. Looks up the agent's permission profile
3. Checks the requested tool against the agent's allowlist (default-deny)
4. Validates tool parameters against per-rule constraints
5. Enforces per-agent, per-tool rate limits
6. Runs outbound DLP — scans params for secrets, PII, and sensitive data before forwarding
7. Optionally pauses for human approval (`require_approval` on a rule, or a DLP `approve` pattern)
8. Retrieves the downstream credential from a secret store at call time
9. Forwards the call (JSON-RPC to an MCP server, or HTTP to a native API)
10. Runs inbound DLP — scans the response for prompt-injection attempts before returning it to the agent
11. Logs every request, decision, and response — tagged with agent and server
12. Flags anomalies: denial bursts, first-time tool use, and off-hours calls

Tool listings are filtered to only the tools an agent is permitted to call, and parameter schemas are narrowed to reflect the agent's actual constraints — so the LLM never sees tools it can't use or parameter values it can't supply.

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

## Connecting agents

The wrapper supports four connection modes. All require `Authorization: Bearer <token>`.

### REST API (default)

The original interface. Useful for custom clients or scripts.

| Endpoint | Method | Purpose |
|---|---|---|
| `/mcp/tools/list` | GET | List permitted tools |
| `/mcp/tools/call` | POST | Call a tool |
| `/audit/recent` | GET | Recent audit log entries |
| `/audit/stats` | GET | Summary statistics |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/mcp/tools/list
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"tool": "GetDateTime", "params": {"_reason": "user asked for time"}}' \
     http://localhost:8080/mcp/tools/call
```

### MCP protocol — SSE

Standard MCP over Server-Sent Events. Compatible with Claude Code CLI and any MCP-compliant client.

- **SSE endpoint:** `GET /mcp-sse/sse`
- **Message endpoint:** `POST /mcp-sse/messages/`

**Claude Code** (`~/.claude/settings.json` or project `.claude/settings.json`):

```json
{
  "mcpServers": {
    "my-wrapper": {
      "type": "sse",
      "url": "http://localhost:8080/mcp-sse/sse",
      "headers": {
        "Authorization": "Bearer YOUR_AGENT_TOKEN"
      }
    }
  }
}
```

### MCP protocol — Streamable HTTP

The newer MCP 2025-03 transport. Supported by recent Claude Code builds and other modern MCP clients.

- **Endpoint:** `GET / POST / DELETE /mcp`

```json
{
  "mcpServers": {
    "my-wrapper": {
      "type": "http",
      "url": "http://localhost:8080/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_AGENT_TOKEN"
      }
    }
  }
}
```

You can also verify the MCP connection interactively with the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector http://localhost:8080/mcp-sse/sse
```

### Claude API tool_use format

For agents built directly on the Anthropic SDK. Returns tools in the SDK's native `input_schema` format and accepts `tool_use` content blocks.

```
GET  /claude/tools       — returns {"tools": [...]} in Anthropic format
POST /claude/tools/call  — accepts tool_use blocks, returns tool_result blocks
```

```python
import anthropic, httpx

client = anthropic.Anthropic()
headers = {"Authorization": f"Bearer {TOKEN}"}

# Fetch tools in Anthropic format
tools = httpx.get("http://localhost:8080/claude/tools", headers=headers).json()["tools"]

# Run a conversation turn
response = client.messages.create(model="claude-opus-4-7", max_tokens=1024, tools=tools, messages=[...])

# Execute tool calls through the wrapper
if response.stop_reason == "tool_use":
    tool_uses = [b for b in response.content if b.type == "tool_use"]
    results = httpx.post(
        "http://localhost:8080/claude/tools/call",
        headers={**headers, "Content-Type": "application/json"},
        json={"tool_uses": [{"type": b.type, "id": b.id, "name": b.name, "input": b.input}
                            for b in tool_uses]},
    ).json()["tool_results"]
```

Tool calls in a single request are executed **sequentially** — approval gates on earlier calls complete before later calls are evaluated.

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
| `config/wrapper.toml` | Server, logging, secret backends, DLP, anomaly detection, approval, notifications |
| `config/mcp-servers.toml` | Downstream MCP server proxy definitions |
| `config/native-tools.toml` | Native HTTP tool definitions (no downstream MCP server required) |
| `config/plugins.toml` | Local Python plugin tool definitions (exposed via MCP protocol) |
| `config/gateway.toml` | Gateway tool definitions — Python scripts, shell commands, HTTP endpoints (exposed via REST) |
| `config/agents.toml` | Agent token and access definitions |
| `config/rules-defaults.toml` | Default per-server tool allow/constrain rules (all agents) |
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
db_path   = "data/audit.db"  # SQLite audit log; use "data/audit.db" in Docker (persists in the named volume)
# jsonl_path = "audit.jsonl" # optional append-only JSONL alongside SQLite
level     = "INFO"
```

Every audit log entry includes the agent ID, session ID, MCP server name, tool, parameters, decision, and latency. Denied calls include a `denial_reason`.

> **Docker persistence:** `db_path` must be set to `"data/audit.db"` (resolving to `/app/data/audit.db` inside the container) so the database lands in the `mcp_data` named volume. The default `"audit.db"` path writes to the container layer and is lost on every rebuild.

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

### Native tools

Native tools let you define HTTP-callable tools directly in config — no downstream MCP server required. The wrapper makes the HTTP call itself, injecting stored credentials, and applies the same enforcement pipeline (rules, DLP, rate limits, approvals) as any other tool call.

```toml
# mcp-servers.toml

[native_tools.ha_light_toggle]
description  = "Toggle a Home Assistant light entity"
url          = "http://homeassistant:8123/api/services/light/toggle"
method       = "POST"
credential   = "env:HA_TOKEN"
credential_injection = "bearer"   # inject as: Authorization: Bearer <token>
param_placement      = "json"     # send arguments as JSON request body

[native_tools.ha_light_toggle.input_schema]
type     = "object"
required = ["entity_id"]

[native_tools.ha_light_toggle.input_schema.properties.entity_id]
type        = "string"
description = "Home Assistant entity ID (e.g. light.living_room)"
```

#### Credential injection modes

| Mode | Effect |
|---|---|
| `bearer` (default) | `Authorization: Bearer <token>` header |
| `header` | Custom header — also set `credential_header = "X-Api-Key"` |
| `query` | Query parameter — also set `credential_param = "api_key"` |

#### Parameter placement modes

| Mode | Effect |
|---|---|
| `query` (default) | Arguments appended as URL query params |
| `json` | Arguments sent as JSON request body |
| `path` | Arguments interpolated into the URL via `str.format(**arguments)` |

#### Static params

Use `static_params` to pin values that agents must not override:

```toml
[native_tools.weather_current]
description  = "Get current weather"
url          = "https://api.openweathermap.org/data/2.5/weather"
method       = "GET"
credential   = "env:OPENWEATHER_API_KEY"
credential_injection = "query"
credential_param     = "appid"
param_placement      = "query"

[native_tools.weather_current.static_params]
units = "metric"    # always metric; agents cannot override this

[native_tools.weather_current.input_schema]
type     = "object"
required = ["q"]

[native_tools.weather_current.input_schema.properties.q]
type        = "string"
description = "City name"
```

#### Rules for native tools

Native tools use the reserved server name `__native__` in rules files:

```toml
# rules-defaults.toml

[__native__]
allow = ["weather_current", "ha_light_toggle"]

[__native__.constrain.ha_light_toggle]
allowed_params = {entity_id = {pattern = "^light\\..*"}}
require_approval = true
```

---

### Plugin tools

Plugin tools are local Python files that execute inside the wrapper process. They follow the same enforcement pipeline as any other tool (rules, DLP, rate limits, approvals) and appear in `tools/list` alongside MCP server tools.

#### Writing a plugin

Every plugin file must define three things:

```python
DESCRIPTION = "One sentence shown to the agent."

INPUT_SCHEMA = {
    "type": "object",
    "required": ["param1"],
    "properties": {
        "param1": {"type": "string", "description": "..."},
    },
}

async def execute(arguments: dict) -> str:
    # Use asyncio.to_thread for any blocking I/O
    ...
```

#### Registering a plugin

```toml
# config/plugins.toml
[plugin_tools.my_tool]
path = "plugins/my_tool.py"
max_response_chars = 50000   # optional
```

#### Adding rules

Plugin tools use the reserved server name `__plugins__` in rules files:

```toml
# rules-defaults.toml
[__plugins__]
allow = ["my_tool", "fetch_body"]

[__plugins__.constrain.shell]
require_approval = true
```

#### Ready-to-use plugins

The `plugins/` directory contains drop-in tools. Install any extra deps noted in the file header, register in `plugins.toml`, and add to `[__plugins__]` in your rules.

| File | Tool name | What it does | Extra dep |
|---|---|---|---|
| `fetch_body.py` | `fetch_body` | Fetch a URL; strip scripts/styles; return body text | — |
| `html_to_markdown.py` | `html_to_markdown` | Fetch a URL or convert raw HTML to Markdown; strips navigation chrome | — |
| `upload_file.py` | `upload_file` | Save a base64-encoded file to the upload directory; return its path | — |
| `list_files.py` | `list_files` | List files in the upload directory with size and modified time | — |
| `read_file.py` | `read_file` | Read a text file from the upload directory with optional pagination | — |
| `write_file.py` | `write_file` | Write text to a file in the upload directory | — |
| `xlsx_to_csv.py` | `xlsx_to_csv` | Read an `.xlsx` file by path and return its contents as CSV | `openpyxl` |
| `pdf_to_text.py` | `pdf_to_text` | Extract text from a PDF by path; optional page range | `pypdf` |
| `math_eval.py` | `math_eval` | Evaluate a mathematical expression safely (no `eval()`) | — |
| `jq_query.py` | `jq_query` | Fetch JSON from a URL or file and apply a jq filter | `jq` |
| `csv_query.py` | `csv_query` | Run SQL against a CSV file in the upload directory using DuckDB | `duckdb` |
| `shell.py` | `shell` | Run a shell command in the upload directory; logged, allowlisted, timeout-bounded | — |

**Shell plugin configuration** — the `shell` plugin behaviour is tuned via environment variables:

| Variable | Default | Description |
|---|---|---|
| `MCP_SHELL_ALLOWLIST` | built-in set | Comma-separated permitted command names, or `*` for unrestricted |
| `MCP_SHELL_TIMEOUT` | `30` | Default max seconds per command |
| `MCP_SHELL_MAX_OUTPUT` | `50000` | Characters before stdout is truncated |
| `MCP_UPLOAD_DIR` | `/tmp/mcp-uploads` | Upload directory shared across all file plugins |

The built-in allowlist includes: `jq`, `duckdb`, `python3`, `grep`, `awk`, `sed`, `sort`, `uniq`, `cut`, `tr`, `head`, `tail`, `cat`, `curl`, `wget`, `find`, `gzip`, `zip`, `tar`, `pdftotext`, `pandoc`, `bc`, and others. Set `MCP_SHELL_ALLOWLIST=*` to allow any command (the Docker container's non-root user and filesystem permissions remain the real security boundary).

---

### Gateway API

The Gateway API lets you expose **operator-defined tools** — Python scripts, shell commands, or HTTP endpoints — through a governed REST API, without an MCP server. Agents call these tools directly over HTTP, and every call passes through the same enforcement pipeline (rules, DLP, rate limits, human approval gates, audit log).

This is useful for teams with existing automation scripts, internal APIs, or batch jobs that they want AI agents to use safely.

#### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/gateway/tools` | List permitted gateway tools in OpenAI function-calling format |
| `POST` | `/gateway/call` | Execute a single tool `{"name": "...", "arguments": {...}}` |
| `POST` | `/gateway/calls` | Batch execute `{"calls": [{"name": "...", "arguments": {...}}]}` |

#### Adding a gateway tool

1. **Write a Python script** and drop it in `./plugins/`:

   ```python
   # plugins/run_report.py
   def execute(params: dict) -> str | dict:
       report_name = params["report_name"]
       # ... generate report ...
       return {"result": "..."}
   ```

   The function may be `async`. The calling agent's ID is always injected as `params["_agent_id"]`.

2. **Register it in `config/gateway.toml`:**

   ```toml
   [gateway_tools.run_report]
   type        = "python"
   path        = "plugins/run_report.py"
   description = "Generate a named report"
   required    = ["report_name"]

   [gateway_tools.run_report.schema]
   report_name = {type = "string", description = "Name of the report to generate"}
   format      = {type = "string", description = "Output format", enum = ["csv", "json"]}
   ```

3. **Allow it in `config/rules-defaults.toml`:**

   ```toml
   [__gateway__]
   allow = ["run_report"]
   ```

4. **Hot-reload** — `POST /reload` picks up the new tool without restarting the container.

#### Tool types

| Type | Required config | Description |
|---|---|---|
| `python` | `path = "plugins/my_script.py"` | Imports the file and calls `execute(params)`. Supports `async`. |
| `shell` | `command = "scripts/deploy.sh"` | Runs a shell command; params sent as JSON on stdin, result read from stdout. |
| `http` | `url = "http://internal-api/action"` | POSTs params as JSON body; returns the response. |

#### Rules for gateway tools

Gateway tools use the reserved server name `__gateway__` in rules files — identical to how `__native__` works for native tools:

```toml
# rules-defaults.toml
[__gateway__]
allow = ["run_report"]

[__gateway__.constrain.deploy_service]
allowed_params = {environment = {allowlist = ["staging"]}}
require_approval = true
rate_limit = {per_minute = 2}
```

Per-agent overrides work the same way in `rules-agents.toml`:

```toml
[restricted-bot.__gateway__]
allow = ["run_report"]   # this agent can only run reports, not deploy
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

> **Note:** `log_only` bypasses rule checks, param validation, and approval gates for all tool calls — including native tools that execute real HTTP calls with stored credentials. Do not grant `log_only` agents access to native tools that perform sensitive or irreversible actions.

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

Anomaly-flagged calls are tagged in the admin UI with a `⚠ anomaly` badge. Click any audit log row to open the detail side pane, which lists the specific anomaly reasons (e.g. "first time tool X has been called by this agent").

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

## Admin UI

A browser-based admin interface is available at `http://localhost:8080/admin/`. On first visit it prompts you to create an admin account; credentials are stored in `wrapper.toml` and are completely separate from agent bearer tokens.

| Page | What it shows |
|---|---|
| `/admin/dashboard` | Global stats (total/allowed/denied calls, estimated token usage), by-agent breakdown, recent events |
| `/admin/audit` | Filterable audit log — filter by agent, tool, decision, and date range; click any row to open a detail side pane |
| `/admin/agents` | Create, edit, and delete agents |
| `/admin/servers` | Create, edit, and delete MCP server proxies |
| `/admin/rules` | In-browser TOML editors for `rules-defaults.toml` and `rules-agents.toml` |
| `/admin/settings` | Server, logging, Vault, Slack/Telegram notifications, and approval settings |

**Audit log detail pane** — clicking any audit row slides in a panel showing the full params JSON, response content (stored only for errors and anomaly-flagged calls to avoid DB bloat), and anomaly reasons when present. Anomaly-flagged rows are tagged with a `⚠ anomaly` badge.

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

# List tools (REST)
curl -H "Authorization: Bearer $DEFAULT_AGENT_TOKEN" http://localhost:8080/mcp/tools/list

# List tools (Claude API format)
curl -H "Authorization: Bearer $DEFAULT_AGENT_TOKEN" http://localhost:8080/claude/tools

# Call a tool (REST)
curl -H "Authorization: Bearer $DEFAULT_AGENT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"tool": "GetDateTime", "params": {"_reason": "user asked for time"}}' \
     http://localhost:8080/mcp/tools/call

# Call a tool (Claude API tool_use format)
curl -H "Authorization: Bearer $DEFAULT_AGENT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"tool_uses": [{"type": "tool_use", "id": "toolu_01", "name": "GetDateTime", "input": {}}]}' \
     http://localhost:8080/claude/tools/call

# Verify MCP protocol connection (requires npx)
npx @modelcontextprotocol/inspector http://localhost:8080/mcp-sse/sse

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

---

Copyright (C) 2026 Andreas Wiebe. Licensed under the [GNU Affero General Public License v3.0](LICENSE).
