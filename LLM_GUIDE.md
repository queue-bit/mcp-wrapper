# MCP Wrapper — LLM Setup and Configuration Guide

This document is written for LLMs assisting operators in deploying and configuring mcp-wrapper.
It is a complete technical reference. Human readability is not a goal.

---

## What this system does

mcp-wrapper is a security proxy that sits between AI agents and MCP servers (or direct HTTP APIs).
Every tool call an agent makes passes through the wrapper before reaching the downstream service.
The wrapper enforces access control, rate limits, DLP scanning, and human approval gates,
then logs every event to a SQLite audit database.

Agents connect to the wrapper using standard MCP protocol or via a Claude-native HTTP API.
The wrapper resolves the agent's identity from their bearer token, checks rules, and either
forwards the call or denies it.

---

## Deployment

### Requirements

- Python 3.11+
- Install: `pip install -e .` (from repo root) or `pip install mcp-wrapper`
- Optional extras: `pip install -e ".[vault-aws]"` for AWS IAM Vault auth,
  `pip install -e ".[vault-gcp]"` for GCP Vault auth

### Running

```
mcp-wrapper --config config
```

`--config` is a path to a directory containing the config files (default: `config`).
All config files in the directory are optional; missing files produce empty defaults.

### Config directory structure

```
config/
  wrapper.toml           # infrastructure: server, logging, secrets, anomaly, DLP, notifications, approval
  mcp-servers.toml       # downstream MCP server proxy definitions
  native-tools.toml      # native HTTP tool definitions
  plugins.toml           # local Python plugin tool definitions
  agents.toml            # agent token and access definitions
  rules-defaults.toml    # per-server tool allow/constrain rules (applied to all agents)
  rules-agents.toml      # per-agent rule overrides (fully replaces server default for that agent+server)
```

Load order: wrapper.toml → mcp-servers.toml → native-tools.toml → plugins.toml → agents.toml
(merged as flat TOML dicts, no key collisions possible). Rules files are loaded separately.

Plugin Python files live anywhere on the filesystem; `path` in `plugins.toml` points to them.
The `plugins/` directory at the repo root contains ready-to-use examples.

---

## Docker deployment

### Prerequisites

- Docker 24+ and Docker Compose v2 (`docker compose` not `docker-compose`)
- Config files prepared in `config/` (copy `.toml.example` → `.toml` and edit)
- `.env` file with all secrets (copy `.env.example` → `.env` and fill in)

### Required config changes for Docker

Two settings in `config/wrapper.toml` MUST differ from the bare-metal defaults when running inside Docker:

```toml
[server]
host = "0.0.0.0"        # REQUIRED: "127.0.0.1" makes the port unreachable from outside the container

[logging]
db_path = "data/audit.db"   # REQUIRED: resolves to /app/data/audit.db inside the named volume
```

All other config is identical to bare-metal operation.

### Volume mount layout

| Host path | Container path | Type | Purpose |
|-----------|---------------|------|---------|
| `./config/` | `/config` | bind (read-only) | All TOML config files |
| `./plugins/` | `/app/plugins` | bind (read-only) | Python plugin files |
| `mcp_data` (named) | `/app/data` | named volume | `audit.db` and optional `audit.jsonl` |

Plugin paths in `plugins.toml` must be relative to WORKDIR (`/app`):
```toml
[plugin_tools.fetch_body]
path = "plugins/fetch_body.py"   # resolves to /app/plugins/fetch_body.py
```
Absolute paths (`/app/plugins/fetch_body.py`) also work.

### Quick start

```bash
# 1. Prepare config
cp config/wrapper.toml.example config/wrapper.toml
# Edit config/wrapper.toml: set host = "0.0.0.0" and db_path = "data/audit.db"
cp config/agents.toml.example config/agents.toml
# Edit agents.toml: set token = "env:DEFAULT_AGENT_TOKEN" (or generate your own)

# 2. Export secrets in your shell — no file on disk
export DEFAULT_AGENT_TOKEN=$(openssl rand -hex 32)
export HA_TOKEN=your-token   # add any other env:VAR_NAME references from your config

# 3. Build and start
docker compose up -d

# 4. Verify
curl http://localhost:8080/health
# → {"status":"ok"}

# 5. Tail logs
docker compose logs -f mcp-wrapper
```

### Environment variable passing

Secrets are passed via shell environment inheritance — no secrets file on disk. `docker-compose.yml` lists bare variable names (no `=`) under `environment:`, which Docker Compose resolves from the shell that runs `docker compose up`. Add a line for every `env:VAR_NAME` reference used in your TOML config.

Variables not set in the shell produce a WARNING at startup; credential resolution fails at call time when an agent actually uses that tool. `.env.example` documents the full list of available variable names.

### base_url for approval webhooks and Slack/Telegram

`[approval] base_url` must be the externally reachable URL of the host or reverse proxy.
`http://localhost:8080` inside Docker refers to the container itself — Slack and Telegram cannot reach it.

```toml
[approval]
base_url = "https://mcp.example.com"   # or http://your-server-ip:8080
```

For Slack: the Interactivity URL in your Slack app settings must be `<base_url>/slack/interact`.
For Telegram: the wrapper calls `setWebhook` automatically on startup using `<base_url>/telegram/webhook`.
If `base_url` is not externally reachable, approval callbacks fail silently and requests auto-deny after `timeout_seconds`.

### Optional extras: vault-aws and vault-gcp

`vault-aws` (adds `boto3`) and `vault-gcp` (adds `google-auth`) are not installed by default:

```bash
docker build --build-arg EXTRAS="vault-aws" -t mcp-wrapper .
docker build --build-arg EXTRAS="vault-aws,vault-gcp" -t mcp-wrapper .
```

Or in `docker-compose.yml`:
```yaml
build:
  context: .
  args:
    EXTRAS: "vault-aws"
```

AWS auth (`method = "aws"`) uses the boto3 default credential chain. On ECS/EC2 the instance role is picked up automatically. For IRSA on Kubernetes, mount the service account token as usual.

### Health check

`GET /health` requires no authentication and returns `{"status":"ok"}` with HTTP 200. Both `Dockerfile` and `docker-compose.yml` configure Docker's built-in health check against this endpoint.

### Backing up audit.db

```bash
# Copy audit.db from the named volume while the container is running
docker run --rm \
  -v mcp_data:/data \
  -v $(pwd):/out \
  busybox \
  cp /data/audit.db /out/audit-$(date +%Y%m%d).db
```

### Restart after config changes

Config and plugin files are loaded once at startup. After editing any TOML file or plugin:
```bash
docker compose restart mcp-wrapper
```

The audit volume and any open approval requests are preserved across restarts.

### TLS / reverse proxy

The wrapper does not terminate TLS. Place a reverse proxy in front:
- **nginx**: `proxy_pass http://mcp-wrapper:8080;` with TLS on the nginx side
- **Traefik**: standard Traefik labels on the compose service
- **Caddy**: `reverse_proxy mcp-wrapper:8080` (automatic HTTPS)

`tls_cert`/`tls_key` fields exist in `ServerConfig` but are not currently wired to uvicorn. Do not set them expecting TLS to activate — terminate TLS at the reverse proxy instead.

---

## Config reference

All files use TOML format. Secret values anywhere in config accept these reference prefixes:
- `env:VARNAME` — resolved from environment variable at startup
- `keyring:service:username` — resolved from OS keyring (macOS Keychain, libsecret, DBUS)
- `vault:path/to/secret#fieldname` — resolved from HashiCorp Vault KV
- `literal-value` — used as-is (logs a warning; acceptable for dev/testing only)

---

### wrapper.toml

#### [server]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| host | string | `"127.0.0.1"` | Bind address. Use `"0.0.0.0"` or a Tailscale IP for LAN access |
| port | int | `8080` | Listen port |
| tls_cert | string\|null | null | Path to TLS certificate PEM file |
| tls_key | string\|null | null | Path to TLS private key PEM file |

#### [logging]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| db_path | string | `"audit.db"` | SQLite audit database path |
| jsonl_path | string\|null | null | Optional append-only JSONL flat file alongside SQLite |
| level | string | `"INFO"` | Log level: DEBUG, INFO, WARNING, ERROR |

#### [secrets.vault]
Only required when any credential uses the `vault:` prefix.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| addr | string | `"https://127.0.0.1:8200"` | Vault server address |
| kv_mount | string | `"secret"` | KV secrets engine mount path |
| kv_version | int | `2` | KV version: 1 or 2 |
| path_field_separator | string | `"#"` | Separator between path and field in vault: references |
| namespace | string\|null | null | Vault Enterprise namespace |
| tls_verify | bool | `true` | Verify Vault TLS certificate |

#### [secrets.vault.auth]
| Field | Type | Required for | Description |
|-------|------|-------------|-------------|
| method | string | all | `"token"`, `"approle"`, `"aws"`, `"kubernetes"`, `"gcp"` |
| token | string\|null | token | Vault token (use `env:VAULT_TOKEN`) |
| role_id | string\|null | approle | AppRole role ID |
| secret_id | string\|null | approle | AppRole secret ID |
| role | string\|null | aws/kubernetes/gcp | Vault role name mapping to IAM/k8s/GCP identity |
| jwt_path | string | kubernetes | Service account JWT path; default `/var/run/secrets/kubernetes.io/serviceaccount/token` |
| gcp_auth_type | string | gcp | `"iam"` (ADC service account) or `"gce"` (metadata server) |
| mount | string\|null | all | Auth backend mount; defaults: approle→`approle`, aws→`aws`, kubernetes→`kubernetes`, gcp→`gcp` |

AWS auth uses the boto3 default credential chain (instance profile, IRSA, env vars). No keys in config.

#### [anomaly]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| denial_burst_threshold | int | `5` | Number of denials that triggers a WARNING log |
| denial_burst_window_seconds | int | `60` | Time window for counting denials |
| business_hours_enabled | bool | `false` | Enable off-hours alerting |
| business_hours_start | int | `9` | Start hour (0-23, inclusive) |
| business_hours_end | int | `18` | End hour (0-23, exclusive) |
| business_hours_timezone | string | `"UTC"` | IANA timezone string |
| business_days | list[int] | `[0,1,2,3,4]` | Days of week; 0=Monday, 6=Sunday |

#### [dlp]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| enabled | bool | `true` | Master DLP on/off switch |
| use_builtin_outbound | bool | `true` | Include built-in outbound patterns |
| use_builtin_inbound | bool | `true` | Include built-in inbound patterns |

Built-in outbound patterns (action: block unless noted):
- `private_key` — PEM private key headers
- `aws_access_key` — AKIA… tokens
- `github_token` — ghp_/gho_/ghu_/ghs_/ghr_ tokens
- `api_key_sk` — sk-… keys (OpenAI, Anthropic)
- `credit_card` — Visa/MC/Amex numbers (action: warn)
- `ssn` — US SSN format (action: warn)

Built-in inbound patterns (action: redact unless noted):
- `ignore_instructions` — "ignore all previous instructions" variants
- `system_tag` — `<system>`, `[SYSTEM]`, `### System` injection
- `jailbreak` — DAN mode, jailbreak mode phrases
- `prompt_leak` — attempts to extract system prompt
- `indirect_injection` — "tell the user to visit…" (action: warn)

##### [[dlp.outbound]] and [[dlp.inbound]] — custom / override patterns
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| name | string | required | Pattern name; matches built-in name to override it |
| pattern | string | required | Python regex (re module) |
| action | string | `"warn"` | `"block"`, `"redact"`, `"warn"`, or `"approve"` |
| enabled | bool | `true` | Set false to disable a built-in by name without replacing it |

Actions:
- `block` — deny the tool call entirely; the call is logged as denied
- `redact` — replace match with `[REDACTED:name]`; call proceeds with sanitized params
- `warn` — allow through; adds pattern name to `_security_warnings` in response
- `approve` — pause the call, send notification, wait for human resolution

The `_reason` field in tool call params is also DLP-scanned before being written to the audit log.

#### [approval]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| base_url | string | `"http://localhost:8080"` | Used to construct the approval URL sent in notifications |
| timeout_seconds | int | `300` | Seconds to wait before auto-denying a pending approval |
| webhook_url | string\|null | null | HTTP POST target for each approval request (use `env:` reference) |

Approval webhook POST body:
```json
{"approval_id": "...", "agent_id": "...", "tool": "...", "params": {...}, "reason": "...", "approve_url": "..."}
```

To resolve manually (without Slack/Telegram):
```
POST /approval/<approval_id>  {"approved": true, "note": "optional reason"}
```

#### [notifications.slack]
| Field | Type | Description |
|-------|------|-------------|
| bot_token | string | Bot User OAuth Token (`xoxb-…`); use `env:` reference |
| channel | string | Channel ID (not name); e.g. `C0XXXXXXXXX` |
| signing_secret | string | From Slack app settings; used to verify interaction payloads |

Slack app setup requirements: `chat:write` and `chat:write.public` scopes.
Interactivity URL must point to `<base_url>/slack/interact`.

#### [notifications.telegram]
| Field | Type | Description |
|-------|------|-------------|
| bot_token | string | Token from @BotFather; use `env:` reference |
| chat_id | string | Personal or group chat ID; use `env:` reference |
| secret_token | string\|null | Set on setWebhook for inbound verification (recommended) |

The wrapper registers the Telegram webhook automatically on startup using `base_url` from `[approval]`.

---

### mcp-servers.toml

#### [mcp_servers.\<name\>]
One block per downstream MCP server. `<name>` is the server identifier used in `agents.toml` and `rules-defaults.toml`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| url | string | required | Full URL to the MCP server's endpoint |
| credential | string\|null | null | Bearer token secret reference; sent as `Authorization: Bearer <value>` |
| response_fields | list[string]\|null | null | Dot-path fields to extract from the response; drops all other keys |
| max_response_chars | int\|null | null | Truncate serialized response to this many characters |

`response_fields` dot-path syntax: `"key"`, `"nested.key"`, `"array.0.field"`.
Applied before DLP inbound scan. Truncation appends ` …[N chars truncated]`.

**LLM prompt for generating response_fields and max_response_chars:**
> Make a sample tool call against this MCP server, capture the raw response, then paste it here with:
> "Given this MCP tool response, suggest response_fields (dot-path strings to the most useful fields)
> and a max_response_chars limit appropriate for a 4k-token context window.
> Format the answer as TOML config lines."

---

### native-tools.toml

#### [native_tools.\<name\>]
One block per native HTTP tool. `<name>` is the tool name agents will call.
Native tools are governed by rules under `[__native__]` in rules-defaults.toml.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| description | string | required | Tool description shown to agents |
| url | string | required | HTTP endpoint URL |
| method | string | `"GET"` | HTTP method |
| credential | string\|null | null | Secret reference for the credential value |
| credential_injection | string | `"bearer"` | How to inject the credential: `"bearer"`, `"header"`, `"query"` |
| credential_header | string\|null | null | Header name when `credential_injection = "header"` |
| credential_param | string\|null | null | Query param name when `credential_injection = "query"` |
| static_params | table | `{}` | Operator-pinned params; agents cannot override these keys |
| input_schema | table | `{"type":"object","properties":{}}` | JSON Schema for agent-supplied arguments |
| param_placement | string | `"query"` | Where to put agent arguments: `"query"`, `"json"`, `"path"` |
| timeout_seconds | float | `30.0` | HTTP request timeout |
| response_fields | list[string]\|null | null | Dot-path fields to extract from JSON response |
| max_response_chars | int\|null | null | Truncate to this many characters before returning to agent |

Security: `static_params` keys and `credential_param`/`credential_header` are stripped from
agent-supplied arguments before merging, preventing agent override of operator-pinned values.

`param_placement` details:
- `query` — arguments merged into URL query string
- `json` — arguments sent as JSON body; adds `Content-Type: application/json`
- `path` — arguments interpolated into URL with `str.format(**arguments)`; use `{param}` in url

**LLM prompt for generating response_fields and max_response_chars:**
> Paste an example API response here with:
> "Given this API response, suggest response_fields (dot-path strings to the 4–6 most useful fields)
> and a max_response_chars limit appropriate for a 4k-token context window.
> Format the answer as TOML config lines."

**Example with all features:**
```toml
[native_tools.weather_current]
description          = "Get current weather for a city"
url                  = "https://api.openweathermap.org/data/2.5/weather"
method               = "GET"
credential           = "env:OPENWEATHER_API_KEY"
credential_injection = "query"
credential_param     = "appid"
param_placement      = "query"
response_fields      = ["name", "main.temp", "main.feels_like", "weather.0.description"]
max_response_chars   = 500

[native_tools.weather_current.static_params]
units = "metric"

[native_tools.weather_current.input_schema]
type     = "object"
required = ["q"]

[native_tools.weather_current.input_schema.properties.q]
type        = "string"
description = "City name (e.g. Vancouver)"
```

---

### plugins.toml

#### [plugin_tools.\<name\>]
One block per plugin tool. `<name>` is the tool name agents will call.
Plugin tools are governed by rules under `[__plugins__]` in rules-defaults.toml.
Plugin Python files are loaded once at startup; restart required after editing.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| path | string | required | Path to the Python plugin file. Relative to cwd or absolute. |
| response_fields | list[string]\|null | null | Dot-path fields to extract from the return value (if dict) |
| max_response_chars | int\|null | null | Truncate response to this many characters |

**Plugin file contract** — every plugin file must define:

```python
DESCRIPTION = "Plain-English description shown to the agent"

INPUT_SCHEMA = {
    "type": "object",
    "required": ["param1"],
    "properties": {
        "param1": {"type": "string", "description": "..."},
    },
}

async def execute(arguments: dict) -> Any:
    # arguments contains the agent-supplied params (already DLP-scanned)
    # Return: a string, any JSON-serializable value, or a pre-formed MCP content block:
    #   {"content": [{"type": "text", "text": "..."}]}
    ...
```

Rules for using blocking I/O inside plugins: wrap with `asyncio.to_thread(blocking_fn, ...)`.
Plugins may import any installed package. Missing packages raise `ImportError` at first call if
the import is deferred (recommended pattern — see `xlsx_to_csv.py`), or at startup if top-level.

**LLM prompt for writing a new plugin:**
> "Write a Python plugin for mcp-wrapper that [describe what it should do].
>  The file must define DESCRIPTION (string), INPUT_SCHEMA (JSON Schema dict),
>  and async def execute(arguments: dict) -> str.
>  Use asyncio.to_thread for any blocking I/O.
>  Defer optional imports inside the function body so missing packages
>  raise a clear error at call time rather than at startup."

**Ready-to-use example plugins** (copy from `plugins/` directory):

| File | Tool name | What it does |
|------|-----------|--------------|
| `plugins/fetch_body.py` | `fetch_body` | Fetches a URL; strips `<script>`, `<style>`, `<head>`; returns body text |
| `plugins/xlsx_to_csv.py` | `xlsx_to_csv` | Reads a local `.xlsx` file and returns its contents as CSV (`pip install openpyxl`) |

---

### agents.toml

#### [agents.\<agent-id\>]
`<agent-id>` is the identifier used in audit logs and rules-agents.toml.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| token | string | required | Bearer token the agent sends; use `env:` reference |
| mcp_servers | list[string] | required | Names matching `[mcp_servers.<name>]` keys this agent can access |
| log_only | bool | `false` | If true, skip enforcement for downstream MCP calls (native tool calls always enforce) |

`log_only = true` is an observation mode for passive agents. It does NOT bypass native tool enforcement —
native tools make real HTTP calls with stored credentials and are always fully enforced.

---

### rules-defaults.toml

One section per MCP server or `__native__` for native tools.
These rules apply to all agents unless overridden in rules-agents.toml.
**Anything not listed is denied by default.**

```toml
[<server-name>]
allow = ["ToolName", "Prefix*"]          # fnmatch globs allowed here; no constraints

[<server-name>.constrain.<ExactToolName>]  # must be exact name; implicitly allowed
allowed_params = {param = {allowlist = ["a", "b"]}}
allowed_params = {param = {pattern = "^prefix\\..*"}}
allowed_params = {param = {minimum = 0, maximum = 100}}
rate_limit = {per_minute = 5, per_hour = 20}
require_approval = true
```

`allow` uses fnmatch (not regex): `*` matches anything, `?` matches one char.
`constrain` keys must be exact tool names; they are implicitly allowed.
`allowed_params` constraints: `allowlist`, `pattern` (regex), `minimum`, `maximum` — all optional, combinable.
`rate_limit`: `per_minute` and/or `per_hour`; both limits enforced independently if both set.
`require_approval`: blocks the call and sends a notification until a human resolves it.

Native tools use the reserved server name `__native__`:
```toml
[__native__]
allow = ["weather_current"]

[__native__.constrain.ha_light_toggle]
allowed_params = {entity_id = {pattern = "^light\\..*"}}
rate_limit = {per_minute = 10}
```

See `config/rules-defaults.toml.extended.example` for pre-built rules for: GitHub, GitLab, Jira,
Confluence, Google Drive, Gmail, Google Calendar, Slack, Linear, Notion, PostgreSQL, Filesystem,
Brave Search, Puppeteer.

---

### rules-agents.toml

Per-agent rule overrides. An entry for `[agent-id.server-name]` **fully replaces** the server
default for that agent+server combination — it does not merge.

```toml
[<agent-id>.<server-name>]
allow = [...]

[<agent-id>.<server-name>.constrain.<ToolName>]
rate_limit = {per_minute = 2}
```

Agents not listed here receive the server defaults from rules-defaults.toml unchanged.

---

## Enforcement pipeline (order of operations per tool call)

1. Authenticate agent from bearer token → resolve agent_id
2. Extract and DLP-scan `_reason` field from params (stored in audit log)
3. Resolve target: native tool registry → MCP server (by agent's mcp_servers list)
4. If `log_only = false` OR target is a native or plugin tool:
   a. Check target exists; deny if not found
   b. Load effective rules (agent override if exists, else server default)
   c. Check tool is in allow list or constrain table; deny if not
   d. Check rate limit if configured; deny if exceeded
   e. Validate params against constraints; deny if violation
   f. If `require_approval`: send notification, block until resolved or timeout
5. DLP outbound scan on params; block/redact/approve/warn per pattern
6. Execute: call native HTTP tool or forward to MCP server
7. Apply response_fields and max_response_chars shaping (native tools before step 6; MCP servers here)
8. DLP inbound scan on response; block/redact/warn per pattern
9. Log AuditEvent; run anomaly detection
10. Return result to agent

---

## Tool routing

When an agent calls a tool, the wrapper resolves it in this order:
1. Check native tool registry first (`[native_tools.*]`)
2. Check plugin registry second (`[plugin_tools.*]`)
3. Check MCP servers in the agent's `mcp_servers` list, matching by:
   a. Tool name prefix matching server name (e.g. `homeassistant.GetDateTime` → `homeassistant`)
   b. Tool name prefix with underscore (e.g. `homeassistant_GetDateTime`)
   c. Falls back to first server in the list if no prefix match
4. If still not found: deny with "no server or native tool found"

Native tools take priority over plugins; both take priority over MCP server tools.
A native or plugin tool name shadows any MCP server tool with the same name.

---

## API endpoints

All endpoints require `Authorization: Bearer <token>` unless noted.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check; no auth required |
| GET | `/mcp/tools/list` | List tools permitted for the authenticated agent |
| POST | `/mcp/tools/call` | Call a tool; body: `{"tool": "name", "params": {...}}` |
| GET | `/claude/tools` | Tools in Anthropic `tool_use` JSON Schema format |
| POST | `/claude/tools/call` | Accept Anthropic `tool_use` blocks; return `tool_result` blocks |
| POST | `/approval/<id>` | Resolve an approval gate; body: `{"approved": true, "note": "..."}` |
| POST | `/slack/interact` | Slack interactivity webhook (no agent auth; verified by signing secret) |
| POST | `/telegram/webhook` | Telegram update webhook (no agent auth; verified by secret token) |
| GET | `/audit/recent` | Query audit log for authenticated agent |
| GET | `/audit/stats` | Aggregated stats for authenticated agent |
| GET/POST/DELETE | `/mcp` | Streamable HTTP MCP transport endpoint |
| GET | `/mcp-sse/sse` | SSE MCP transport endpoint |
| POST | `/mcp-sse/messages/` | SSE message posting endpoint |

### /mcp/tools/call
Request body:
```json
{"tool": "ToolName", "params": {"arg1": "value", "_reason": "why I'm calling this"}}
```
The `_reason` field is strongly encouraged — its absence adds a `_warning` to the response.
`_reason` is stripped from params before forwarding and stored in the audit log (DLP-scanned).

### /claude/tools/call
Request body:
```json
{
  "tool_uses": [
    {"type": "tool_use", "id": "toolu_01...", "name": "ToolName", "input": {"arg": "value"}}
  ]
}
```
Returns:
```json
{
  "tool_results": [
    {"type": "tool_result", "tool_use_id": "toolu_01...", "content": "...", "is_error": false}
  ]
}
```
Tool uses are executed sequentially. `PermissionError` produces `is_error: true` without aborting the batch.

### /audit/recent query parameters
| Param | Type | Description |
|-------|------|-------------|
| limit | int | Max entries returned (default 50) |
| tool | string | Exact name or fnmatch glob |
| mcp_server | string | Filter by server name |
| decision | string | `allowed`, `denied`, or `error` |
| since | string | ISO 8601 timestamp lower bound (inclusive) |
| until | string | ISO 8601 timestamp upper bound (inclusive) |

---

## Common tasks

### Add a new MCP server proxy

1. Add to `config/mcp-servers.toml`:
   ```toml
   [mcp_servers.<name>]
   url        = "<server-url>"
   credential = "env:<TOKEN_VAR>"
   ```

2. Add rules to `config/rules-defaults.toml`. Check `rules-defaults.toml.extended.example`
   for pre-built rules for common services. If the server is not there, call `tools/list`
   on the server directly to enumerate available tools, then use this prompt:
   > "Given this list of MCP tools from [service name], generate a rules-defaults.toml section
   > that allows read operations without constraints, adds rate limits to write operations
   > (5/min, 20/hr is a safe default), and leaves destructive operations (delete, drop, purge,
   > destroy, remove) unlisted (denied by default)."

3. Add the server name to the relevant agent's `mcp_servers` list in `config/agents.toml`.

4. Optionally set `response_fields` and `max_response_chars` on the server config using the
   LLM prompt in the mcp-servers.toml.example file.

### Add a plugin tool

1. Write the plugin file (or copy one from `plugins/`) and place it anywhere accessible to mcp-wrapper.

2. Add to `config/plugins.toml`:
   ```toml
   [plugin_tools.<name>]
   path = "plugins/<name>.py"
   max_response_chars = 8000   # optional
   ```

3. Add to `config/rules-defaults.toml` under `[__plugins__]`:
   ```toml
   [__plugins__]
   allow = ["<name>"]
   ```

4. Restart mcp-wrapper (plugins are loaded at startup).

5. Use the LLM prompt in `plugins.toml.example` to generate `response_fields`/`max_response_chars`
   after a test run.

### Add a new native HTTP tool

1. Call the API endpoint manually or check its docs to get an example JSON response.

2. Use this prompt to generate the config block:
   > "Generate a [native_tools.<name>] TOML block for the following HTTP API.
   > Endpoint: [URL]. Method: [GET/POST]. Auth: [bearer token / query param named X / header named X].
   > Arguments the agent should supply: [list them]. Static/pinned params: [list them].
   > Example response: [paste it].
   > Include response_fields (4–6 most useful dot-paths) and max_response_chars for a 4k-token
   > context window. Include a complete input_schema with types and descriptions."

3. Add the tool to `config/rules-defaults.toml` under `[__native__]`:
   ```toml
   [__native__]
   allow = ["<tool-name>"]
   ```
   Or with constraints:
   ```toml
   [__native__.constrain.<tool-name>]
   allowed_params = {param = {allowlist = ["value1", "value2"]}}
   rate_limit = {per_minute = 10}
   ```

4. No agent-level config needed — all agents can reach native tools if rules allow.

### Add a new agent

1. Generate a token: `openssl rand -hex 32` or use a secret manager.

2. Add to `config/agents.toml`:
   ```toml
   [agents.<agent-id>]
   token       = "env:<TOKEN_VAR>"
   mcp_servers = ["<server1>", "<server2>"]
   log_only    = false
   ```

3. If the agent needs tighter rules than the defaults, add to `config/rules-agents.toml`:
   ```toml
   [<agent-id>.<server-name>]
   allow = ["Tool1", "Tool2"]
   ```
   This fully replaces the server default for that agent+server pair.

### Enable mobile approval gates

1. Configure Slack or Telegram in `config/wrapper.toml` under `[notifications.slack]` or
   `[notifications.telegram]`.

2. Mark tools that need approval in `rules-defaults.toml`:
   ```toml
   [server.constrain.DangerousTool]
   require_approval = true
   ```

3. For Slack, configure the Interactivity URL in the Slack app settings:
   `<base_url>/slack/interact`

4. The `[approval]` section's `base_url` must be reachable by Slack/Telegram.

### Configure DLP

To escalate a built-in pattern from warn to approve:
```toml
[[dlp.outbound]]
name    = "ssn"
pattern = "\\b\\d{3}-\\d{2}-\\d{4}\\b"
action  = "approve"
```

To add a custom outbound pattern:
```toml
[[dlp.outbound]]
name    = "internal_ticket"
pattern = "\\bINT-\\d{6}\\b"
action  = "block"
```

To disable a built-in pattern:
```toml
[[dlp.outbound]]
name    = "credit_card"
pattern = "."
enabled = false
```

---

## AuditEvent schema

Every tool call produces an AuditEvent written to the SQLite database.

| Field | Type | Description |
|-------|------|-------------|
| timestamp | datetime | UTC time of the event |
| agent_id | string | Agent identifier |
| session_id | string | Session identifier (changes on reconnect) |
| mcp_server | string\|null | Server name or `__native__` for native tools |
| tool | string\|null | Tool name called |
| params | object\|null | Sanitized params (sensitive values redacted by DLP) |
| decision | string | `allowed`, `denied`, `error`, `session_start`, `session_end` |
| denial_reason | string\|null | Why the call was denied |
| credential_accessed | string\|null | Which credential was used |
| response_status | string\|null | `success`, `denied`, or `error` |
| latency_ms | int\|null | End-to-end latency in milliseconds |
| reason | string\|null | Agent-supplied `_reason` (DLP-scanned before storage) |
| approval_id | string\|null | UUID of the approval request if one was created |
| approval_note | string\|null | Human note from the approval resolution |

---

## Response shaping

`response_fields` and `max_response_chars` can be set on both `McpServerConfig` and `NativeToolConfig`.

**`response_fields`** is a list of dot-path strings. Applied to the parsed JSON response dict.
Examples:
- `"temperature"` → `response["temperature"]`
- `"main.temp"` → `response["main"]["temp"]`
- `"weather.0.description"` → `response["weather"][0]["description"]`

If a path does not exist in the response, it is silently omitted.
Non-dict responses (strings, arrays at top level) are not filtered.

**`max_response_chars`** applies after field filtering. If the serialized response exceeds this
length, it is truncated and ` …[N chars truncated]` is appended.

Both operate before DLP inbound scanning, so DLP only sees what the agent will receive.
For MCP proxy responses, if truncation produces a string it is re-wrapped as
`{"content": [{"type": "text", "text": "..."}]}` to preserve the MCP result structure.

---

## Important constraints and invariants

- Agent tokens are looked up at call time; changing a token in config requires restart.
- Rules are loaded at startup; config changes require restart.
- A tool not listed in either `allow` or `constrain` for a server is always denied.
- `rules-agents.toml` entries fully replace (not merge with) the server default for that agent+server.
- Native tools take priority over plugin tools; both take priority over MCP server tool names.
- `log_only = true` skips enforcement for MCP proxy calls only; native and plugin tools always enforce.
- Plugin files are loaded once at startup; a restart is required after editing a plugin file.
- If a plugin file fails to load at startup, that tool is silently absent (logged at ERROR level); other tools are unaffected.
- Static params in native tools cannot be overridden by agents regardless of input schema.
- The `credential_param` and `credential_header` names are stripped from agent arguments
  before merging to prevent credential substitution attacks.
- DLP scans the `_reason` field before storing it to prevent audit log as exfiltration channel.
- All approval notification payloads have outbound DLP redaction applied before sending.
