# MCP Wrapper — LLM Setup and Configuration Guide

This document is written for LLMs assisting operators in deploying and configuring mcp-wrapper.
It is a complete technical reference. Human readability is not a goal.

---

## What this system does

mcp-wrapper is an agent gateway and tool execution platform that sits between AI agents and their tool backends.
It serves each agent a filtered list of only the tools they are permitted to call, and shapes responses
to only the fields they need — reducing token usage on both sides of every call.

Backends can be downstream MCP servers, native HTTP APIs defined in config, local Python plugin files,
or operator-defined shell commands and scripts. No MCP server is required to expose tools through the wrapper.

Every tool call passes through the same enforcement pipeline: authentication, access control, parameter
validation, rate limiting, DLP scanning, and human approval gates, then is logged to a SQLite audit database.

Agents connect using standard MCP protocol (SSE or Streamable HTTP), via a Claude-native tool_use HTTP API,
or via a REST API. The wrapper resolves the agent's identity from their bearer token, checks rules, and either
forwards the call or denies it.

---

## Deployment

### Requirements

- Docker 24+ and Docker Compose v2 (recommended), or Python 3.11+ for source installs
- Source install: `pip install -e .` (from repo root)
- Optional extras for source installs: `pip install -e ".[vault-aws]"` for AWS IAM Vault auth,
  `pip install -e ".[vault-gcp]"` for GCP Vault auth
- The pre-built Docker image (`ghcr.io/queue-bit/mcp-wrapper:latest`) includes all extras by default

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
  plugins.toml           # local Python plugin tool definitions (exposed via MCP protocol)
  gateway.toml           # gateway tool definitions (Python/shell/HTTP; exposed via REST API)
  agents.toml            # agent token and access definitions
  rules-defaults.toml    # per-server tool allow/constrain rules (applied to all agents)
  rules-agents.toml      # per-agent rule overrides (fully replaces server default for that agent+server)
```

Load order: wrapper.toml → mcp-servers.toml → native-tools.toml → plugins.toml → gateway.toml → agents.toml
(merged as flat TOML dicts, no key collisions possible). Rules files are loaded separately.

Plugin Python files live anywhere on the filesystem; `path` in `plugins.toml` points to them.
Gateway scripts (Python, shell) also live in `./plugins/` by convention; `path` in `gateway.toml` resolves relative to cwd (`/app` in Docker), so `path = "plugins/my_script.py"` maps to the bind-mounted `./plugins/` directory.
The `plugins/` directory at the repo root contains ready-to-use examples.

---

## Docker deployment

### Prerequisites

- Docker 24+ and Docker Compose v2 (`docker compose` not `docker-compose`)
- Config files prepared in `config/` (copy `.toml.example` → `.toml` and edit)

### Pre-built image

A multi-platform image (`linux/amd64`, `linux/arm64`) is published to the GitHub Container Registry
on every push to `main`. It includes all optional extras (vault-aws, vault-gcp) by default.

```
ghcr.io/queue-bit/mcp-wrapper:latest
ghcr.io/queue-bit/mcp-wrapper:sha-<short-commit>   # pinned release
```

Use the pre-built image unless the operator has a reason to build from source.

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
# 1. Get example config files (no full source install needed)
git clone --depth=1 https://github.com/queue-bit/mcp-wrapper.git
cp -r mcp-wrapper/config ./config

# 2. Edit config/wrapper.toml: set host = "0.0.0.0" and db_path = "data/audit.db"
# Edit config/agents.toml: set tokens and mcp_servers for each agent

# 3. Create docker-compose.yml referencing the pre-built image:
# image: ghcr.io/queue-bit/mcp-wrapper:latest
# (see Volume mount layout below for the full compose structure)

# 4. Export secrets in your shell — no file on disk
export VAULT_TOKEN=hvs.<mcp-wrapper-token>   # if using Vault
# or export env:VAR_NAME values directly for each credential in your config

# 5. Start
docker compose up -d

# 6. Verify
curl http://localhost:8080/health
# → {"status":"ok"}

# 7. Tail logs
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

The pre-built image includes `vault-aws` (boto3) and `vault-gcp` (google-auth) by default — no custom build needed.

For source installs, install extras explicitly:
```bash
pip install -e ".[vault-aws]"
pip install -e ".[vault-aws,vault-gcp]"
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

## Admin UI

A browser-based admin interface is available at `/admin/`. It is enabled by default and provides config editing, audit log viewing, and live status without requiring manual TOML edits or environment variables.

### First-run setup

On first access, the operator is redirected to `/admin/setup` to create an admin account. After creating the account, they are redirected to the login page. The password hash is stored in `wrapper.toml` under `[admin]`.

### Pages

| Path | Purpose |
|------|---------|
| `/admin/dashboard` | Global stats (total/allowed/denied calls, by-agent breakdown), recent audit events |
| `/admin/agents` | Create, edit, delete agents — token field shows `●●●●●●` masked; leave blank on edit to keep current |
| `/admin/servers` | Create, edit, delete MCP server proxies — credential field masked same way |
| `/admin/rules` | Raw TOML editors for `rules-defaults.toml` and `rules-agents.toml`; syntax validated before save |
| `/admin/gateway` | List all gateway tools; edit credentials for any tool that has a `credentials` table |
| `/admin/plugins` | List all plugin tools; edit credentials for any plugin that has a `credentials` table |
| `/admin/audit` | Filterable audit log — agent, tool, decision, date range; HTMX live filter; click any row to open a detail side pane showing full params JSON, response (stored for errors and anomaly-flagged calls only), and anomaly reasons |
| `/admin/settings` | Tabbed settings: Server, Logging, Vault, Notifications (Slack/Telegram), Approval |

### Secrets and credentials

All credentials entered via the admin UI (agent tokens, MCP server credentials, Vault credentials) are stored as **literal values** in the appropriate TOML config file. No env vars or `.env` file required.

After configuring Vault via the Settings → Vault tab, the operator can edit individual agent/server credentials in the UI to use `vault:` references instead of literals.

### Vault configuration

The Settings → Vault tab writes a `[secrets.vault]` section to `wrapper.toml`. Fields:
- Address, KV mount, KV version, path/field separator
- Auth method (token, approle, aws, kubernetes, gcp) — relevant credential fields shown/hidden by JS
- Vault credentials stored as literals; switch to `env:` references for higher-security environments

### Restart-required banner

Most config changes require a server restart to take effect. The admin UI shows a yellow banner after any save. To apply changes:
```
docker compose restart mcp-wrapper
```
The banner auto-clears after restart.

**Exception**: The admin password hash is applied immediately without restart (so the operator can log in after setup).

### Disabling the admin UI

Add to `wrapper.toml`:
```toml
[admin]
enabled = false
```

All `/admin/*` routes are not mounted when disabled. Restart required.

### Admin auth details

- Password stored as PBKDF2-HMAC-SHA256 (600,000 iterations) in `wrapper.toml`
- Session: in-memory UUID cookie, 8-hour expiry (configurable via `session_timeout_hours`)
- CSRF: per-session token embedded in all forms, validated on every POST
- Admin auth is completely separate from the MCP bearer-token auth system; `/health` is unaffected

### LLM prompt for operator setup

> "The operator has just started mcp-wrapper for the first time. Walk them through:
> 1. Browsing to http://localhost:8080/admin/ to create their admin account
> 2. Adding their first agent via the Agents page (generate a token with `openssl rand -hex 32`)
> 3. Adding their MCP server via the MCP Servers page
> 4. Setting the allow rules on the Rules page
> 5. Restarting with `docker compose restart mcp-wrapper`
> 6. Testing with `curl -H 'Authorization: Bearer TOKEN' http://localhost:8080/mcp/tools/list`"

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
| transport | string | `"http"` | Transport protocol: `"http"` (Streamable HTTP) or `"sse"` |
| credential | string\|null | null | Bearer token secret reference; sent as `Authorization: Bearer <value>` |
| tool_prefix | string\|null | null | Override the prefix prepended to tool names (default: lowercased server name). Use to disambiguate multiple servers that expose identical tool names (e.g. two Slack orgs). Rules always match against the native (unprefixed) tool name since they are scoped per server. |
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
| credentials | table | `{}` | `{name: secret_reference}` — resolved at call time and injected as `arguments["_credentials"]` |

#### Plugin credentials

Plugins that need API access can declare credentials in their config block. Values accept the same `env:`, `vault:`, and `keyring:` reference formats as any other secret in config. At call time the values are resolved and injected into `arguments["_credentials"]`:

```toml
[plugin_tools.gmail_list]
path = "/app/plugins/gmail_list.py"

[plugin_tools.gmail_list.credentials]
GOOGLE_CLIENT_ID     = "vault:mcp-wrapper/google#client_id"
GOOGLE_CLIENT_SECRET = "vault:mcp-wrapper/google#client_secret"
GOOGLE_REFRESH_TOKEN = "vault:mcp-wrapper/google#refresh_token"
```

In the plugin:
```python
async def execute(arguments: dict) -> str:
    creds = arguments["_credentials"]   # {"GOOGLE_CLIENT_ID": "...", ...}
    token = await get_access_token(creds)
```

All 8 tools sharing the same underlying credentials can reference the same Vault path — the three Vault reads happen at call time (one per unique reference, not per tool).

Credentials can be edited via **Admin → Plugins → Manage Credentials** and written to Vault from the UI. The Vault path defaults to `mcp-wrapper/plugins/<tool_name>#<key>` for new entries; if the current reference is already a `vault:` path, the UI updates the value at that existing path instead.

A shared helper file (e.g. `_google_auth.py` in the same directory as the plugin) can be imported directly: `from _google_auth import get_access_token`. The wrapper inserts the plugin file's parent directory into `sys.path` when loading it.

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

| File | Tool name | What it does | Extra dep |
|------|-----------|--------------|-----------|
| `fetch_body.py` | `fetch_body` | Fetch a URL; strip scripts/styles; return body text | — |
| `html_to_markdown.py` | `html_to_markdown` | Fetch a URL or convert raw HTML to Markdown; strips navigation chrome | — |
| `upload_file.py` | `upload_file` | Save a base64-encoded file to the upload directory; return its path | — |
| `list_files.py` | `list_files` | List files in the upload directory with size and modified time | — |
| `read_file.py` | `read_file` | Read a text file from the upload directory; supports max_chars + offset pagination | — |
| `write_file.py` | `write_file` | Write text to a file in the upload directory | — |
| `xlsx_to_csv.py` | `xlsx_to_csv` | Read an `.xlsx` file by path and return its contents as CSV | `openpyxl` |
| `pdf_to_text.py` | `pdf_to_text` | Extract text from a PDF by path; optional page range parameter | `pypdf` |
| `math_eval.py` | `math_eval` | Evaluate a mathematical expression safely (no eval()) | — |
| `jq_query.py` | `jq_query` | Fetch JSON from a URL or file and apply a jq filter; payload never enters context | `jq` |
| `csv_query.py` | `csv_query` | Run SQL against a CSV file in the upload directory using DuckDB; table name is `data` | `duckdb` |
| `shell.py` | `shell` | Run a shell command in the upload directory; command is logged via the normal audit pipeline | — |

**Shell plugin env vars:**

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_SHELL_ALLOWLIST` | built-in set | Comma-separated permitted command names, or `*` for unrestricted |
| `MCP_SHELL_TIMEOUT` | `30` | Default max seconds per command |
| `MCP_SHELL_MAX_OUTPUT` | `50000` | Characters before stdout is truncated |

**Upload directory env var** (shared by all file plugins):

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_UPLOAD_DIR` | `/tmp/mcp-uploads` | Directory used by upload_file, list_files, read_file, write_file, csv_query |

---

### gateway.toml

#### [gateway_tools.\<name\>]
One block per gateway tool. `<name>` is the tool name agents will call via the REST gateway API.
Gateway tools are governed by rules under `[__gateway__]` in rules-defaults.toml.
Python gateway files are loaded at startup and on hot-reload (`POST /reload`).
Gateway tools are NOT exposed via the MCP protocol — use `plugin_tools` for that.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| type | string | required | `"python"`, `"shell"`, or `"http"` |
| description | string | `""` | Tool description shown to agents |
| path | string\|null | null | Path to Python file (type=python). Relative to cwd (`/app` in Docker) or absolute. |
| command | string\|null | null | Shell command to run (type=shell). Params passed as JSON on stdin; result read from stdout. |
| url | string\|null | null | HTTP endpoint URL (type=http) |
| method | string | `"POST"` | HTTP method (type=http) |
| headers | table | `{}` | Extra HTTP request headers (type=http) |
| schema | table | `{}` | `{param_name: JSON Schema object}` — defines the tool's inputSchema for agents |
| required | list[string] | `[]` | Required parameter names |
| timeout_seconds | float | `30.0` | Execution timeout in seconds |
| response_fields | list[string]\|null | null | Dot-path fields to extract from the return value (if dict) |
| max_response_chars | int\|null | null | Truncate response to this many characters |

**Python tool contract:**
```python
# Sync or async — both supported
def execute(params: dict) -> str | dict | None:
    agent_id = params.get("_agent_id")   # injected by the wrapper; not from agent input
    # ...
    return "result string"               # or a dict, or {"content": [...]} MCP block
```

**Shell tool contract:**
- JSON params written to stdin; result read from stdout
- Non-zero exit code raises RuntimeError with stderr content
- Command string is operator-defined in config (not user-controlled — no injection risk)

**HTTP tool contract:**
- Params POSTed as JSON body to `url` with `method` and `headers`
- Response parsed as JSON if possible, otherwise returned as text

**Hot-reload:**
`POST /reload` reloads config and loads/unloads Python gateway modules for added and removed tools.
Edits to an existing Python module require a container restart — hot-reload only handles add/remove.

**Example:**
```toml
[gateway_tools.run_report]
type        = "python"
path        = "plugins/run_report.py"
description = "Generate a named business report"
required    = ["report_name"]

[gateway_tools.run_report.schema]
report_name = {type = "string", description = "Name of the report to generate"}
format      = {type = "string", description = "Output format", enum = ["csv", "json", "text"]}

[gateway_tools.deploy_service]
type        = "shell"
command     = "scripts/deploy.sh"
description = "Deploy a service to a target environment"
required    = ["service", "environment"]

[gateway_tools.deploy_service.schema]
service     = {type = "string", description = "Service name"}
environment = {type = "string", description = "Target environment", enum = ["staging", "production"]}
```

Gateway tools are ruled under `__gateway__` in rules files:
```toml
[__gateway__]
allow = ["run_report"]

[__gateway__.constrain.deploy_service]
allowed_params = {environment = {allowlist = ["staging"]}}
require_approval = true
```

---

### Tool router (meta-tools)

The tool router provides two meta-tools — `search_tools` and `call_tool` — that allow agents to discover and invoke any available tool without receiving the full tool list upfront. This is useful for agents with access to many tools where the full tool definitions would occupy too much context.

**Meta-tools are governed by the `__meta__` virtual server name in rules files.**

#### Enabling the tool router

```toml
# rules-defaults.toml
[__meta__]
allow = ["search_tools", "call_tool"]
```

Or as a per-agent override:
```toml
# rules-agents.toml
[my-agent.__meta__]
allow = ["search_tools", "call_tool"]
```

#### Meta-tool definitions

**`search_tools`**
| Input | Type | Description |
|-------|------|-------------|
| query | string (required) | Substring matched against tool names and descriptions (case-insensitive) |
| limit | integer (optional) | Max results, default 10, max 50 |

Returns JSON: `[{name, description, required, optional}, ...]`.

**`call_tool`**
| Input | Type | Description |
|-------|------|-------------|
| name | string (required) | Tool name (as returned by search_tools) |
| arguments | object (required) | Tool arguments |

Routes through the full enforcement pipeline — same auth, rules, DLP, rate limits, approvals, and audit logging as a direct tool call. No governance bypass possible.

#### Governance

`call_tool` dispatches to `McpProxy.call_tool()` with the original session, so all of:
- The outer `call_tool` call is audited under `__meta__`
- The inner tool call is audited under its own server (e.g. `__plugins__`, `homeassistant`)
- Rate limits, approval gates, and DLP on the inner tool all apply as normal

Recursive `call_tool` chains are guarded by a depth limit of 10.

#### Important constraints

- `search_tools` results include the tools the agent is permitted to call (filtered by rules, same as `tools/list`). The results are not a broader universe — the agent sees only what it's allowed to use.
- Adding `__meta__` rules does not grant access to additional tools — it only enables lazy discovery. Tools still need to be allowed under their own virtual server sections.
- Agents not given `__meta__` rules continue to receive all permitted tool definitions upfront in `tools/list`, exactly as before.

---

### agents.toml

#### [agents.\<agent-id\>]
`<agent-id>` is the identifier used in audit logs and rules-agents.toml.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| token | string | required | Bearer token the agent sends; use `env:` or `vault:` reference |
| mcp_servers | list[string] | required | Names matching `[mcp_servers.<name>]` keys this agent can access |
| log_only | bool | `false` | If true, skip enforcement for downstream MCP calls (native tool calls always enforce) |
| shared_key_action | string | `"warn"` | Action when this agent's token matches another agent's token: `"allow"`, `"block"`, `"warn"`, `"notify"` |

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
3. Resolve target: meta-tools (`__meta__`) → native tool registry → plugin registry → gateway registry → MCP server (by agent's mcp_servers list)
4. If `log_only = false` OR target is a meta, native, plugin, or gateway tool:
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
9. Log AuditEvent; run anomaly detection; store anomaly reasons in `anomalies` column and full response in `response` column for errors and anomaly-flagged calls
10. Return result to agent

If the MCP client disconnects mid-call (e.g. timeout during an approval wait), the resulting `asyncio.CancelledError` is caught separately. The audit write is protected with `asyncio.shield()` so the entry is still committed with `response_status = "cancelled"`.

---

## Tool routing

When an agent calls a tool via MCP or the `/mcp/tools/call` REST endpoint, the wrapper resolves it in this order:
1. Check meta-tools first (`search_tools`, `call_tool`) — governed by `__meta__` rules
2. Check native tool registry (`[native_tools.*]`) — governed by `__native__` rules
3. Check plugin registry (`[plugin_tools.*]`) — governed by `__plugins__` rules
4. Check gateway registry (`[gateway_tools.*]`) — governed by `__gateway__` rules
5. Check MCP servers in the agent's `mcp_servers` list, matching by:
   a. Tool name prefix matching server name (e.g. `homeassistant.GetDateTime` → `homeassistant`)
   b. Tool name prefix with underscore (e.g. `homeassistant_GetDateTime`)
   c. Falls back to first server in the list if no prefix match
6. If still not found: deny with "no server or native tool found"

Meta-tools take priority over all others. Native tools take priority over plugins and gateway tools; plugins take priority over gateway tools; all three take priority over MCP server tools.

Gateway tools are also callable directly via `POST /gateway/call` and `POST /gateway/calls` — these endpoints bypass MCP server routing entirely and go straight to the gateway registry (still fully governed by rules).

`call_tool` (the meta-tool) routes through this same priority chain — it can invoke native tools, plugins, gateway tools, or MCP server tools depending on what it resolves to.

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
| GET | `/gateway/tools` | List permitted gateway tools in OpenAI function-calling format |
| POST | `/gateway/call` | Execute a gateway tool; body: `{"name": "tool", "arguments": {...}}` |
| POST | `/gateway/calls` | Batch gateway calls; body: `{"calls": [{"name": "...", "arguments": {...}}]}` |
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

**Via the UI (recommended):**
1. Browse to `/admin/servers` → click **Add server**
2. Enter the name, URL, and credential (accepts `vault:`, `env:`, or a literal value)
3. Save — the server is available immediately for assignment to agents
4. Browse to `/admin/rules` and add rules for the new server under `rules-defaults.toml`
5. Browse to `/admin/agents` and add the server name to the relevant agent's `mcp_servers` list
6. Restart via `docker compose restart mcp-wrapper` to apply config changes

**Via config files (for automation or options not in the UI):**
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

### Add a gateway tool

Gateway tools expose operator-defined Python scripts, shell commands, or HTTP endpoints via a governed REST API without an MCP server.

1. Write the script and place it in `./plugins/` (bind-mounted at `/app/plugins/` in Docker):

   ```python
   # plugins/run_report.py
   def execute(params: dict) -> str | dict:
       # params["_agent_id"] is injected by the wrapper
       return {"report": "..."}
   ```

2. Add to `config/gateway.toml`:
   ```toml
   [gateway_tools.run_report]
   type        = "python"
   path        = "plugins/run_report.py"
   description = "Generate a named report"
   required    = ["report_name"]

   [gateway_tools.run_report.schema]
   report_name = {type = "string", description = "Report name"}
   ```

3. Add to `config/rules-defaults.toml` under `[__gateway__]`:
   ```toml
   [__gateway__]
   allow = ["run_report"]
   ```
   Or with constraints:
   ```toml
   [__gateway__.constrain.run_report]
   rate_limit = {per_minute = 5}
   require_approval = true
   ```

4. Send `POST /reload` to hot-reload the config and load the new module (no restart needed for new tools; restart required to reload edits to an existing module).

5. Agents call the tool via `POST /gateway/call`:
   ```json
   {"name": "run_report", "arguments": {"report_name": "monthly_summary"}}
   ```
   Or list available tools via `GET /gateway/tools` (OpenAI function-calling format, filtered by rules).

### Add a new agent

**Via the UI (recommended):**
1. Browse to `/admin/agents` → click **Add agent**
2. Enter an agent ID and paste or generate a token (the UI can generate one)
3. Select the MCP servers this agent can access
4. Save — the agent is active immediately (no restart needed for new agents added via UI)
5. If the agent needs tighter rules than the defaults, browse to `/admin/rules` and add an entry
   under `rules-agents.toml`

**Via config files (for automation or `vault:` token references):**
1. Generate a token: `openssl rand -hex 32` or use a secret manager.

2. Add to `config/agents.toml`:
   ```toml
   [agents.<agent-id>]
   token       = "vault:mcp-wrapper/agents/<agent-id>#token"
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
| mcp_server | string\|null | Server name, or one of the reserved names: `__native__`, `__plugins__`, `__gateway__`, `__meta__` |
| tool | string\|null | Tool name called |
| params | object\|null | Sanitized params (sensitive values redacted by DLP) |
| decision | string | `allowed`, `denied`, `error`, `session_start`, `session_end` |
| denial_reason | string\|null | Why the call was denied |
| credential_accessed | string\|null | Which credential was used |
| response_status | string\|null | `success`, `denied`, `error`, or `cancelled` (client disconnected during approval wait) |
| latency_ms | int\|null | End-to-end latency in milliseconds |
| reason | string\|null | Agent-supplied `_reason` (DLP-scanned before storage) |
| approval_id | string\|null | UUID of the approval request if one was created |
| approval_note | string\|null | Human note from the approval resolution |
| params_chars | int\|null | Character count of serialized params |
| response_chars | int\|null | Character count of serialized response (after jq/grep filtering if applied) |
| raw_response_chars | int\|null | Character count of response before jq/grep filtering or tool-list filtering; null when no filtering occurred. Used to compute token savings on the dashboard. |
| response | string\|null | Response content; stored only for errors (error text) and anomaly-flagged calls (full JSON); NULL for normal allowed/denied calls |
| anomalies | string\|null | JSON array of anomaly reason strings (e.g. `["first time tool X has been called by this agent"]`); populated when anomalies detected |

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
- Rules are loaded at startup; config changes require restart (exception: `POST /reload` hot-reloads all config including gateway tool additions/removals).
- A tool not listed in either `allow` or `constrain` for a server is always denied.
- `rules-agents.toml` entries fully replace (not merge with) the server default for that agent+server.
- Meta-tools (`search_tools`, `call_tool`) take priority over all other tool types.
- Native tools take priority over plugin tools; both take priority over gateway tools; all three take priority over MCP server tool names.
- `call_tool` dispatches through the full enforcement pipeline with the original session — no governance bypass. Recursive `call_tool` chains are limited to 10 levels.
- Agents without `[__meta__]` rules in `rules-defaults.toml` or `rules-agents.toml` do not see the meta-tools and receive the full permitted tool list as before.
- `log_only = true` skips enforcement for MCP proxy calls only; native, plugin, and gateway tools always enforce.
- Plugin files are loaded once at startup; a restart is required after editing a plugin file.
- Gateway Python files are loaded at startup; `POST /reload` hot-reloads config and loads/unloads modules for added/removed tools. Editing an existing gateway module requires a restart to take effect.
- If a plugin or gateway file fails to load at startup, that tool is silently absent (logged at ERROR level); other tools are unaffected.
- Gateway tools use the reserved server name `__gateway__` in rules files (same pattern as `__native__` and `__plugins__`).
- Gateway shell tools receive params as JSON on stdin; the shell command is operator-defined in config and is not user-controlled (no injection risk). Non-zero exit code raises RuntimeError.
- `_agent_id` is injected into the params dict passed to gateway Python `execute()` functions; it is not part of the tool's public schema and cannot be supplied by agents.
- Gateway tools placed in `./plugins/` are accessible at `path = "plugins/my_script.py"` in `gateway.toml` (resolves to `/app/plugins/my_script.py` inside the Docker container).
- Static params in native tools cannot be overridden by agents regardless of input schema.
- The `credential_param` and `credential_header` names are stripped from agent arguments
  before merging to prevent credential substitution attacks.
- DLP scans the `_reason` field before storing it to prevent audit log as exfiltration channel.
- All approval notification payloads have outbound DLP redaction applied before sending.
- Client disconnections (`asyncio.CancelledError`) still produce audit log entries; the write is shielded from cancellation and sets `response_status = "cancelled"`.
- The `response` column stores content only for errors and anomaly-flagged calls; it is NULL for normal allowed/denied calls to avoid database bloat. `params_chars` and `response_chars` are always recorded for token usage estimation.
- `raw_response_chars` records the pre-filter size when `response_jq`/`response_grep` constraints are applied or when tool listing is filtered by rules; NULL otherwise. The dashboard uses it to compute estimated token savings.
- The `audit.db` path defaults to `"audit.db"` (relative to cwd). In Docker this resolves to the container layer and is lost on rebuild — set `db_path = "data/audit.db"` to persist in the `mcp_data` named volume.
