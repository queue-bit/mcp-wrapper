# MCP Security Wrapper
### Credential Isolation, Audit Logging & Action Whitelisting for MCP Servers
*Project Plan — v0.1 Draft*

---

## 1. Overview

Model Context Protocol (MCP) provides a standardized interface between LLM agents and external tools and services. However, MCP itself is protocol-neutral — it defines *how* the agent communicates with tools, but not how credentials are stored, which actions are permitted, or how agent activity is recorded.

This project builds a reusable security and monitoring wrapper that sits between any MCP-compatible LLM client and one or more MCP servers. The wrapper enforces credential isolation, action whitelisting, and structured audit logging without requiring changes to upstream MCP servers or the downstream LLM client.

> **Core principle:** The LLM agent never holds credentials directly. It expresses intent; the wrapper validates, executes, and records.

---

## 2. Agent Permission Model

A core design goal is supporting multiple agents with different permission scopes connecting to the same wrapper instance. MCP servers are configured once; the wrapper determines what each agent can access and do.

```
┌─────────────┐        ┌──────────────────────────────────────┐
│  Personal   │──────▶ │          MCP Security Wrapper        │
│  Assistant  │        │                                      │
│  Agent      │        │  Agent: personal-assistant           │
└─────────────┘        │  Permissions: ha.*, gmail.read,      │
                       │              gmail.send              │
┌─────────────┐        │                                      │
│  Research   │──────▶ │  Agent: research-agent               │
│  Agent      │        │  Permissions: web.search,            │
│             │        │              gdrive.read             │
└─────────────┘        │                                      │
                       └──────────────────────────────────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    ▼                   ▼                   ▼
              ┌──────────┐       ┌──────────┐       ┌──────────┐
              │ HA MCP   │       │ Gmail    │       │ GDrive   │
              │ Server   │       │ MCP      │       │ MCP      │
              └──────────┘       └──────────┘       └──────────┘
```

### Agent Identity

Each connecting agent presents an **agent identity** when it connects to the wrapper. The wrapper uses this identity to look up the agent's permission profile and apply the appropriate rules for every call made in that session.

Identity is established via a **shared secret token** issued per agent — simple, local-network appropriate, and avoids complex auth infrastructure for home use. Each agent is configured with its token; the wrapper validates it on connection.

### Permission Profiles

Each agent has a named profile in the config that defines:

- Which MCP servers it can reach
- Which tools on those servers it can call
- Parameter-level constraints specific to that agent
- Whether confirmation gates apply
- Rate limits scoped to that agent

Profiles use a **wildcard + explicit deny** syntax to keep common cases concise:

```toml
[agents.personal-assistant]
token = "env:PERSONAL_ASSISTANT_TOKEN"   # retrieved from env or keyring
mcp_servers = ["homeassistant", "gmail", "google-calendar"]

  [[agents.personal-assistant.rules]]
  tool = "homeassistant.*"               # all HA tools permitted
  confirmation_required = false

  [[agents.personal-assistant.rules]]
  tool = "gmail.send"
  confirmation_required = true           # always confirm outbound email
  allowed_params.to.allowlist = ["known@example.com"]

  [[agents.personal-assistant.rules]]
  tool = "gmail.read"
  confirmation_required = false

[agents.research-agent]
token = "env:RESEARCH_AGENT_TOKEN"
mcp_servers = ["web-search", "google-drive"]  # no HA, no Gmail

  [[agents.research-agent.rules]]
  tool = "web_search.*"
  confirmation_required = false

  [[agents.research-agent.rules]]
  tool = "gdrive.read"
  confirmation_required = false
  # gdrive.write not listed = implicitly denied
```

Anything not explicitly listed in an agent's rules is **denied by default**, regardless of what the downstream MCP server exposes.

### Audit Log Includes Agent Identity

Every log entry is tagged with the agent identity, making it straightforward to filter activity by agent, detect cross-agent anomalies, or review what a specific agent has been doing:

```json
{
  "timestamp": "2025-04-23T14:32:01.442Z",
  "agent_id": "personal-assistant",
  "session_id": "sess_abc123",
  "tool": "homeassistant.turn_off",
  ...
}
```

---

## 3. Problem Statement

Agentic LLM systems that connect to real services introduce risks that traditional application security is not designed for:

- **Prompt injection** — malicious content in external sources (web pages, emails, documents) can manipulate the agent into misusing legitimate tool access
- **Credential exposure** — credentials stored in env vars or config files are accessible to the agent process and can be exfiltrated
- **Unbounded action scope** — without whitelisting, a compromised agent can use any action the MCP server exposes
- **No observability** — without logging, there is no way to detect anomalous behavior or reconstruct what happened after an incident
- **Credential sprawl** — multiple MCP servers each holding their own credentials in their own ways, with no central management

---

## 3. Goals

### Must Have
- [ ] Credential isolation — MCP servers retrieve credentials from a secure store at call time; credentials are never passed through the agent
- [ ] Action whitelisting — explicit allow-list of permitted tools and parameters per agent; all other calls are rejected
- [ ] Structured audit logging — every request, decision, and response logged with timestamp, agent identity, source, action, parameters, and outcome
- [ ] Drop-in compatibility — presents a standard MCP interface; existing clients connect without modification
- [ ] Multi-agent support — multiple agents with distinct permission profiles connect to a single wrapper instance; MCP servers are configured once and shared
- [ ] Agent identity — each agent authenticates with the wrapper; all enforcement and logging is scoped to that identity

### Should Have
- [ ] Parameter validation — enforce types, ranges, and allowed values on action inputs
- [ ] Rate limiting — per-action and per-session call limits
- [ ] Human confirmation hooks — flag high-impact actions for explicit approval before execution
- [ ] Anomaly alerting — detect and surface unusual action patterns
- [ ] DLP scanning — inspect outbound parameters and inbound responses for sensitive data patterns with block/redact/alert actions

### Nice to Have
- [ ] Web UI dashboard for log browsing and rule management
- [ ] LLM model routing integration (local vs cloud escalation)
- [ ] Per-session trust levels
- [ ] Replay and simulation mode for testing rules against historical traffic

---

## 4. Architecture

```
┌─────────────────────┐   ┌─────────────────────┐
│  Personal Assistant │   │   Research Agent    │
│  Agent              │   │   Agent             │
│  (token: pa-token)  │   │  (token: ra-token)  │
└──────────┬──────────┘   └──────────┬──────────┘
           │ MCP + identity token     │ MCP + identity token
           └──────────────┬───────────┘
                          ▼
┌─────────────────────────────────────────────────────────┐
│                  MCP Security Wrapper                   │
│                                                         │
│  ┌──────────────┐                                       │
│  │   Identity   │  resolve agent → permission profile  │
│  │   resolver   │                                       │
│  └──────┬───────┘                                       │
│         ▼                                               │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │   Request   │  │    Action    │  │     Audit     │  │
│  │  Sanitizer  │→ │  Whitelist   │→ │    Logger     │  │
│  └─────────────┘  │ (per-agent)  │  │ (agent-tagged)│  │
│                   └──────┬───────┘  └───────────────┘  │
│                          │                              │
│                   ┌──────▼───────┐                      │
│                   │     DLP      │  inspect outbound    │
│                   │   Scanner    │  before it leaves    │
│                   └──────┬───────┘                      │
│                          │                              │
│  ┌─────────────────────────────────────────────────┐   │
│  │            Credential Broker                    │   │
│  │   (retrieves secrets at call time from store)   │   │
│  └──────────────────────┬──────────────────────────┘   │
└─────────────────────────┼───────────────────────────────┘
                          │  Authenticated calls
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
    ┌──────────┐   ┌──────────────────┐   ┌──────────────────┐
    │ HA MCP   │   │ Gmail MCP        │   │ GDrive MCP       │
    │ (local)  │   │ (remote/cloud)   │   │ (remote/cloud)   │
    └──────────┘   └──────────────────┘   └──────────────────┘
    (PA only)      (PA only)              (Research only)
```

### Key Design Decisions

**The wrapper is a proxy, not a plugin.** It runs as a separate process, presents a valid MCP endpoint, and forwards approved calls to downstream MCP servers. This means it works with any MCP-compatible client and any MCP server without modification to either.

**MCP servers are configured once, shared by all agents.** Adding a new MCP server to the wrapper makes it *available* — which agents can actually reach it and what they can do is controlled entirely by their permission profiles. There is no per-agent MCP server setup.

**Credentials flow down, never up.** The credential broker injects credentials into outbound calls to MCP servers. No agent ever receives or handles tokens directly.

**The whitelist is the security boundary.** If an action is not explicitly listed in an agent's profile, it is denied regardless of what the downstream MCP server exposes. Default-deny per agent.

**Agent identity is established at connection time.** Every subsequent call in a session inherits that identity. The whitelist, rate limiter, confirmation gate, and audit log all operate in the context of the resolved agent.

**MCP servers can be local or remote.** The wrapper connects outbound to MCP servers over standard HTTPS regardless of where they are hosted. Local servers (Home Assistant), self-hosted servers, and cloud-hosted servers (Gmail, Google Drive) are all treated identically from the wrapper's perspective. The inbound agent-facing surface is where network security controls apply; the outbound MCP server connections rely on standard TLS and the credential broker for authentication.

**Outbound data is as important as inbound actions.** The DLP scanner inspects tool call parameters before they leave the wrapper toward any MCP server — local or remote. Sensitive data patterns (credentials, PII, internal identifiers) can be blocked or redacted before reaching a third-party server. This is especially important for remote/cloud MCP servers where the wrapper has no control over what the server does with received data.

---

## 5. Component Design

### 5.1 Identity Resolver

The first component every inbound request passes through. Establishes which agent is making the request and loads its permission profile for use by all downstream components.

- Validates the agent's token against the configured agent registry
- Resolves the token to a named agent identity (`personal-assistant`, `research-agent`, etc.)
- Loads the agent's permission profile into the request context
- Rejects unauthenticated connections before they reach any other component
- Emits a session-start audit event on successful authentication

```
Input:  MCP connection with identity token
Output: Authenticated session with resolved agent profile
```

### 5.2 Request Sanitizer

Processes all inbound requests from the agent before they reach the whitelist.

- Strips or tags content that arrived from external sources (web, email, documents)
- Wraps untrusted content in markers so downstream validation can treat it appropriately
- Detects and rejects structurally anomalous requests (malformed tool calls, unexpected parameter shapes)

```
Input:  Raw MCP tool call from agent
Output: Sanitized, annotated tool call
```

### 5.3 Action Whitelist

The core enforcement layer. Rules are defined per agent in the config — the whitelist evaluates every call against the *calling agent's* profile, not a global ruleset.

Each agent's rules define:
- **tool** — the MCP tool name (wildcards supported, e.g. `homeassistant.*`)
- **allowed_params** — which parameters are accepted and their valid types/ranges
- **denied_values** — explicit blocklist for parameter values (e.g., block external URLs)
- **confirmation_required** — boolean, triggers human approval gate if true
- **rate_limit** — max calls per minute/hour for this agent on this tool

An agent that attempts to call a tool not in its profile receives a denial — even if another agent is permitted to use that same tool. The downstream MCP server is never contacted for denied calls.

Example rule:

```yaml
rules:
  - tool: homeassistant.turn_off
    allowed_params:
      entity_id:
        type: string
        pattern: "^(light|switch|climate)\\..*"
    rate_limit:
      per_minute: 10
    confirmation_required: false

  - tool: homeassistant.call_service
    confirmation_required: true   # always requires human approval

  - tool: gmail.send
    allowed_params:
      to:
        type: string
        allowlist:
          - "known-address@example.com"
    confirmation_required: true
```

### 5.4 DLP Scanner

Inspects outbound tool call parameters *after* whitelist approval but *before* the credential broker dispatches the call to the MCP server. This is the last point where data can be examined and stopped before it leaves the wrapper — particularly important for remote and cloud-hosted MCP servers where you have no visibility into what happens to data once received.

**Why outbound DLP matters here specifically:**
- Cloud MCP servers (Gmail, Google Drive, web search) receive the full content of tool call parameters
- A prompt injection could cause an agent to include sensitive local data in a web search query or email body
- Without inspection, sensitive data could leave your network silently and legitimately (the action was whitelisted, the credential was valid)

**What it inspects:**
- Tool call parameters being sent to MCP servers
- Response content returned from MCP servers before it reaches the agent (inbound DLP)

**Detection capabilities (configurable per agent and per MCP server):**

```toml
[dlp]
  [[dlp.rules]]
  name = "credentials"
  pattern = "(Bearer\s+[A-Za-z0-9\-._~+/]+=*|sk-[a-zA-Z0-9]{32,})"
  action = "block"         # block | redact | alert
  alert = true

  [[dlp.rules]]
  name = "local-ip-ranges"
  pattern = "(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)"
  action = "block"         # stop internal IPs leaving to cloud servers
  alert = true

  [[dlp.rules]]
  name = "pii-email"
  pattern = "[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
  action = "redact"        # replace with [REDACTED-EMAIL]
  alert = false
  exceptions = ["known@example.com"]   # allowlisted values pass through
```

**Actions:**
- **block** — reject the call entirely, log the violation, return error to agent
- **redact** — replace matched content with a placeholder before the call proceeds
- **alert** — log the match but allow the call through (useful during initial tuning)

DLP rules can be scoped globally, per agent, or per MCP server destination — a rule that makes sense for cloud MCP servers may not be needed for a local Home Assistant server.

```
Input:  Approved tool call with parameters
Output: Cleared call (possibly redacted), or blocked with violation log entry
```

#### DLP Implementation Options

The DLP scanner is implemented as a layered pipeline. Each layer is independently enabled via config and optional dependencies. Layers run in order; a block decision from any layer stops the call.

**Layer 1 — Regex (built-in, no extra dependencies)**

Pattern matching against known secret and sensitive data formats. Pattern sets are sourced from the [gitleaks](https://github.com/gitleaks/gitleaks) and [trufflehog](https://github.com/trufflesecurity/trufflehog) rule libraries, which are actively maintained as new token formats emerge. Covers: API keys, bearer tokens, private keys, AWS/GCP/Azure credentials, database connection strings, internal IP ranges, and custom org-specific patterns.

This layer is always present. It is the lowest-latency option and catches the highest-confidence cases.

**Layer 2 — PII detection: Microsoft Presidio (optional, local)**

[Presidio](https://github.com/microsoft/presidio) is an open-source PII detection and anonymization library that runs entirely locally. It uses a combination of regex and spaCy NLP models to detect: names, email addresses, phone numbers, credit card numbers, SSNs, IBANs, passport numbers, medical identifiers, and more. Its built-in anonymizer maps directly to the `redact` action.

Enabled via `pip install mcp-wrapper[dlp-pii]`. Requires spaCy language models (~100–500MB depending on language). Adds meaningful per-call latency — recommended to enable only for MCP servers that handle sensitive data (email, documents) rather than globally.

Do not use cloud-based PII APIs (AWS Comprehend, Google Cloud DLP, Azure) for this — sending data to a cloud DLP service to check whether it is safe to send to a cloud MCP server is circular. The data has already left by the time you get a result.

**Layer 3 — Prompt injection detection: llm-guard (optional, local)**

[llm-guard](https://github.com/protectai/llm-guard) is an open-source library with specific scanners for prompt injection, jailbreaking, and toxic content in both inputs and outputs. Used here to inspect MCP server *responses* before they reach the agent — the most likely vector for indirect prompt injection.

Enabled via `pip install mcp-wrapper[dlp-injection]`. Runs locally. Adds latency proportional to content length.

[Lakera Guard](https://lakera.ai) is an API-based alternative with higher accuracy, but response content leaves your environment to be checked — appropriate in some deployments, not others.

#### Recommended pipeline by deployment type

| Deployment | Layer 1 (regex) | Layer 2 (Presidio) | Layer 3 (llm-guard) |
|---|---|---|---|
| Home / local-only MCP servers | Yes | No | No |
| Home with cloud MCP servers (Gmail, web search) | Yes | Yes (for email/doc servers) | Optional |
| Small team, mixed cloud | Yes | Yes | Yes |
| Security research / high-trust required | Yes | Yes | Yes |

### 5.5 Credential Broker

- Retrieves secrets from the system keyring (Linux keyring / macOS Keychain) at call time
- Injects credentials into outbound MCP requests
- Supports credential rotation without service restart
- Logs credential *access events* (not the credential values) tagged with agent identity for audit purposes

Supported secret backends (in priority order):
1. Linux kernel keyring (`keyctl`) — preferred for Pi/Linux deployments
2. `systemd-creds` — for systemd-managed service deployments
3. HashiCorp Vault — for multi-machine or production setups
4. Encrypted file (age/sops) — fallback, at minimum better than plaintext

### 5.6 Audit Logger

Writes a structured record for every event that passes through the wrapper. All entries are tagged with the agent identity, enabling per-agent activity review and cross-agent anomaly detection.

Log entry schema:

```json
{
  "timestamp": "2025-04-23T14:32:01.442Z",
  "agent_id": "personal-assistant",
  "session_id": "sess_abc123",
  "tool": "homeassistant.turn_off",
  "params": { "entity_id": "light.kitchen" },
  "decision": "allowed",
  "rule_matched": "homeassistant.*",
  "credential_accessed": "ha_token",
  "response_status": "success",
  "latency_ms": 142,
  "model_used": "local/llama3",
  "confirmation": null
}
```

Log destinations (configurable):
- Local SQLite database — default, queryable, filterable by agent
- Append-only JSONL file — simple, easy to ship elsewhere
- Syslog — for integration with existing log infrastructure

### 5.7 Human Confirmation Gate (optional)

For actions flagged `confirmation_required: true`, the wrapper pauses execution and emits a confirmation request tagged with the agent identity and action details. The agent receives a pending status. Execution only proceeds when the confirmation is received through an out-of-band channel.

Confirmation channels:
- Touchscreen UI (ideal for the Pi panel use case — shows which agent is requesting what)
- REST endpoint polled by a UI
- CLI prompt (development/testing)

---

## 6. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.11+ | Strong MCP ecosystem, good keyring libraries, readable |
| MCP library | `mcp` (official Python SDK) | Standard, maintained |
| Secret store | `keyring` library | Abstracts Linux/macOS/Windows backends |
| Config format | TOML | Readable, less error-prone than YAML for rules |
| Audit DB | SQLite via `aiosqlite` | Zero-infrastructure, queryable, local |
| Rate limiting | `limits` + in-memory | Simple, no Redis dependency for home use |
| HTTP (optional UI) | FastAPI | Lightweight, async-native |
| Tests | pytest + pytest-asyncio | Standard |

---

## 7. File Structure

```
mcp-security-wrapper/
├── README.md
├── pyproject.toml
├── config/
│   ├── wrapper.toml          # Main config (ports, log paths, secret backend)
│   └── rules.toml            # Action whitelist rules
├── src/
│   └── mcp_wrapper/
│       ├── __init__.py
│       ├── main.py           # Entry point, starts proxy server
│       ├── proxy.py          # MCP protocol handling, request routing
│       ├── sanitizer.py      # Request sanitization
│       ├── whitelist.py      # Rule loading and enforcement
│       ├── credentials.py    # Credential broker, keyring integration
│       ├── logger.py         # Audit logging, SQLite writer
│       ├── limiter.py        # Rate limiting
│       ├── confirmation.py   # Human approval gate
│       └── models.py         # Shared data models (Pydantic)
├── tests/
│   ├── test_whitelist.py
│   ├── test_sanitizer.py
│   ├── test_credentials.py
│   └── test_logger.py
└── examples/
    ├── homeassistant/        # Example rules + setup for HA MCP
    └── gmail/                # Example rules + setup for Gmail MCP
```

---

## 8. Phases

### Phase 1 — Core Proxy (MVP)
*Goal: a working transparent proxy that logs everything*

- MCP proxy that forwards calls to a single downstream MCP server
- Basic audit logging to SQLite
- Credential injection from system keyring
- No whitelist yet (log-only mode — observe before enforcing)

Deliverable: working proxy, can connect Claude Code or similar to HA MCP through it and see logs.

### Phase 2 — Enforcement
*Goal: actual security boundary*

- Whitelist rule engine with TOML config
- Parameter validation
- Default-deny posture with explicit allow rules
- Rate limiting
- Rejection logging (log *why* something was blocked)

Deliverable: wrapper actively enforcing rules, safe to expose to an agent with real HA access.

### Phase 3 — Multi-server & Credential Management
*Goal: handle real-world complexity*

- Route to multiple downstream MCP servers from a single wrapper endpoint
- Per-server credential management
- Credential rotation support
- Human confirmation gate (REST + simple UI)

Deliverable: single wrapper managing HA + Gmail + other MCP servers.

### Phase 4 — Observability & Polish
*Goal: useful long-term, not just functional*

- Log query interface (CLI or simple web UI)
- Anomaly detection (action pattern baseline + alerting)
- Grafana-compatible metrics export (optional)
- Thorough documentation and example configs for common MCP servers

---

## 9. Decisions

Previously open questions, now resolved:

1. **Agent identity transport** — `Authorization: Bearer <token>` HTTP header. Auth happens at the transport layer before any MCP messages are processed — no authentication window, standard pattern, immediate `401` rejection for unknown tokens. (The handshake tool approach was considered but rejected due to the gap between connection establishment and the handshake call.)

2. **MCP transport** — Streamable HTTP first (current 2025 MCP standard), stdio second. Agents POST requests to an endpoint; responses can stream via SSE when needed but don't require a persistent connection.

3. **Session identity** — connection-level tracking is sufficient for v1. Each authenticated connection gets a generated `session_id` logged alongside the `agent_id`.

4. **Whitelist granularity** — hybrid: tool-level required, parameter-level optional. Every allowed tool must be explicitly listed (default-deny at the tool level is the hard security boundary). Parameter-level rules are addons applied where the tool is high-risk or takes values that could be weaponized. No parameter rules needed for low-risk read-only tools.

5. **Confirmation UX** — two-tier:
   - Phase 2: REST endpoint (`/pending`, `/approve/{id}`, `/deny/{id}`) + minimal browser UI
   - Phase 3: external notification channel (Slack, TBD) — no Telegram
   - Phase 4: touchscreen UI for Pi panel
   - Timeout behavior: **auto-deny** after configurable duration (default 60s). Agent receives clear error: `"Confirmation timeout — action denied"`.

6. **Log retention policy** — to be defined before Phase 4. SQLite rotation/archive strategy TBD.

---

## 10. Network Security & Deployment

The wrapper’s agent-facing surface requires explicit consideration depending on where agents run relative to the wrapper. “Trust the local network” is not a safe default assumption.

### Threat Model

Even on a home network, the following are realistic threats:

- Token interception on an unencrypted connection (other devices on the LAN, rogue device on guest WiFi)
- A compromised agent process on an otherwise trusted machine using its credentials to probe the wrapper
- An attacker with LAN access replaying captured tool calls
- Future remote access requirements exposing the wrapper to broader networks

### Deployment Tiers

```
Loopback only (localhost)
  Agents and wrapper on same machine
  → No TLS needed, token sufficient, lowest complexity

Trusted LAN
  Agents on known, segmented devices
  → TLS strongly recommended, token for agent identity

Untrusted or mixed LAN
  Guest devices present, network not fully controlled
  → TLS required + short-lived tokens, or mTLS

Remote / across internet
  → Never expose wrapper directly
     Use Tailscale (recommended) or WireGuard VPN
     Wrapper listens on VPN interface only
```

### Transport Encryption (TLS)

All non-loopback connections between agents and the wrapper should be encrypted. The wrapper supports TLS configuration via cert/key paths in `wrapper.toml`. For automatic certificate management, running behind **Caddy** as a reverse proxy is the recommended approach — it handles cert issuance and renewal transparently.

```toml
[server]
host = "0.0.0.0"
port = 8443
tls_cert = "/etc/mcp-wrapper/cert.pem"
tls_key  = "/etc/mcp-wrapper/key.pem"
```

### Mutual TLS (mTLS)

For zero-trust deployments where network-level trust cannot be assumed, the wrapper supports mutual TLS. Both sides present certificates signed by a shared CA:

- The wrapper presents its server cert (agent knows it’s talking to the real wrapper)
- The agent presents a client cert (wrapper knows the request is from a legitimate agent process, not just a stolen token)
- Token theft alone is insufficient — an attacker also needs the client certificate

Each agent gets its own client certificate, which also serves as its identity — the token-based identity step can be skipped entirely in mTLS mode since the cert already establishes who the agent is.

```toml
[server.mtls]
enabled = true
ca_cert = "/etc/mcp-wrapper/ca.pem"   # agents must present certs signed by this CA
```

Generating a local CA and per-agent certs for a small fixed set of agents is a one-time operation. Scripts for this will be provided in the `examples/` directory.

### Tailscale (Recommended for Most Deployments)

For home and small-team deployments, **Tailscale** is the recommended network security layer. It provides:

- Encrypted, authenticated connectivity between all devices on your Tailnet regardless of underlying network
- The wrapper only listens on the Tailscale interface (`100.x.x.x`) — never on the public interface
- Device-level mutual authentication managed by Tailscale’s control plane
- Remote access (from your phone, laptop, etc.) without exposing anything to the internet
- No PKI to manage yourself

With Tailscale in place, the network transport is already authenticated and encrypted, and the token-based agent identity approach from the core plan is sufficient for most threat models.

```toml
[server]
host = "100.x.x.x"   # Tailscale interface IP only
port = 8080
tls_cert = ""         # Tailscale handles transport encryption
```

### Token Security

Regardless of transport security, agent tokens should be treated as bearer credentials:

- Generated with sufficient entropy (32+ bytes random, base64-encoded)
- Stored in the system keyring on the agent’s machine, not in plaintext config
- Rotatable without service restart
- Short-lived tokens with refresh (Phase 3+) preferred over indefinite shared secrets for higher security deployments

### What the Wrapper Does Not Do

The wrapper enforces identity and permissions at the application layer. It does not:

- Provide network segmentation — use VLANs, firewall rules, or Tailscale ACLs for this
- Manage TLS certificate lifecycle — use Caddy, Tailscale, or your own PKI
- Protect against a fully compromised agent host — if the machine running the agent is owned, all bets are off

---

## 11. Non-Goals (for now)

- This is not a general-purpose API gateway — it is specifically designed for the MCP protocol
- It does not attempt to make LLMs injection-proof (that's unsolved) — it limits the *damage* a successful injection can cause
- It does not manage MCP server deployment or lifecycle
- It does not replace a VPN or network-level segmentation — these are complementary controls, not alternatives
- It does not manage TLS certificate lifecycle beyond documenting the requirement — use Caddy, nginx, or Tailscale for cert management

---

## 12. References

- [MCP Specification](https://modelcontextprotocol.io)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — particularly LLM01 (Prompt Injection) and LLM06 (Sensitive Information Disclosure)
- [Linux Kernel Keyring](https://www.man7.org/linux/man-pages/man7/keyrings.7.html)
- [systemd-creds](https://systemd.io/CREDENTIALS/)
- [Tailscale](https://tailscale.com) — recommended VPN layer for home/small-team deployments
- [Caddy](https://caddyserver.com) — recommended reverse proxy for automatic TLS management
