from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, Field
import uuid

from .dlp import DlpConfig  # noqa: F401 — re-exported for convenience


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Vault configuration
# ---------------------------------------------------------------------------

class VaultAuthConfig(BaseModel):
    method: Literal["token", "approle", "aws", "kubernetes", "gcp"]

    # token auth
    token: str | None = None                        # env:VAULT_TOKEN

    # approle auth
    role_id: str | None = None                      # env:VAULT_ROLE_ID
    secret_id: str | None = None                    # env:VAULT_SECRET_ID

    # aws / kubernetes / gcp — the role name configured in Vault
    role: str | None = None

    # kubernetes: path to the service account JWT
    jwt_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"

    # gcp: "iam" (service account) or "gce" (metadata server)
    gcp_auth_type: Literal["iam", "gce"] = "iam"

    # mount point for the auth backend (defaults applied per method if None)
    mount: str | None = None


class VaultConfig(BaseModel):
    addr: str = "https://127.0.0.1:8200"
    auth: VaultAuthConfig

    # Vault Enterprise namespace (leave empty for open-source Vault)
    namespace: str | None = None

    tls_verify: bool = True

    # KV secrets engine
    kv_mount: str = "secret"
    kv_version: Literal[1, 2] = 2

    # Separator between path and field in vault: secret references.
    # Default "#" avoids collision with forward-slash paths.
    # Set to ":" if your org prefers vault:path/to/secret:field notation.
    path_field_separator: str = "#"


# ---------------------------------------------------------------------------
# Top-level config models
# ---------------------------------------------------------------------------

class NativeToolCredentialInjection(str, Enum):
    bearer = "bearer"
    header = "header"
    query = "query"


class NativeToolConfig(BaseModel):
    description: str
    url: str
    method: str = "GET"
    credential: str | None = None
    credential_injection: NativeToolCredentialInjection = NativeToolCredentialInjection.bearer
    credential_header: str | None = None
    credential_param: str | None = None
    static_params: dict[str, Any] = Field(default_factory=dict)
    input_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}})
    param_placement: Literal["query", "json", "path"] = "query"
    timeout_seconds: float = 30.0
    response_fields: list[str] | None = None
    max_response_chars: int | None = None


class ClaudeToolUseBlock(BaseModel):
    type: Literal["tool_use"]
    id: str
    name: str
    input: dict[str, Any]


class ClaudeToolCallRequest(BaseModel):
    tool_uses: list[ClaudeToolUseBlock]


class ClaudeToolResultBlock(BaseModel):
    type: Literal["tool_result"] = "tool_result"
    tool_use_id: str
    content: str | list[dict[str, Any]]
    is_error: bool = False


class ParamConstraint(BaseModel):
    pattern: str | None = None           # regex — applied to str(value)
    allowlist: list[str] | None = None   # value must be in this list
    minimum: float | None = None         # numeric lower bound (inclusive)
    maximum: float | None = None         # numeric upper bound (inclusive)


class RateLimitConfig(BaseModel):
    per_minute: int | None = None
    per_hour: int | None = None


class ToolConstraint(BaseModel):
    allowed_params: dict[str, ParamConstraint] = {}
    rate_limit: RateLimitConfig | None = None
    require_approval: bool = False
    response_jq: str | None = None
    response_grep: str | None = None


class ApprovalConfig(BaseModel):
    webhook_url: str | None = None
    base_url: str = "http://localhost:8080"
    timeout_seconds: int = 300


class ServerRules(BaseModel):
    allow: list[str] = []                          # fnmatch patterns, no constraints
    constrain: dict[str, ToolConstraint] = {}      # exact name → constraints (implicitly allowed)


class AgentConfig(BaseModel):
    token: str
    mcp_servers: list[str]
    log_only: bool = False
    shared_key_action: Literal["allow", "block", "warn", "notify"] = "warn"


class OAuthConfig(BaseModel):
    grant_type: Literal["client_credentials", "authorization_code"] = "client_credentials"
    client_id: str
    client_secret: str | None = None          # use env:/keyring:/vault: reference
    token_url: str
    authorize_url: str | None = None          # required for authorization_code flow
    scopes: list[str] = []                    # sent as 'scope' (bot scopes for Slack)
    user_scopes: list[str] = []              # sent as 'user_scope' (Slack user token scopes)
    audience: str | None = None               # some providers (Auth0) require this
    pkce: bool = True                         # enable PKCE for authorization_code


class McpServerConfig(BaseModel):
    url: str
    transport: Literal["http", "sse"] = "http"
    credential: str | None = None
    oauth: OAuthConfig | None = None
    response_fields: list[str] | None = None
    max_response_chars: int | None = None
    tool_prefix: str | None = None


class PluginToolConfig(BaseModel):
    path: str
    response_fields: list[str] | None = None
    max_response_chars: int | None = None
    credentials: dict[str, str] = Field(default_factory=dict)  # name → vault/env/plaintext ref


class GatewayToolConfig(BaseModel):
    type: Literal["python", "shell", "http"]
    description: str = ""
    path: str | None = None           # python
    command: str | None = None        # shell
    url: str | None = None            # http
    method: str = "POST"              # http
    headers: dict[str, Any] = Field(default_factory=dict)  # http
    schema: dict[str, Any] = Field(default_factory=dict)   # {param: JSON Schema object}
    required: list[str] = Field(default_factory=list)
    timeout_seconds: float = 30.0
    response_fields: list[str] | None = None
    max_response_chars: int | None = None
    credentials: dict[str, str] = Field(default_factory=dict)  # name → vault/env/plaintext ref


class ServerConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8080
    tls_cert: str | None = None
    tls_key: str | None = None


class LoggingConfig(BaseModel):
    db_path: str = "audit.db"
    jsonl_path: str | None = None
    level: str = "INFO"


class SecretsConfig(BaseModel):
    vault: VaultConfig | None = None


class SlackConfig(BaseModel):
    bot_token: str       # xoxb-… use env: reference
    channel: str         # channel ID (C…)
    signing_secret: str  # from Slack app settings — used to verify interaction payloads


class TelegramConfig(BaseModel):
    bot_token: str            # from @BotFather
    chat_id: str              # your personal or group chat ID
    secret_token: str | None = None  # set on setWebhook for inbound verification


class NotificationsConfig(BaseModel):
    slack: SlackConfig | None = None
    telegram: TelegramConfig | None = None


class AnomalyConfig(BaseModel):
    denial_burst_threshold: int = 5
    denial_burst_window_seconds: int = 60
    business_hours_enabled: bool = False
    business_hours_start: int = 9
    business_hours_end: int = 18
    business_hours_timezone: str = "UTC"
    business_days: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4])  # Mon-Fri


class AdminConfig(BaseModel):
    enabled: bool = True
    username: str = "admin"
    password_hash: str = ""      # empty = first-run setup required
    session_timeout_hours: int = 8


class WrapperConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)
    approval: ApprovalConfig = Field(default_factory=ApprovalConfig)
    anomaly: AnomalyConfig = Field(default_factory=AnomalyConfig)
    dlp: DlpConfig = Field(default_factory=DlpConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    mcp_servers: dict[str, McpServerConfig] = Field(default_factory=dict)
    native_tools: dict[str, NativeToolConfig] = Field(default_factory=dict)
    plugin_tools: dict[str, PluginToolConfig] = Field(default_factory=dict)
    gateway_tools: dict[str, GatewayToolConfig] = Field(default_factory=dict)
    agents: dict[str, AgentConfig] = Field(default_factory=dict)
    admin: AdminConfig = Field(default_factory=AdminConfig)
    # Populated from rules-defaults.toml and rules-agents.toml by load_config
    server_rules: dict[str, ServerRules] = Field(default_factory=dict)
    agent_overrides: dict[str, dict[str, ServerRules]] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Runtime models
# ---------------------------------------------------------------------------

class Session(BaseModel):
    session_id: str = Field(default_factory=lambda: f"sess_{uuid.uuid4().hex[:12]}")
    agent_id: str
    connected_at: datetime = Field(default_factory=_utcnow)
    client_info: str | None = None


class AuditEvent(BaseModel):
    timestamp: datetime = Field(default_factory=_utcnow)
    agent_id: str
    session_id: str
    mcp_server: str | None = None
    tool: str | None = None
    params: dict[str, Any] | None = None
    decision: str  # allowed | denied | error | session_start | session_end
    rule_matched: str | None = None
    credential_accessed: str | None = None
    response_status: str | None = None
    latency_ms: int | None = None
    denial_reason: str | None = None
    reason: str | None = None
    approval_id: str | None = None
    approval_note: str | None = None
    params_chars: int | None = None
    response_chars: int | None = None
    raw_response_chars: int | None = None
    response: str | None = None
    anomalies: list[str] | None = None
    client_info: str | None = None
