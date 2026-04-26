from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, Field
import uuid


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

class AgentConfig(BaseModel):
    token: str
    mcp_servers: list[str]
    log_only: bool = False


class McpServerConfig(BaseModel):
    url: str
    credential: str | None = None


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


class WrapperConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)
    mcp_servers: dict[str, McpServerConfig] = Field(default_factory=dict)
    agents: dict[str, AgentConfig] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Runtime models
# ---------------------------------------------------------------------------

class Session(BaseModel):
    session_id: str = Field(default_factory=lambda: f"sess_{uuid.uuid4().hex[:12]}")
    agent_id: str
    connected_at: datetime = Field(default_factory=_utcnow)


class AuditEvent(BaseModel):
    timestamp: datetime = Field(default_factory=_utcnow)
    agent_id: str
    session_id: str
    tool: str | None = None
    params: dict[str, Any] | None = None
    decision: str  # allowed | denied | error | session_start | session_end
    rule_matched: str | None = None
    credential_accessed: str | None = None
    response_status: str | None = None
    latency_ms: int | None = None
    denial_reason: str | None = None
