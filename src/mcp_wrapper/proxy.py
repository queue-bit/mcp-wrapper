from __future__ import annotations

import logging
import time
import uuid
from typing import Any

import httpx

from .credentials import CredentialBroker
from .identity import IdentityResolver
from .limiter import RateLimiter
from .logger import AuditLogger
from .models import AuditEvent, Session, WrapperConfig
from .rules import check_tool, get_effective_rules, validate_params

log = logging.getLogger(__name__)


class McpProxy:
    """Forwards MCP tool calls to downstream servers, logging every request."""

    def __init__(
        self,
        config: WrapperConfig,
        identity: IdentityResolver,
        audit: AuditLogger,
        credentials: CredentialBroker,
        limiter: RateLimiter,
    ):
        self._config = config
        self._identity = identity
        self._audit = audit
        self._credentials = credentials
        self._limiter = limiter

    def _server_for_tool(self, tool_name: str, agent_config) -> tuple[str, Any] | None:
        for server_name in agent_config.mcp_servers:
            if tool_name.startswith(f"{server_name}.") or tool_name.startswith(f"{server_name}_"):
                server_cfg = self._config.mcp_servers.get(server_name)
                if server_cfg:
                    return server_name, server_cfg
        for server_name in agent_config.mcp_servers:
            server_cfg = self._config.mcp_servers.get(server_name)
            if server_cfg:
                return server_name, server_cfg
        return None

    async def _deny(
        self,
        session: Session,
        server_name: str | None,
        tool_name: str,
        params: dict[str, Any],
        reason: str,
    ) -> None:
        log.warning("denied: agent=%s server=%s tool=%s reason=%s", session.agent_id, server_name, tool_name, reason)
        await self._audit.log(
            AuditEvent(
                agent_id=session.agent_id,
                session_id=session.session_id,
                mcp_server=server_name,
                tool=tool_name,
                params=params,
                decision="denied",
                denial_reason=reason,
                response_status="denied",
                latency_ms=0,
            )
        )
        raise PermissionError(reason)

    async def call_tool(
        self, session: Session, tool_name: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        agent_cfg = self._identity.get_agent_config(session.agent_id)
        if agent_cfg is None:
            raise ValueError(f"No config for agent {session.agent_id!r}")

        start = time.monotonic()
        response_status = "error"
        credential_accessed = None

        server_result = self._server_for_tool(tool_name, agent_cfg)
        server_name: str | None = server_result[0] if server_result else None

        if not agent_cfg.log_only:
            if server_name is None:
                await self._deny(session, None, tool_name, params, f"no MCP server found for tool {tool_name!r}")

            effective_rules = get_effective_rules(self._config, session.agent_id, server_name)  # type: ignore[arg-type]
            if effective_rules is None:
                await self._deny(session, server_name, tool_name, params, f"no rules configured for server {server_name!r}")

            allowed, constraint = check_tool(effective_rules, tool_name)  # type: ignore[arg-type]
            if not allowed:
                await self._deny(session, server_name, tool_name, params, f"tool {tool_name!r} not in ruleset for {server_name!r}")

            if constraint is not None:
                if constraint.rate_limit is not None:
                    if not self._limiter.check(session.agent_id, tool_name, constraint.rate_limit):
                        await self._deny(session, server_name, tool_name, params, f"rate limit exceeded for tool {tool_name!r}")

                param_denial = validate_params(params, constraint)
                if param_denial is not None:
                    await self._deny(session, server_name, tool_name, params, param_denial)

        try:
            if server_result is None:
                raise ValueError(f"No MCP server found for tool {tool_name!r}")

            _, server_cfg = server_result
            token = self._credentials.get_token(server_name)  # type: ignore[arg-type]
            if token:
                credential_accessed = server_name

            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            if token:
                headers["Authorization"] = f"Bearer {token}"

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    server_cfg.url,
                    json={
                        "jsonrpc": "2.0",
                        "id": str(uuid.uuid4()),
                        "method": "tools/call",
                        "params": {"name": tool_name, "arguments": params},
                    },
                    headers=headers,
                    timeout=30.0,
                )
                resp.raise_for_status()
                data = resp.json()
                if "error" in data:
                    raise RuntimeError(f"MCP error: {data['error']}")
                result = data.get("result", data)
                response_status = "success"
                return result

        except Exception as e:
            log.error("Tool call failed: tool=%s error=%s", tool_name, e)
            response_status = "error"
            raise
        finally:
            latency_ms = int((time.monotonic() - start) * 1000)
            await self._audit.log(
                AuditEvent(
                    agent_id=session.agent_id,
                    session_id=session.session_id,
                    mcp_server=server_name,
                    tool=tool_name,
                    params=params,
                    decision="allowed",
                    credential_accessed=credential_accessed,
                    response_status=response_status,
                    latency_ms=latency_ms,
                )
            )
