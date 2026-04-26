from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from .credentials import CredentialBroker
from .identity import IdentityResolver
from .logger import AuditLogger
from .models import AuditEvent, Session, WrapperConfig

log = logging.getLogger(__name__)


class McpProxy:
    """Forwards MCP tool calls to downstream servers, logging every request."""

    def __init__(
        self,
        config: WrapperConfig,
        identity: IdentityResolver,
        audit: AuditLogger,
        credentials: CredentialBroker,
    ):
        self._config = config
        self._identity = identity
        self._audit = audit
        self._credentials = credentials

    def _server_for_tool(self, tool_name: str, agent_config) -> tuple[str, Any] | None:
        """Find which configured MCP server handles this tool.

        In Phase 1, tool names are prefixed with the server name (e.g. homeassistant.turn_on).
        If no prefix match, try the first server the agent has access to.
        """
        for server_name in agent_config.mcp_servers:
            if tool_name.startswith(f"{server_name}.") or tool_name.startswith(f"{server_name}_"):
                server_cfg = self._config.mcp_servers.get(server_name)
                if server_cfg:
                    return server_name, server_cfg
        # Fallback: first accessible server
        for server_name in agent_config.mcp_servers:
            server_cfg = self._config.mcp_servers.get(server_name)
            if server_cfg:
                return server_name, server_cfg
        return None

    async def call_tool(
        self, session: Session, tool_name: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        agent_cfg = self._identity.get_agent_config(session.agent_id)
        if agent_cfg is None:
            raise ValueError(f"No config for agent {session.agent_id!r}")

        start = time.monotonic()
        server_result = self._server_for_tool(tool_name, agent_cfg)
        response_status = "error"
        credential_accessed = None

        try:
            if server_result is None:
                raise ValueError(f"No MCP server found for tool {tool_name!r}")

            server_name, server_cfg = server_result
            token = self._credentials.get_token(server_name)
            if token:
                credential_accessed = server_name

            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = f"Bearer {token}"

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    server_cfg.url,
                    json={"tool": tool_name, "params": params},
                    headers=headers,
                    timeout=30.0,
                )
                resp.raise_for_status()
                result = resp.json()
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
                    tool=tool_name,
                    params=params,
                    decision="allowed",  # Phase 1: log-only, everything is allowed
                    credential_accessed=credential_accessed,
                    response_status=response_status,
                    latency_ms=latency_ms,
                )
            )
