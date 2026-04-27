from __future__ import annotations

import fnmatch
import logging
import re
import time
from typing import Any

import uuid

import httpx

from .credentials import CredentialBroker
from .identity import IdentityResolver
from .limiter import RateLimiter
from .logger import AuditLogger
from .models import AuditEvent, RuleConfig, Session, WrapperConfig

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

    def _validate_params(self, params: dict[str, Any], rule: RuleConfig) -> str | None:
        """Return a denial reason if any param constraint is violated, else None."""
        for param_name, constraint in rule.allowed_params.items():
            value = params.get(param_name)
            if value is None:
                continue

            if constraint.allowlist is not None:
                if str(value) not in constraint.allowlist:
                    return f"param {param_name!r}: {value!r} not in allowlist {constraint.allowlist}"

            if constraint.pattern is not None:
                if not re.fullmatch(constraint.pattern, str(value)):
                    return f"param {param_name!r}: {value!r} does not match pattern {constraint.pattern!r}"

            if constraint.minimum is not None or constraint.maximum is not None:
                try:
                    numeric = float(value)
                except (TypeError, ValueError):
                    return f"param {param_name!r}: expected numeric value, got {value!r}"
                if constraint.minimum is not None and numeric < constraint.minimum:
                    return f"param {param_name!r}: {value} is below minimum {constraint.minimum}"
                if constraint.maximum is not None and numeric > constraint.maximum:
                    return f"param {param_name!r}: {value} is above maximum {constraint.maximum}"

        return None

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
        response_status = "error"
        credential_accessed = None

        if not agent_cfg.log_only:
            matched_rule = next(
                (r for r in agent_cfg.rules if fnmatch.fnmatch(tool_name, r.tool)),
                None,
            )
            if matched_rule is None:
                denial_reason = f"tool {tool_name!r} not in agent ruleset"
                log.warning("denied: agent=%s tool=%s reason=%s", session.agent_id, tool_name, denial_reason)
                await self._audit.log(
                    AuditEvent(
                        agent_id=session.agent_id,
                        session_id=session.session_id,
                        tool=tool_name,
                        params=params,
                        decision="denied",
                        denial_reason=denial_reason,
                        response_status="denied",
                        latency_ms=0,
                    )
                )
                raise PermissionError(denial_reason)

            if matched_rule.rate_limit is not None:
                if not self._limiter.check(session.agent_id, tool_name, matched_rule.rate_limit):
                    denial_reason = f"rate limit exceeded for tool {tool_name!r}"
                    await self._audit.log(
                        AuditEvent(
                            agent_id=session.agent_id,
                            session_id=session.session_id,
                            tool=tool_name,
                            params=params,
                            decision="denied",
                            denial_reason=denial_reason,
                            response_status="denied",
                            latency_ms=0,
                        )
                    )
                    raise PermissionError(denial_reason)

            param_denial = self._validate_params(params, matched_rule)
            if param_denial is not None:
                log.warning("denied: agent=%s tool=%s reason=%s", session.agent_id, tool_name, param_denial)
                await self._audit.log(
                    AuditEvent(
                        agent_id=session.agent_id,
                        session_id=session.session_id,
                        tool=tool_name,
                        params=params,
                        decision="denied",
                        denial_reason=param_denial,
                        response_status="denied",
                        latency_ms=0,
                    )
                )
                raise PermissionError(param_denial)

        server_result = self._server_for_tool(tool_name, agent_cfg)
        server_name: str | None = None

        try:
            if server_result is None:
                raise ValueError(f"No MCP server found for tool {tool_name!r}")

            server_name, server_cfg = server_result  # type: ignore[misc]
            token = self._credentials.get_token(server_name)
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
                    mcp_server=server_name if server_result else None,
                    tool=tool_name,
                    params=params,
                    decision="allowed",
                    credential_accessed=credential_accessed,
                    response_status=response_status,
                    latency_ms=latency_ms,
                )
            )
