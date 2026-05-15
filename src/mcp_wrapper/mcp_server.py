from __future__ import annotations

import contextvars
import json
import logging
from collections.abc import Callable, Coroutine
from typing import Any

import mcp.types as types
from mcp.server import Server
from mcp.server.models import InitializationOptions

from .logger import AuditLogger
from .models import AuditEvent, Session
from .proxy import McpProxy

log = logging.getLogger(__name__)

# Per-task context variable: holds the Session for the current MCP connection.
# Set by the SSE/Streamable HTTP auth wrappers before the mcp library's handlers run.
# anyio tasks inherit the parent's ContextVar context, so child tasks spawned by
# the mcp library see the correct session without explicit passing.
current_session: contextvars.ContextVar[Session | None] = contextvars.ContextVar(
    "current_session", default=None
)

CollectToolsFn = Callable[[Session], Coroutine[Any, Any, tuple[list[dict[str, Any]], int]]]


def build_mcp_server(
    proxy: McpProxy,
    collect_tools_fn: CollectToolsFn,
    audit: AuditLogger,
) -> Server:
    server: Server = Server("mcp-security-wrapper")

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        session = current_session.get()
        if session is None:
            return []
        tools_raw, raw_chars = await collect_tools_fn(session)
        result = [
            types.Tool(
                name=t["name"],
                description=t.get("description", ""),
                inputSchema=t.get("inputSchema", {"type": "object", "properties": {}}),
            )
            for t in tools_raw
        ]
        await audit.log(AuditEvent(
            agent_id=session.agent_id,
            session_id=session.session_id,
            tool="tools/list",
            decision="allowed",
            response_status="success",
            response_chars=len(json.dumps(tools_raw)),
            raw_response_chars=raw_chars or None,
        ))
        return result

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict[str, Any] | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        session = current_session.get()
        if session is None:
            raise PermissionError("No authenticated session for this MCP connection")
        result = await proxy.call_tool(session, name, dict(arguments or {}))
        content = result.get("content", [])
        if isinstance(content, list):
            return [
                types.TextContent(type="text", text=block.get("text", str(block)))
                for block in content
                if isinstance(block, dict)
            ]
        return [types.TextContent(type="text", text=str(result))]

    return server
