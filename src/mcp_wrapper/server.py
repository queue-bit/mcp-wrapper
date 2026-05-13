from __future__ import annotations

"""Streamable HTTP MCP wrapper server.

Presents a standard MCP endpoint. Agents authenticate via:
    Authorization: Bearer <token>

Tool listing and calls are filtered and enforced against the agent's
rules. log_only = true bypasses enforcement for observation mode.
"""

import copy
import logging
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.applications import Starlette
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response
from starlette.routing import Mount, Route

from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from .anomaly import AnomalyDetector
from .approvals import ApprovalManager
from .dlp import DlpScanner
from .credentials import CredentialBroker, SecretResolver, VaultClient
from .identity import IdentityResolver
from .limiter import RateLimiter
from .logger import AuditLogger
from .mcp_server import build_mcp_server, current_session
from .models import (
    AuditEvent,
    ClaudeToolCallRequest,
    ClaudeToolResultBlock,
    Session,
    ToolConstraint,
    WrapperConfig,
)
from .native_tools import NativeToolRegistry
from .notifications import build_notifiers
from .plugin_tools import PluginRegistry
from .proxy import McpProxy
from .rules import check_tool, get_effective_rules

log = logging.getLogger(__name__)


class ToolCallRequest(BaseModel):
    tool: str
    params: dict[str, Any] = {}


class ApprovalResolution(BaseModel):
    approved: bool
    note: str | None = None


def _apply_constraints_to_tool(tool: dict[str, Any], constraint: ToolConstraint) -> dict[str, Any]:
    """Return a copy of the tool definition with param constraints injected into its JSON Schema
    and approval/rate-limit annotations appended to its description."""
    tool = copy.deepcopy(tool)

    properties: dict[str, Any] = tool.get("inputSchema", {}).get("properties", {})
    for param_name, pc in constraint.allowed_params.items():
        if param_name not in properties:
            continue
        prop = properties[param_name]
        if pc.allowlist is not None:
            prop["enum"] = pc.allowlist
        if pc.pattern is not None:
            prop["pattern"] = pc.pattern
        if pc.minimum is not None:
            prop["minimum"] = pc.minimum
        if pc.maximum is not None:
            prop["maximum"] = pc.maximum

    tags: list[str] = []
    if constraint.require_approval:
        tags.append("[requires approval]")
    if constraint.rate_limit is not None:
        rl = constraint.rate_limit
        parts = []
        if rl.per_minute is not None:
            parts.append(f"{rl.per_minute}/min")
        if rl.per_hour is not None:
            parts.append(f"{rl.per_hour}/hr")
        if parts:
            tags.append(f"[rate limited: {', '.join(parts)}]")

    if tags:
        desc = tool.get("description", "")
        tool["description"] = f"{desc} {' '.join(tags)}".strip()

    return tool


def _mcp_tool_to_claude_tool(tool: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": tool["name"],
        "description": tool.get("description", ""),
        "input_schema": tool.get("inputSchema", {"type": "object", "properties": {}}),
    }


def _mcp_result_to_claude_content(result: dict[str, Any]) -> str | list[dict[str, Any]]:
    content = result.get("content", [])
    if isinstance(content, list) and len(content) == 1 and content[0].get("type") == "text":
        return content[0]["text"]
    if isinstance(content, list):
        return content
    return str(result)


def build_resolver(config: WrapperConfig) -> SecretResolver:
    vault_client: VaultClient | None = None
    if config.secrets.vault is not None:
        vault_client = VaultClient(config.secrets.vault)
    return SecretResolver(vault=vault_client)


def build_app(config: WrapperConfig) -> FastAPI:
    resolver = build_resolver(config)
    audit = AuditLogger(
        db_path=config.logging.db_path,
        jsonl_path=config.logging.jsonl_path,
    )
    identity = IdentityResolver(config, resolver)
    credentials = CredentialBroker(config.mcp_servers, resolver)
    limiter = RateLimiter()
    webhook_url = resolver.resolve(config.approval.webhook_url) if config.approval.webhook_url else None
    anomaly = AnomalyDetector(audit, config.anomaly)
    dlp = DlpScanner(config.dlp)
    slack_notifier, telegram_notifier, composite_notifier = build_notifiers(
        config.notifications, resolver
    )
    approvals = ApprovalManager(
        webhook_url=webhook_url,
        base_url=config.approval.base_url,
        timeout_seconds=config.approval.timeout_seconds,
        notifier=composite_notifier,
        dlp=dlp,
    )
    native_registry = NativeToolRegistry(config.native_tools, resolver)
    plugin_registry = PluginRegistry(config.plugin_tools)
    proxy = McpProxy(
        config, identity, audit, credentials, limiter, approvals, anomaly, dlp,
        native_registry=native_registry,
        plugin_registry=plugin_registry,
    )

    async def collect_permitted_tools(session: Session) -> list[dict[str, Any]]:
        """Aggregate and filter the tool list for a session across all sources."""
        agent_cfg = identity.get_agent_config(session.agent_id)
        if agent_cfg is None:
            return []

        tools: list[dict[str, Any]] = []

        async with httpx.AsyncClient() as client:
            for server_name in agent_cfg.mcp_servers:
                server_cfg = config.mcp_servers.get(server_name)
                if server_cfg is None:
                    continue
                token = credentials.get_token(server_name)
                headers: dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                try:
                    resp = await client.post(
                        server_cfg.url,
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                        headers=headers,
                        timeout=10.0,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    server_tools: list[dict[str, Any]] = data.get("result", {}).get("tools", [])
                    if not agent_cfg.log_only:
                        effective_rules = get_effective_rules(config, session.agent_id, server_name)
                        if effective_rules is not None:
                            filtered = []
                            for t in server_tools:
                                allowed, constraint = check_tool(effective_rules, t["name"])
                                if not allowed:
                                    continue
                                if constraint is not None:
                                    t = _apply_constraints_to_tool(t, constraint)
                                filtered.append(t)
                            server_tools = filtered
                        else:
                            server_tools = []
                    tools.extend(server_tools)
                except Exception as e:
                    log.warning("Could not fetch tools from %s: %s", server_name, e)

        # Native tools
        native_defs = native_registry.list_all_definitions()
        if native_defs:
            effective_rules = get_effective_rules(
                config, session.agent_id, NativeToolRegistry.VIRTUAL_SERVER_NAME
            )
            if effective_rules is not None:
                for t in native_defs:
                    allowed, constraint = check_tool(effective_rules, t["name"])
                    if not allowed:
                        continue
                    if constraint is not None:
                        t = _apply_constraints_to_tool(t, constraint)
                    tools.append(t)

        # Plugin tools
        plugin_defs = plugin_registry.list_all_definitions()
        if plugin_defs:
            effective_rules = get_effective_rules(
                config, session.agent_id, PluginRegistry.VIRTUAL_SERVER_NAME
            )
            if effective_rules is not None:
                for t in plugin_defs:
                    allowed, constraint = check_tool(effective_rules, t["name"])
                    if not allowed:
                        continue
                    if constraint is not None:
                        t = _apply_constraints_to_tool(t, constraint)
                    tools.append(t)

        return tools

    # Build the low-level MCP server (used by both SSE and Streamable HTTP transports)
    mcp_server = build_mcp_server(proxy, collect_permitted_tools)

    # SSE transport
    sse_transport = SseServerTransport("/mcp-sse/messages/")

    # Streamable HTTP session manager
    session_manager = StreamableHTTPSessionManager(
        app=mcp_server,
        stateless=False,
        session_idle_timeout=1800,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await audit.start()
        if telegram_notifier is not None:
            await telegram_notifier.register_webhook(config.approval.base_url)
        async with session_manager.run():
            log.info("MCP wrapper started")
            yield
        await audit.stop()
        log.info("MCP wrapper stopped")

    app = FastAPI(title="MCP Security Wrapper", lifespan=lifespan)

    def get_session(request: Request) -> Session:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing bearer token",
            )
        token = auth[7:]
        session = identity.resolve(token)
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        return session

    def _resolve_session_from_header(auth_header: str) -> Session | None:
        if not auth_header.startswith("Bearer "):
            return None
        return identity.resolve(auth_header[7:])

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/mcp/tools/call")
    async def call_tool(
        body: ToolCallRequest,
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        has_reason = "_reason" in body.params
        try:
            result = await proxy.call_tool(session, body.tool, body.params)
            if not has_reason:
                result["_warning"] = "No _reason provided. Include a '_reason' field in your tool call arguments explaining why you are calling this tool."
            return JSONResponse(content=result)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/mcp/tools/list")
    async def list_tools(session: Session = Depends(get_session)) -> JSONResponse:
        """Return aggregated tool list from all sources the agent can reach."""
        tools = await collect_permitted_tools(session)
        await audit.log(
            AuditEvent(
                agent_id=session.agent_id,
                session_id=session.session_id,
                tool="tools/list",
                decision="allowed",
                response_status="success",
            )
        )
        return JSONResponse(content={"tools": tools})

    @app.get("/claude/tools")
    async def list_claude_tools(session: Session = Depends(get_session)) -> JSONResponse:
        """Return permitted tools in Anthropic tool_use JSON Schema format."""
        tools = await collect_permitted_tools(session)
        return JSONResponse(content={"tools": [_mcp_tool_to_claude_tool(t) for t in tools]})

    @app.post("/claude/tools/call")
    async def call_claude_tools(
        body: ClaudeToolCallRequest,
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        """Accept Anthropic tool_use blocks and return tool_result blocks.

        Tool uses are executed sequentially so approval gates on earlier calls
        complete before later calls are evaluated.
        """
        results: list[dict[str, Any]] = []
        for tool_use in body.tool_uses:
            try:
                result = await proxy.call_tool(session, tool_use.name, dict(tool_use.input))
                content = _mcp_result_to_claude_content(result)
                results.append(
                    ClaudeToolResultBlock(
                        tool_use_id=tool_use.id,
                        content=content,
                        is_error=False,
                    ).model_dump()
                )
            except PermissionError as e:
                results.append(
                    ClaudeToolResultBlock(
                        tool_use_id=tool_use.id,
                        content=str(e),
                        is_error=True,
                    ).model_dump()
                )
            except Exception as e:
                results.append(
                    ClaudeToolResultBlock(
                        tool_use_id=tool_use.id,
                        content=f"Internal error: {e}",
                        is_error=True,
                    ).model_dump()
                )
        return JSONResponse(content={"tool_results": results})

    @app.post("/approval/{approval_id}")
    async def resolve_approval(
        approval_id: str,
        body: ApprovalResolution,
    ) -> JSONResponse:
        ok = approvals.resolve(approval_id, body.approved, body.note)
        if not ok:
            raise HTTPException(status_code=404, detail="Unknown or expired approval request")
        return JSONResponse(content={"status": "approved" if body.approved else "denied"})

    @app.post("/slack/interact")
    async def slack_interact(request: Request) -> JSONResponse:
        if slack_notifier is None:
            raise HTTPException(status_code=404, detail="Slack not configured")
        body = await request.body()
        timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
        signature = request.headers.get("X-Slack-Signature", "")
        if not slack_notifier.verify_signature(body, timestamp, signature):
            raise HTTPException(status_code=401, detail="Invalid Slack signature")
        import urllib.parse
        form_str = body.decode()
        parsed = urllib.parse.parse_qs(form_str)
        payload_json = parsed.get("payload", ["{}"])[0]
        import json as _json
        payload = _json.loads(payload_json)
        await slack_notifier.handle_interact(payload, approvals)
        return JSONResponse(content={})

    @app.post("/telegram/webhook")
    async def telegram_webhook(request: Request) -> JSONResponse:
        if telegram_notifier is None:
            raise HTTPException(status_code=404, detail="Telegram not configured")
        secret_token = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
        if not telegram_notifier.verify_secret_token(secret_token):
            raise HTTPException(status_code=401, detail="Invalid Telegram secret token")
        update = await request.json()
        await telegram_notifier.handle_update(update, approvals)
        return JSONResponse(content={})

    @app.get("/audit/recent")
    async def recent_logs(
        limit: int = 50,
        tool: str | None = None,
        mcp_server: str | None = None,
        decision: str | None = None,
        since: str | None = None,
        until: str | None = None,
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        """Return filtered audit log entries for the authenticated agent.

        Query params:
          limit       — max entries (default 50)
          tool        — exact name or glob (e.g. Hass*)
          mcp_server  — filter by server name
          decision    — allowed | denied | error
          since       — ISO timestamp lower bound (inclusive)
          until       — ISO timestamp upper bound (inclusive)
        """
        entries = await audit.query_entries(
            agent_id=session.agent_id,
            limit=limit,
            tool=tool,
            mcp_server=mcp_server,
            decision=decision,
            since=since,
            until=until,
        )
        return JSONResponse(content={"entries": entries})

    @app.get("/audit/stats")
    async def audit_stats(
        since: str | None = None,
        until: str | None = None,
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        """Return summary statistics for the authenticated agent.

        Query params:
          since  — ISO timestamp lower bound (inclusive)
          until  — ISO timestamp upper bound (inclusive)
        """
        stats = await audit.query_stats(
            agent_id=session.agent_id,
            since=since,
            until=until,
        )
        return JSONResponse(content=stats)

    # -------------------------------------------------------------------------
    # MCP protocol transports
    # -------------------------------------------------------------------------

    async def _sse_endpoint(request: StarletteRequest) -> Response:
        """SSE connection endpoint for the MCP protocol."""
        session = _resolve_session_from_header(request.headers.get("Authorization", ""))
        if session is None:
            return Response("Unauthorized", status_code=401)
        token = current_session.set(session)
        try:
            async with sse_transport.connect_sse(
                request.scope, request.receive, request._send  # type: ignore[attr-defined]
            ) as streams:
                await mcp_server.run(
                    streams[0],
                    streams[1],
                    mcp_server.create_initialization_options(),
                )
        finally:
            current_session.reset(token)
        return Response()

    sse_starlette = Starlette(
        routes=[
            Route("/sse", endpoint=_sse_endpoint, methods=["GET"]),
            Mount("/messages/", app=sse_transport.handle_post_message),
        ]
    )
    app.mount("/mcp-sse", sse_starlette)

    async def _mcp_http_handler(scope: Any, receive: Any, send: Any) -> None:
        """Auth wrapper for the Streamable HTTP MCP endpoint."""
        req = StarletteRequest(scope, receive)
        session = _resolve_session_from_header(req.headers.get("Authorization", ""))
        if session is None:
            resp = Response("Unauthorized", status_code=401)
            await resp(scope, receive, send)
            return
        token = current_session.set(session)
        try:
            await session_manager.handle_request(scope, receive, send)
        finally:
            current_session.reset(token)

    app.add_route("/mcp", _mcp_http_handler, methods=["GET", "POST", "DELETE"])

    return app
