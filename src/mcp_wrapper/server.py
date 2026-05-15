from __future__ import annotations

"""Streamable HTTP MCP wrapper server.

Presents a standard MCP endpoint. Agents authenticate via:
    Authorization: Bearer <token>

Tool listing and calls are filtered and enforced against the agent's
rules. log_only = true bypasses enforcement for observation mode.
"""

import copy
import json
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
from .credentials import CredentialBroker, OAuthTokenManager, OAuthTokenStore, SecretResolver, VaultClient
from .gateway import GatewayRegistry
from .mcp_client import mcp_request
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


def _build_client_info(headers: Any) -> str | None:
    """Extract a compact client identifier from request headers."""
    name = (headers.get("X-Client-Name") or "").strip()
    version = (headers.get("X-Client-Version") or "").strip()
    if name:
        return f"{name}/{version}" if version else name
    ua = (headers.get("User-Agent") or "").strip()
    return ua[:200] if ua else None
from .rules import check_tool, get_effective_rules

log = logging.getLogger(__name__)


class ToolCallRequest(BaseModel):
    tool: str
    params: dict[str, Any] = {}


class GatewayCallRequest(BaseModel):
    name: str
    arguments: dict[str, Any] = {}


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


def build_app(config: WrapperConfig, config_dir: str = "config") -> FastAPI:
    resolver = build_resolver(config)
    audit = AuditLogger(
        db_path=config.logging.db_path,
        jsonl_path=config.logging.jsonl_path,
    )
    identity = IdentityResolver(config, resolver)
    oauth_store = OAuthTokenStore(f"{config_dir}/oauth-tokens.json")
    oauth_manager = OAuthTokenManager(config.mcp_servers, resolver, oauth_store)
    credentials = CredentialBroker(config.mcp_servers, resolver, oauth_manager)
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
    gateway_registry = GatewayRegistry(config.gateway_tools)
    proxy = McpProxy(
        config, identity, audit, credentials, limiter, approvals, anomaly, dlp,
        native_registry=native_registry,
        plugin_registry=plugin_registry,
        gateway_registry=gateway_registry,
    )

    async def collect_permitted_tools(session: Session) -> tuple[list[dict[str, Any]], int]:
        """Aggregate and filter the tool list for a session across all sources.

        Returns (filtered_tools, raw_chars) where raw_chars is the total JSON size
        of all tools before any rules filtering — useful for auditing token savings.
        """
        agent_cfg = identity.get_agent_config(session.agent_id)
        if agent_cfg is None:
            return [], 0

        tools: list[dict[str, Any]] = []
        seen_prefixed: dict[str, str] = {}  # prefixed_name -> server_name, for collision detection
        raw_chars = 0

        for server_name in agent_cfg.mcp_servers:
            server_cfg = config.mcp_servers.get(server_name)
            if server_cfg is None:
                continue
            prefix = (server_cfg.tool_prefix or server_name).lower()
            token = await credentials.get_token(server_name)
            try:
                data = await mcp_request(
                    server_cfg.url, token, server_cfg.transport, "tools/list", timeout=10.0
                )
                server_tools: list[dict[str, Any]] = data.get("result", {}).get("tools", [])
                raw_chars += len(json.dumps(server_tools))
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
                prefixed: list[dict[str, Any]] = []
                for t in server_tools:
                    prefixed_name = f"{prefix}_{t['name']}"
                    if prefixed_name in seen_prefixed:
                        log.warning(
                            "Tool name collision: '%s' from '%s' conflicts with '%s' — skipping",
                            prefixed_name, server_name, seen_prefixed[prefixed_name],
                        )
                        continue
                    seen_prefixed[prefixed_name] = server_name
                    t = copy.deepcopy(t)
                    t["name"] = prefixed_name
                    prefixed.append(t)
                tools.extend(prefixed)
            except Exception as e:
                log.warning("Could not fetch tools from %s: %s", server_name, e)

        # Native tools
        native_defs = native_registry.list_all_definitions()
        if native_defs:
            raw_chars += len(json.dumps(native_defs))
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
            raw_chars += len(json.dumps(plugin_defs))
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

        return tools, raw_chars

    async def _hot_reload() -> None:
        """Re-parse config files and update all live components in-place."""
        from .config import load_config as _load_config
        new_cfg = _load_config(config_dir)
        # Update dict fields in-place so all closures see the new values immediately.
        # NativeToolRegistry._configs is already this same dict object, so it auto-updates.
        config.mcp_servers.clear()
        config.mcp_servers.update(new_cfg.mcp_servers)
        config.agents.clear()
        config.agents.update(new_cfg.agents)
        config.server_rules.clear()
        config.server_rules.update(new_cfg.server_rules)
        config.agent_overrides.clear()
        config.agent_overrides.update(new_cfg.agent_overrides)
        config.native_tools.clear()
        config.native_tools.update(new_cfg.native_tools)
        config.plugin_tools.clear()
        config.plugin_tools.update(new_cfg.plugin_tools)
        config.gateway_tools.clear()
        config.gateway_tools.update(new_cfg.gateway_tools)
        identity.reload(new_cfg, resolver)
        plugin_registry.reload(new_cfg.plugin_tools)
        gateway_registry.reload(new_cfg.gateway_tools)
        log.info("Config hot-reloaded")

    # Build the low-level MCP server (used by both SSE and Streamable HTTP transports)
    mcp_server = build_mcp_server(proxy, collect_permitted_tools, audit)

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

    async def get_session(request: Request) -> Session:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing bearer token",
            )
        token = auth[7:]
        session = identity.resolve(token, _build_client_info(request.headers))
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        log.info("rest_request: agent=%s client_info=%r", session.agent_id, session.client_info)
        fp_anomalies = await anomaly.check_fingerprint(session)
        if fp_anomalies:
            # Persist this fingerprint so seeding works correctly after a restart.
            await audit.log(AuditEvent(
                agent_id=session.agent_id,
                session_id=session.session_id,
                decision="session_start",
                response_status="rest",
                client_info=session.client_info,
            ))
            agent_cfg = identity.get_agent_config(session.agent_id)
            action = agent_cfg.shared_key_action if agent_cfg else "warn"
            if action == "allow":
                pass  # Silently accept — fingerprint already tracked in memory
            else:
                await audit.log(AuditEvent(
                    agent_id=session.agent_id,
                    session_id=session.session_id,
                    decision="shared_key_detected",
                    denial_reason=fp_anomalies[0],
                    anomalies=fp_anomalies,
                    client_info=session.client_info,
                ))
                if action == "notify":
                    try:
                        await composite_notifier.send_alert(
                            title="Shared key detected",
                            message=(
                                f"*Agent:* {session.agent_id}\n"
                                f"*Client:* {session.client_info or 'unknown'}\n"
                                f"*Detail:* {fp_anomalies[0]}"
                            ),
                        )
                    except Exception as exc:
                        log.error("send_alert failed for shared_key_detected: %s", exc)
                if action == "block":
                    raise HTTPException(status_code=403, detail="Forbidden: shared key detected")
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
        tools, raw_chars = await collect_permitted_tools(session)
        await audit.log(
            AuditEvent(
                agent_id=session.agent_id,
                session_id=session.session_id,
                tool="tools/list",
                decision="allowed",
                response_status="success",
                response_chars=len(json.dumps(tools)),
                raw_response_chars=raw_chars or None,
            )
        )
        return JSONResponse(content={"tools": tools})

    @app.get("/claude/tools")
    async def list_claude_tools(session: Session = Depends(get_session)) -> JSONResponse:
        """Return permitted tools in Anthropic tool_use JSON Schema format."""
        tools, _ = await collect_permitted_tools(session)
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

    # -------------------------------------------------------------------------
    # Gateway API — framework-agnostic, OpenAI function-calling format
    # -------------------------------------------------------------------------

    @app.get("/gateway/tools")
    async def gateway_list_tools(session: Session = Depends(get_session)) -> JSONResponse:
        """List gateway tools in OpenAI function-calling format, filtered by agent rules."""
        agent_cfg = identity.get_agent_config(session.agent_id)
        tools: list[dict[str, Any]] = []
        if agent_cfg is None:
            return JSONResponse(content={"tools": tools})

        effective_rules = get_effective_rules(config, session.agent_id, GatewayRegistry.VIRTUAL_SERVER_NAME)
        raw_defs = gateway_registry.list_all_definitions()
        raw_chars = len(json.dumps(raw_defs))

        for defn in raw_defs:
            if effective_rules is not None and not agent_cfg.log_only:
                allowed, constraint = check_tool(effective_rules, defn["name"])
                if not allowed:
                    continue
                if constraint is not None:
                    defn = _apply_constraints_to_tool(defn, constraint)
            tools.append({
                "type": "function",
                "function": {
                    "name": defn["name"],
                    "description": defn.get("description", ""),
                    "parameters": defn.get("inputSchema", {"type": "object", "properties": {}}),
                },
            })

        filtered_chars = len(json.dumps(tools))
        await audit.log(AuditEvent(
            agent_id=session.agent_id,
            session_id=session.session_id,
            tool="gateway/tools",
            decision="allowed",
            response_status="success",
            response_chars=filtered_chars,
            raw_response_chars=raw_chars if raw_chars != filtered_chars else None,
        ))
        return JSONResponse(content={"tools": tools})

    @app.post("/gateway/call")
    async def gateway_call_tool(
        body: GatewayCallRequest,
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        """Execute a gateway tool call through the full governance stack."""
        try:
            result = await proxy.call_tool(session, body.name, dict(body.arguments))
            content = result.get("content", [])
            if isinstance(content, list) and content:
                first = content[0]
                text = first.get("text", str(first)) if isinstance(first, dict) else str(first)
            else:
                text = str(result)
            return JSONResponse(content={"content": text, "error": False})
        except PermissionError as e:
            return JSONResponse(
                content={"content": str(e), "error": True},
                status_code=403,
            )
        except Exception as e:
            return JSONResponse(
                content={"content": f"Error: {e}", "error": True},
                status_code=500,
            )

    @app.post("/gateway/calls")
    async def gateway_call_tools_batch(
        request: Request,
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        """Execute multiple gateway tool calls sequentially."""
        body = await request.json()
        calls = body.get("calls", [])
        results = []
        for call in calls:
            name = call.get("name", "")
            arguments = call.get("arguments", {})
            try:
                result = await proxy.call_tool(session, name, dict(arguments))
                content = result.get("content", [])
                if isinstance(content, list) and content:
                    first = content[0]
                    text = first.get("text", str(first)) if isinstance(first, dict) else str(first)
                else:
                    text = str(result)
                results.append({"name": name, "content": text, "error": False})
            except PermissionError as e:
                results.append({"name": name, "content": str(e), "error": True})
            except Exception as e:
                results.append({"name": name, "content": f"Error: {e}", "error": True})
        return JSONResponse(content={"results": results})

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

    async def _on_session_start(session: Session) -> bool:
        """Log session_start, check for shared-key use. Returns False if session is blocked."""
        log.info("session_start: agent=%s client_info=%r", session.agent_id, session.client_info)
        # Fingerprint check must happen BEFORE logging session_start. The check
        # seeds known fingerprints by querying session_start rows from the DB, so
        # logging first would include the current session in its own baseline and
        # the mismatch would never be detected.
        fp_anomalies = await anomaly.check_fingerprint(session)
        await audit.log(AuditEvent(
            agent_id=session.agent_id,
            session_id=session.session_id,
            decision="session_start",
            response_status="connected",
            client_info=session.client_info,
        ))
        if not fp_anomalies:
            return True

        agent_cfg = identity.get_agent_config(session.agent_id)
        action = agent_cfg.shared_key_action if agent_cfg else "warn"

        if action == "allow":
            return True

        # warn / block / notify all record the event
        await audit.log(AuditEvent(
            agent_id=session.agent_id,
            session_id=session.session_id,
            decision="shared_key_detected",
            denial_reason=fp_anomalies[0],
            anomalies=fp_anomalies,
            client_info=session.client_info,
        ))

        if action == "notify":
            try:
                await composite_notifier.send_alert(
                    title="Shared key detected",
                    message=(
                        f"*Agent:* {session.agent_id}\n"
                        f"*Client:* {session.client_info or 'unknown'}\n"
                        f"*Detail:* {fp_anomalies[0]}"
                    ),
                )
            except Exception as exc:
                log.error("send_alert failed for shared_key_detected: %s", exc)
            return True

        if action == "block":
            return False

        return True  # "warn" — event logged, session allowed

    async def _sse_endpoint(request: StarletteRequest) -> Response:
        """SSE connection endpoint for the MCP protocol."""
        auth = request.headers.get("Authorization", "")
        base_session = _resolve_session_from_header(auth)
        if base_session is None:
            return Response("Unauthorized", status_code=401)
        session = Session(
            agent_id=base_session.agent_id,
            client_info=_build_client_info(request.headers),
        )
        if not await _on_session_start(session):
            return Response("Forbidden: shared key detected", status_code=403)
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

    class _SentResponse(Response):
        """No-op response — session_manager already sent the full HTTP response."""
        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            pass

    async def _mcp_http_endpoint(request: StarletteRequest) -> Response:
        """Auth wrapper for the Streamable HTTP MCP endpoint."""
        base_session = _resolve_session_from_header(request.headers.get("Authorization", ""))
        if base_session is None:
            return Response("Unauthorized", status_code=401)
        session = Session(
            agent_id=base_session.agent_id,
            client_info=_build_client_info(request.headers),
        )
        if not request.headers.get("mcp-session-id"):
            if not await _on_session_start(session):
                return Response("Forbidden: shared key detected", status_code=403)
        token = current_session.set(session)
        try:
            await session_manager.handle_request(request.scope, request.receive, request._send)  # type: ignore[attr-defined]
        finally:
            current_session.reset(token)
        return _SentResponse()

    app.add_route("/mcp", _mcp_http_endpoint, methods=["GET", "POST", "DELETE"])

    # ------------------------------------------------------------------
    # Admin UI
    # ------------------------------------------------------------------
    if config.admin.enabled:
        from pathlib import Path
        from fastapi.responses import RedirectResponse as _RR
        from fastapi.staticfiles import StaticFiles
        from fastapi.templating import Jinja2Templates

        from .admin_auth import AdminAuthRequired, AdminSessionStore
        from .config_writer import ConfigWriter
        from . import admin as _admin_module

        _session_store = AdminSessionStore(config.admin.session_timeout_hours)
        _templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

        _static_dir = Path(__file__).parent / "static"
        app.mount(
            "/admin/static",
            StaticFiles(directory=str(_static_dir)),
            name="admin-static",
        )

        _admin_router = _admin_module.create_admin_router(
            config=config,
            config_dir=config_dir,
            session_store=_session_store,
            audit=audit,
            templates=_templates,
            credentials=credentials,
            oauth_manager=oauth_manager,
            reload_config=_hot_reload,
        )
        app.include_router(_admin_router, prefix="/admin")

        @app.exception_handler(AdminAuthRequired)
        async def _admin_auth_redirect(request: Request, exc: AdminAuthRequired):
            return _RR("/admin/login", status_code=302)

    return app
