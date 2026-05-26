from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any

import httpx

from .anomaly import AnomalyDetector
from .approvals import ApprovalManager
from .dlp import DlpScanner
from .credentials import CredentialBroker
from .gateway import GatewayRegistry
from .identity import IdentityResolver
from .limiter import RateLimiter
from .logger import AuditLogger
from .mcp_client import mcp_request
from .models import AuditEvent, McpServerConfig, Session, WrapperConfig
from .native_tools import NativeToolRegistry
from .plugin_tools import PluginRegistry
from .response import apply_grep_to_content, apply_jq_to_content, shape_response
from .rules import check_tool, get_effective_rules, validate_params
from .workflow import WorkflowRegistry


@dataclass
class _DownstreamTarget:
    server_name: str
    server_cfg: McpServerConfig
    native_tool_name: str  # original tool name with prefix stripped


@dataclass
class _NativeTarget:
    tool_name: str


@dataclass
class _PluginTarget:
    tool_name: str


@dataclass
class _GatewayTarget:
    tool_name: str


@dataclass
class _MetaTarget:
    tool_name: str  # "search_tools" or "call_tool"


@dataclass
class _WorkflowTarget:
    tool_name: str


VIRTUAL_SERVER_META = "__meta__"

_SEARCH_TOOLS_DEF: dict[str, Any] = {
    "name": "search_tools",
    "description": (
        "Search available tools by name or description. "
        "Use this to discover tool names and their required arguments "
        "before calling them — avoids needing the full tool list in context."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search term matched against tool names and descriptions"},
            "limit": {"type": "integer", "description": "Max results (default 10)"},
        },
        "required": ["query"],
    },
}

_CALL_TOOL_DEF: dict[str, Any] = {
    "name": "call_tool",
    "description": (
        "Call any available tool by name. "
        "Use search_tools first to discover the tool name and its expected arguments."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Tool name (from search_tools results)"},
            "arguments": {"type": "object", "description": "Tool arguments as an object", "additionalProperties": True},
        },
        "required": ["name", "arguments"],
    },
}

_META_TOOLS = {"search_tools": _SEARCH_TOOLS_DEF, "call_tool": _CALL_TOOL_DEF}

log = logging.getLogger(__name__)


class ToolDeniedError(Exception):
    """Raised when a tool call is denied by policy.

    ``user_message`` is a short, safe string suitable for returning to agents.
    The full denial reason (with server/rule details) is only written to logs
    and the audit record.
    """

    def __init__(self, user_message: str) -> None:
        super().__init__(user_message)
        self.user_message = user_message


class McpProxy:
    """Forwards MCP tool calls to downstream servers, logging every request."""

    def __init__(
        self,
        config: WrapperConfig,
        identity: IdentityResolver,
        audit: AuditLogger,
        credentials: CredentialBroker,
        limiter: RateLimiter,
        approvals: ApprovalManager,
        anomaly: AnomalyDetector | None = None,
        dlp: DlpScanner | None = None,
        native_registry: NativeToolRegistry | None = None,
        plugin_registry: PluginRegistry | None = None,
        gateway_registry: GatewayRegistry | None = None,
        workflow_registry: WorkflowRegistry | None = None,
    ):
        self._config = config
        self._identity = identity
        self._audit = audit
        self._credentials = credentials
        self._limiter = limiter
        self._approvals = approvals
        self._anomaly = anomaly
        self._dlp = dlp
        self._native = native_registry
        self._plugins = plugin_registry
        self._gateway = gateway_registry
        self._workflows = workflow_registry
        self._tool_lister: Any = None  # set after init via set_tool_lister()

    def set_tool_lister(self, fn: Any) -> None:
        """Register the async (session) -> (list[dict], int) callback used by search_tools."""
        self._tool_lister = fn

    def _effective_prefix(self, server_name: str) -> str:
        cfg = self._config.mcp_servers.get(server_name)
        raw = (cfg.tool_prefix if cfg and cfg.tool_prefix else server_name)
        return raw.lower()

    def _resolve_target(
        self, tool_name: str, agent_id: str, agent_config
    ) -> _DownstreamTarget | _NativeTarget | _PluginTarget | _GatewayTarget | _MetaTarget | _WorkflowTarget | None:
        if tool_name in _META_TOOLS:
            return _MetaTarget(tool_name=tool_name)
        if self._native and self._native.has_tool(tool_name):
            return _NativeTarget(tool_name=tool_name)
        if self._plugins and self._plugins.has_tool(tool_name):
            return _PluginTarget(tool_name=tool_name)
        if self._gateway and self._gateway.has_tool(tool_name):
            return _GatewayTarget(tool_name=tool_name)
        if self._workflows and self._workflows.has_tool(tool_name):
            return _WorkflowTarget(tool_name=tool_name)
        result = self._server_for_tool(tool_name, agent_id, agent_config)
        if result:
            server_name, native_name, server_cfg = result
            return _DownstreamTarget(server_name=server_name, server_cfg=server_cfg, native_tool_name=native_name)
        return None

    def _server_for_tool(self, tool_name: str, agent_id: str, agent_config) -> tuple[str, str, Any] | None:
        """Return (server_name, native_tool_name, server_cfg) for the given tool.

        native_tool_name is tool_name with the server prefix stripped, which is
        what gets forwarded to the downstream MCP server.
        """
        tool_lower = tool_name.lower()
        # Prefix-based match: agent sent "prefix_nativetoolname"
        for server_name in agent_config.mcp_servers:
            prefix = self._effective_prefix(server_name)
            separator = f"{prefix}_"
            if tool_lower.startswith(separator):
                native = tool_name[len(separator):]
                server_cfg = self._config.mcp_servers.get(server_name)
                if server_cfg:
                    return server_name, native, server_cfg
        # Rules-based fallback: agent sent an unprefixed name (e.g. log_only, direct REST call)
        for server_name in agent_config.mcp_servers:
            server_cfg = self._config.mcp_servers.get(server_name)
            if not server_cfg:
                continue
            effective_rules = get_effective_rules(self._config, agent_id, server_name)
            if effective_rules is not None:
                allowed, _ = check_tool(effective_rules, tool_name)
                if allowed:
                    return server_name, tool_name, server_cfg
        # Last resort for log_only agents with no rules: first available server
        for server_name in agent_config.mcp_servers:
            server_cfg = self._config.mcp_servers.get(server_name)
            if server_cfg:
                return server_name, tool_name, server_cfg
        return None

    async def _deny(
        self,
        session: Session,
        server_name: str | None,
        tool_name: str,
        params: dict[str, Any],
        reason: str,
        call_reason: str | None = None,
        approval_id: str | None = None,
        approval_note: str | None = None,
        user_message: str | None = None,
    ) -> None:
        log.warning("denied: agent=%s server=%s tool=%s reason=%s", session.agent_id, server_name, tool_name, reason)
        event = AuditEvent(
            agent_id=session.agent_id,
            session_id=session.session_id,
            mcp_server=server_name,
            tool=tool_name,
            params=params,
            decision="denied",
            denial_reason=reason,
            response_status="denied",
            latency_ms=0,
            reason=call_reason,
            approval_id=approval_id,
            approval_note=approval_note,
            params_chars=len(json.dumps(params)),
            client_info=session.client_info,
        )
        await self._audit.log(event)
        if self._anomaly is not None:
            await self._anomaly.check(event)
        raise ToolDeniedError(user_message or reason)

    _MAX_CALL_DEPTH = 10

    async def call_tool(
        self, session: Session, tool_name: str, params: dict[str, Any],
        _context_depth: int = 0,
    ) -> dict[str, Any]:
        if _context_depth >= self._MAX_CALL_DEPTH:
            raise RuntimeError(
                f"call_tool depth limit ({self._MAX_CALL_DEPTH}) exceeded — "
                "possible recursive tool call"
            )
        agent_cfg = self._identity.get_agent_config(session.agent_id)
        if agent_cfg is None:
            raise ValueError(f"No config for agent {session.agent_id!r}")

        call_reason: str | None = params.pop("_reason", None)
        # DLP-scan _reason before storing — it's written to the audit log and readable
        # via GET /audit/recent, making it a covert exfiltration channel.
        # Any violation (block, redact, warn, approve) causes redaction: the _reason
        # field is a log sink, not a forwarded value, so partial redaction isn't useful.
        if call_reason and self._dlp is not None:
            scanned = self._dlp.scan_outbound({"_reason": call_reason})
            if scanned.violations:
                call_reason = "[REDACTED BY DLP]"
            else:
                call_reason = scanned.sanitized.get("_reason", call_reason)

        # DLP outbound scan — run BEFORE enforcement so that any denial (rule,
        # rate-limit, param) logs sanitized params rather than raw agent input.
        # Agents can read their own audit entries via GET /audit/recent, making
        # unsanitized params a covert exfiltration channel.
        _dlp_violations: list[str] = []
        if self._dlp is not None:
            outbound = self._dlp.scan_outbound(params)
            if outbound.blocked:
                blocked_names = [v.pattern_name for v in outbound.violations if v.action == "block"]
                params = outbound.sanitized
                target = self._resolve_target(tool_name, session.agent_id, agent_cfg)
                server_name_early = (
                    NativeToolRegistry.VIRTUAL_SERVER_NAME if isinstance(target, _NativeTarget)
                    else PluginRegistry.VIRTUAL_SERVER_NAME if isinstance(target, _PluginTarget)
                    else GatewayRegistry.VIRTUAL_SERVER_NAME if isinstance(target, _GatewayTarget)
                    else WorkflowRegistry.VIRTUAL_SERVER_NAME if isinstance(target, _WorkflowTarget)
                    else VIRTUAL_SERVER_META if isinstance(target, _MetaTarget)
                    else target.server_name if isinstance(target, _DownstreamTarget)
                    else None
                )
                await self._deny(
                    session, server_name_early, tool_name, params,
                    f"DLP: sensitive data in params ({', '.join(blocked_names)})",
                    call_reason,
                    user_message=f"Denied by DLP rule: {', '.join(blocked_names)}",
                )
            if outbound.needs_approval:
                approve_names = [v.pattern_name for v in outbound.violations if v.action == "approve"]
                approved, approval_id_early, approval_note_early = await self._approvals.request(
                    agent_id=session.agent_id,
                    tool=tool_name,
                    params=outbound.sanitized,
                    reason=f"DLP outbound: {', '.join(approve_names)} detected in params",
                )
                if not approved:
                    params = outbound.sanitized
                    target = self._resolve_target(tool_name, session.agent_id, agent_cfg)
                    server_name_early = (
                        NativeToolRegistry.VIRTUAL_SERVER_NAME if isinstance(target, _NativeTarget)
                        else PluginRegistry.VIRTUAL_SERVER_NAME if isinstance(target, _PluginTarget)
                        else GatewayRegistry.VIRTUAL_SERVER_NAME if isinstance(target, _GatewayTarget)
                        else WorkflowRegistry.VIRTUAL_SERVER_NAME if isinstance(target, _WorkflowTarget)
                        else target.server_name if isinstance(target, _DownstreamTarget)
                        else None
                    )
                    await self._deny(
                        session, server_name_early, tool_name, params,
                        f"DLP outbound approval denied ({', '.join(approve_names)}): {approval_note_early or 'request denied'}",
                        call_reason, approval_id=approval_id_early, approval_note=approval_note_early,
                        user_message=f"Denied: DLP approval not granted ({', '.join(approve_names)})",
                    )
            warn_names = [v.pattern_name for v in outbound.violations if v.action == "warn"]
            if warn_names:
                log.warning("DLP warn (outbound): agent=%s tool=%s patterns=%s", session.agent_id, tool_name, warn_names)
                _dlp_violations.extend(f"warn:{n}" for n in warn_names)
            params = outbound.sanitized

        start = time.monotonic()
        response_status = "error"
        credential_accessed = None
        approval_id: str | None = None
        approval_note: str | None = None

        target = self._resolve_target(tool_name, session.agent_id, agent_cfg)
        if isinstance(target, _NativeTarget):
            server_name: str | None = NativeToolRegistry.VIRTUAL_SERVER_NAME
            native_tool_name = tool_name
        elif isinstance(target, _PluginTarget):
            server_name = PluginRegistry.VIRTUAL_SERVER_NAME
            native_tool_name = tool_name
        elif isinstance(target, _GatewayTarget):
            server_name = GatewayRegistry.VIRTUAL_SERVER_NAME
            native_tool_name = tool_name
        elif isinstance(target, _WorkflowTarget):
            server_name = WorkflowRegistry.VIRTUAL_SERVER_NAME
            native_tool_name = tool_name
        elif isinstance(target, _MetaTarget):
            server_name = VIRTUAL_SERVER_META
            native_tool_name = tool_name
        elif isinstance(target, _DownstreamTarget):
            server_name = target.server_name
            native_tool_name = target.native_tool_name
        else:
            server_name = None
            native_tool_name = tool_name

        constraint = None

        # Native, plugin, gateway, workflow, and meta tools execute real code/HTTP with operator
        # credentials, so always enforce rules even when the agent is log_only (Finding 4).
        if not agent_cfg.log_only or isinstance(target, (_NativeTarget, _PluginTarget, _GatewayTarget, _WorkflowTarget, _MetaTarget)):
            if target is None:
                await self._deny(session, None, tool_name, params, f"no server or native tool found for {tool_name!r}", call_reason,
                                 user_message="Denied: tool not found")

            effective_rules = get_effective_rules(self._config, session.agent_id, server_name)  # type: ignore[arg-type]
            if effective_rules is None:
                await self._deny(session, server_name, tool_name, params, f"no rules configured for server {server_name!r}", call_reason,
                                 user_message="Denied: access not configured")

            allowed, constraint = check_tool(effective_rules, native_tool_name)  # type: ignore[arg-type]
            if not allowed:
                await self._deny(session, server_name, tool_name, params, f"tool {tool_name!r} not in ruleset for {server_name!r}", call_reason,
                                 user_message="Denied: tool not in allowed list")

            if constraint is not None:
                if constraint.rate_limit is not None:
                    if not self._limiter.check(session.agent_id, native_tool_name, constraint.rate_limit):
                        await self._deny(session, server_name, tool_name, params, f"rate limit exceeded for tool {tool_name!r}", call_reason,
                                         user_message="Denied: rate limit exceeded")

                param_denial = validate_params(params, constraint)
                if param_denial is not None:
                    await self._deny(session, server_name, tool_name, params, param_denial, call_reason,
                                     user_message=f"Denied: {param_denial}")

                if constraint.require_approval:
                    try:
                        approved, approval_id, approval_note = await self._approvals.request(
                            agent_id=session.agent_id,
                            tool=tool_name,
                            params=params,
                            reason=call_reason,
                        )
                    except asyncio.CancelledError:
                        _ce = AuditEvent(
                            agent_id=session.agent_id,
                            session_id=session.session_id,
                            mcp_server=server_name,
                            tool=tool_name,
                            params=params,
                            decision="allowed",
                            response_status="cancelled",
                            latency_ms=int((time.monotonic() - start) * 1000),
                            reason=call_reason,
                            params_chars=len(json.dumps(params)),
                            client_info=session.client_info,
                        )
                        await asyncio.shield(self._audit.log(_ce))
                        raise
                    if not approved:
                        await self._deny(
                            session, server_name, tool_name, params,
                            f"approval denied: {approval_note or 'request denied'}",
                            call_reason, approval_id=approval_id, approval_note=approval_note,
                            user_message="Denied: approval not granted",
                        )

        params_chars = len(json.dumps(params))
        result: dict[str, Any] | None = None
        audit_event: AuditEvent | None = None
        _error_text: str | None = None
        _audit_id: int | None = None
        _raw_response_chars: int | None = None

        try:
            if target is None:
                raise ValueError(f"No server or native tool found for {tool_name!r}")

            if isinstance(target, _NativeTarget):
                result = await self._native.execute(tool_name, params)  # type: ignore[union-attr]
                if self._native and self._native._configs[tool_name].credential:
                    credential_accessed = f"native:{tool_name}"
                response_status = "success"
            elif isinstance(target, _PluginTarget):
                result = await self._plugins.execute(tool_name, params, agent_id=session.agent_id)  # type: ignore[union-attr]
                response_status = "success"
            elif isinstance(target, _GatewayTarget):
                result = await self._gateway.execute(tool_name, params, agent_id=session.agent_id)  # type: ignore[union-attr]
                response_status = "success"
            elif isinstance(target, _WorkflowTarget):
                async def _tool_caller(name: str, wf_params: dict[str, Any]) -> dict[str, Any]:
                    return await self.call_tool(session, name, wf_params, _context_depth=_context_depth + 1)
                result = await self._workflows.execute(  # type: ignore[union-attr]
                    tool_name, params, agent_id=session.agent_id, tool_caller=_tool_caller
                )
                response_status = "success"
            elif isinstance(target, _MetaTarget):
                if tool_name == "search_tools":
                    result = await self._exec_search_tools(session, params)
                else:  # call_tool
                    inner_name = str(params.get("name", ""))
                    inner_args = dict(params.get("arguments") or {})
                    if not inner_name:
                        raise ValueError("call_tool requires a non-empty 'name' parameter")
                    result = await self.call_tool(
                        session, inner_name, inner_args,
                        _context_depth=_context_depth + 1,
                    )
                response_status = "success"
            else:
                token = await self._credentials.get_token(target.server_name)
                if token:
                    credential_accessed = target.server_name

                data = await mcp_request(
                    target.server_cfg.url,
                    token,
                    target.server_cfg.transport,
                    "tools/call",
                    {"name": native_tool_name, "arguments": params},
                    timeout=30.0,
                )
                if "error" in data:
                    raise RuntimeError(f"MCP error: {data['error']}")
                result = data.get("result", data)
                shaped = shape_response(result, target.server_cfg.response_fields, target.server_cfg.max_response_chars)
                result = shaped if isinstance(shaped, dict) else {"content": [{"type": "text", "text": shaped}]}
                if constraint is not None and (constraint.response_jq or constraint.response_grep):
                    _raw_response_chars = len(json.dumps(result))
                    if constraint.response_jq:
                        result = apply_jq_to_content(result, constraint.response_jq)
                    if constraint.response_grep:
                        result = apply_grep_to_content(result, constraint.response_grep)
                response_status = "success"

            # DLP inbound scan — sanitize response before it reaches the agent.
            if self._dlp is not None:
                inbound = self._dlp.scan_inbound(result)
                result = inbound.sanitized
                if inbound.blocked:
                    blocked_inbound = [v.pattern_name for v in inbound.violations if v.action == "block"]
                    raise ToolDeniedError(f"Denied by DLP rule (inbound): {', '.join(blocked_inbound)}")
                if inbound.needs_approval:
                    approve_names = [v.pattern_name for v in inbound.violations if v.action == "approve"]
                    approved, approval_id, approval_note = await self._approvals.request(
                        agent_id=session.agent_id,
                        tool=tool_name,
                        params={"_dlp_inbound_patterns": approve_names},
                        reason=f"DLP inbound: {', '.join(approve_names)} detected in response",
                    )
                    if not approved:
                        raise ToolDeniedError(
                            f"Denied: DLP inbound approval not granted ({', '.join(approve_names)})"
                        )
                warn_inbound = [v.pattern_name for v in inbound.violations if v.action == "warn"]
                if warn_inbound:
                    log.warning("DLP warn (inbound): agent=%s tool=%s patterns=%s", session.agent_id, tool_name, warn_inbound)
                    _dlp_violations.extend(f"warn_inbound:{n}" for n in warn_inbound)
                    result.setdefault("_security_warnings", []).extend(
                        f"response flagged by DLP pattern: {n}" for n in warn_inbound
                    )
                redacted_inbound = [v.pattern_name for v in inbound.violations if v.action == "redact"]
                if redacted_inbound:
                    _dlp_violations.extend(f"redact_inbound:{n}" for n in redacted_inbound)
                    result.setdefault("_security_warnings", []).extend(
                        f"content redacted by DLP pattern: {n}" for n in redacted_inbound
                    )

        except asyncio.CancelledError:
            response_status = "cancelled"
            raise
        except Exception as e:
            log.error("Tool call failed: tool=%s params=%s error=%s", tool_name, json.dumps(params), e)
            response_status = "error"
            _error_text = str(e)
            raise
        finally:
            latency_ms = int((time.monotonic() - start) * 1000)
            response_chars = len(json.dumps(result)) if result is not None else None
            audit_event = AuditEvent(
                agent_id=session.agent_id,
                session_id=session.session_id,
                mcp_server=server_name,
                tool=tool_name,
                params=params,
                decision="allowed",
                credential_accessed=credential_accessed,
                response_status=response_status,
                latency_ms=latency_ms,
                reason=call_reason,
                approval_id=approval_id,
                approval_note=approval_note,
                params_chars=params_chars,
                response_chars=response_chars,
                raw_response_chars=_raw_response_chars,
                response=_error_text,
                dlp_violations=_dlp_violations or None,
                client_info=session.client_info,
            )
            # asyncio.shield ensures the DB write completes even if the MCP
            # framework cancels this task (e.g. client disconnect / timeout).
            try:
                _audit_id = await asyncio.shield(self._audit.log(audit_event))
            except asyncio.CancelledError:
                _audit_id = None
                raise

        # Only reached on success (exceptions are re-raised above)
        if self._anomaly is not None and result is not None:
            anomalies = await self._anomaly.check(audit_event)  # type: ignore[arg-type]
            if anomalies:
                result["_anomalies"] = anomalies
                if _audit_id is not None:
                    await self._audit.update_result(
                        _audit_id,
                        response=json.dumps(result),
                        anomalies=anomalies,
                    )
        return result  # type: ignore[return-value]

    async def _exec_search_tools(self, session: Session, params: dict[str, Any]) -> dict[str, Any]:
        query = str(params.get("query", "")).lower().strip()
        limit = min(int(params.get("limit") or 10), 50)
        results: list[dict[str, Any]] = []

        if self._tool_lister is not None:
            all_tools, _ = await self._tool_lister(session)
        else:
            all_tools = []

        for tool in all_tools:
            name: str = tool.get("name", "")
            desc: str = tool.get("description", "")
            if not query or query in name.lower() or query in desc.lower():
                required = tool.get("inputSchema", {}).get("required", [])
                props = tool.get("inputSchema", {}).get("properties", {})
                results.append({
                    "name": name,
                    "description": desc[:120] if desc else "",
                    "required": required,
                    "optional": [k for k in props if k not in required],
                })
            if len(results) >= limit:
                break

        if not results:
            text = f"No tools found matching '{query}'." if query else "No tools available."
        else:
            text = json.dumps(results, indent=2)
        return {"content": [{"type": "text", "text": text}]}
