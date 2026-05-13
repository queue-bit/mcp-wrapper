from __future__ import annotations

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
from .identity import IdentityResolver
from .limiter import RateLimiter
from .logger import AuditLogger
from .models import AuditEvent, McpServerConfig, Session, WrapperConfig
from .native_tools import NativeToolRegistry
from .plugin_tools import PluginRegistry
from .response import shape_response
from .rules import check_tool, get_effective_rules, validate_params


@dataclass
class _DownstreamTarget:
    server_name: str
    server_cfg: McpServerConfig


@dataclass
class _NativeTarget:
    tool_name: str


@dataclass
class _PluginTarget:
    tool_name: str

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
        approvals: ApprovalManager,
        anomaly: AnomalyDetector | None = None,
        dlp: DlpScanner | None = None,
        native_registry: NativeToolRegistry | None = None,
        plugin_registry: PluginRegistry | None = None,
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

    def _resolve_target(
        self, tool_name: str, agent_config
    ) -> _DownstreamTarget | _NativeTarget | _PluginTarget | None:
        if self._native and self._native.has_tool(tool_name):
            return _NativeTarget(tool_name=tool_name)
        if self._plugins and self._plugins.has_tool(tool_name):
            return _PluginTarget(tool_name=tool_name)
        result = self._server_for_tool(tool_name, agent_config)
        if result:
            return _DownstreamTarget(server_name=result[0], server_cfg=result[1])
        return None

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
        call_reason: str | None = None,
        approval_id: str | None = None,
        approval_note: str | None = None,
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
        )
        await self._audit.log(event)
        if self._anomaly is not None:
            await self._anomaly.check(event)
        raise PermissionError(reason)

    async def call_tool(
        self, session: Session, tool_name: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        agent_cfg = self._identity.get_agent_config(session.agent_id)
        if agent_cfg is None:
            raise ValueError(f"No config for agent {session.agent_id!r}")

        call_reason: str | None = params.pop("_reason", None)
        # DLP-scan _reason before storing — it's written to the audit log and readable
        # via GET /audit/recent, making it a covert exfiltration channel (Finding 3).
        if call_reason and self._dlp is not None:
            scanned = self._dlp.scan_outbound({"_reason": call_reason})
            call_reason = scanned.sanitized.get("_reason", call_reason)
            if scanned.blocked:
                call_reason = "[REDACTED BY DLP]"

        start = time.monotonic()
        response_status = "error"
        credential_accessed = None
        approval_id: str | None = None
        approval_note: str | None = None

        target = self._resolve_target(tool_name, agent_cfg)
        if isinstance(target, _NativeTarget):
            server_name: str | None = NativeToolRegistry.VIRTUAL_SERVER_NAME
        elif isinstance(target, _PluginTarget):
            server_name = PluginRegistry.VIRTUAL_SERVER_NAME
        elif isinstance(target, _DownstreamTarget):
            server_name = target.server_name
        else:
            server_name = None

        # Native and plugin tools execute real code/HTTP with operator credentials,
        # so always enforce rules even when the agent is log_only (Finding 4).
        if not agent_cfg.log_only or isinstance(target, (_NativeTarget, _PluginTarget)):
            if target is None:
                await self._deny(session, None, tool_name, params, f"no server or native tool found for {tool_name!r}", call_reason)

            effective_rules = get_effective_rules(self._config, session.agent_id, server_name)  # type: ignore[arg-type]
            if effective_rules is None:
                await self._deny(session, server_name, tool_name, params, f"no rules configured for server {server_name!r}", call_reason)

            allowed, constraint = check_tool(effective_rules, tool_name)  # type: ignore[arg-type]
            if not allowed:
                await self._deny(session, server_name, tool_name, params, f"tool {tool_name!r} not in ruleset for {server_name!r}", call_reason)

            if constraint is not None:
                if constraint.rate_limit is not None:
                    if not self._limiter.check(session.agent_id, tool_name, constraint.rate_limit):
                        await self._deny(session, server_name, tool_name, params, f"rate limit exceeded for tool {tool_name!r}", call_reason)

                param_denial = validate_params(params, constraint)
                if param_denial is not None:
                    await self._deny(session, server_name, tool_name, params, param_denial, call_reason)

                if constraint.require_approval:
                    approved, approval_id, approval_note = await self._approvals.request(
                        agent_id=session.agent_id,
                        tool=tool_name,
                        params=params,
                        reason=call_reason,
                    )
                    if not approved:
                        await self._deny(
                            session, server_name, tool_name, params,
                            f"approval denied: {approval_note or 'request denied'}",
                            call_reason, approval_id=approval_id, approval_note=approval_note,
                        )

        # DLP outbound scan — run after all enforcement, before forwarding.
        if self._dlp is not None:
            outbound = self._dlp.scan_outbound(params)
            if outbound.blocked:
                blocked_names = [v.pattern_name for v in outbound.violations if v.action == "block"]
                params = outbound.sanitized  # don't log raw sensitive data in audit
                await self._deny(
                    session, server_name, tool_name, params,
                    f"DLP: sensitive data in params ({', '.join(blocked_names)})",
                    call_reason,
                )
            if outbound.needs_approval:
                approve_names = [v.pattern_name for v in outbound.violations if v.action == "approve"]
                approved, approval_id, approval_note = await self._approvals.request(
                    agent_id=session.agent_id,
                    tool=tool_name,
                    params=outbound.sanitized,
                    reason=f"DLP outbound: {', '.join(approve_names)} detected in params",
                )
                if not approved:
                    params = outbound.sanitized
                    await self._deny(
                        session, server_name, tool_name, params,
                        f"DLP outbound approval denied ({', '.join(approve_names)}): {approval_note or 'request denied'}",
                        call_reason, approval_id=approval_id, approval_note=approval_note,
                    )
            params = outbound.sanitized  # forward redacted copy

        result: dict[str, Any] | None = None
        audit_event: AuditEvent | None = None

        try:
            if target is None:
                raise ValueError(f"No server or native tool found for {tool_name!r}")

            if isinstance(target, _NativeTarget):
                result = await self._native.execute(tool_name, params)  # type: ignore[union-attr]
                if self._native and self._native._configs[tool_name].credential:
                    credential_accessed = f"native:{tool_name}"
                response_status = "success"
            elif isinstance(target, _PluginTarget):
                result = await self._plugins.execute(tool_name, params)  # type: ignore[union-attr]
                response_status = "success"
            else:
                token = self._credentials.get_token(target.server_name)
                if token:
                    credential_accessed = target.server_name

                headers = {"Content-Type": "application/json", "Accept": "application/json"}
                if token:
                    headers["Authorization"] = f"Bearer {token}"

                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        target.server_cfg.url,
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
                    shaped = shape_response(result, target.server_cfg.response_fields, target.server_cfg.max_response_chars)
                    result = shaped if isinstance(shaped, dict) else {"content": [{"type": "text", "text": shaped}]}
                    response_status = "success"

            # DLP inbound scan — sanitize response before it reaches the agent.
            if self._dlp is not None:
                inbound = self._dlp.scan_inbound(result)
                result = inbound.sanitized
                if inbound.blocked:
                    raise RuntimeError("DLP: inbound response blocked by security policy")
                if inbound.needs_approval:
                    approve_names = [v.pattern_name for v in inbound.violations if v.action == "approve"]
                    approved, approval_id, approval_note = await self._approvals.request(
                        agent_id=session.agent_id,
                        tool=tool_name,
                        params={"_dlp_inbound_patterns": approve_names},
                        reason=f"DLP inbound: {', '.join(approve_names)} detected in response",
                    )
                    if not approved:
                        raise RuntimeError(
                            f"DLP inbound approval denied ({', '.join(approve_names)}): "
                            f"{approval_note or 'request denied'}"
                        )
                warn_names = [v.pattern_name for v in inbound.violations if v.action == "warn"]
                if warn_names:
                    result.setdefault("_security_warnings", []).extend(
                        f"response flagged by DLP pattern: {n}" for n in warn_names
                    )
                redacted_names = [v.pattern_name for v in inbound.violations if v.action == "redact"]
                if redacted_names:
                    result.setdefault("_security_warnings", []).extend(
                        f"content redacted by DLP pattern: {n}" for n in redacted_names
                    )

        except Exception as e:
            log.error("Tool call failed: tool=%s error=%s", tool_name, e)
            response_status = "error"
            raise
        finally:
            latency_ms = int((time.monotonic() - start) * 1000)
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
            )
            await self._audit.log(audit_event)

        # Only reached on success (exceptions are re-raised above)
        if self._anomaly is not None and result is not None:
            anomalies = await self._anomaly.check(audit_event)  # type: ignore[arg-type]
            if anomalies:
                result["_anomalies"] = anomalies
        return result  # type: ignore[return-value]
