from __future__ import annotations

"""Streamable HTTP MCP wrapper server.

Presents a standard MCP endpoint. Agents authenticate via:
    Authorization: Bearer <token>

Tool listing and calls are filtered and enforced against the agent's
rules. log_only = true bypasses enforcement for observation mode.
"""

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .anomaly import AnomalyDetector
from .approvals import ApprovalManager
from .dlp import DlpScanner
from .credentials import CredentialBroker, SecretResolver, VaultClient
from .identity import IdentityResolver
from .limiter import RateLimiter
from .logger import AuditLogger
from .models import AuditEvent, Session, WrapperConfig
from .notifications import build_notifiers
from .proxy import McpProxy
from .rules import check_tool, get_effective_rules

log = logging.getLogger(__name__)


class ToolCallRequest(BaseModel):
    tool: str
    params: dict[str, Any] = {}


class ApprovalResolution(BaseModel):
    approved: bool
    note: str | None = None


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
    proxy = McpProxy(config, identity, audit, credentials, limiter, approvals, anomaly, dlp)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await audit.start()
        if telegram_notifier is not None:
            await telegram_notifier.register_webhook(config.approval.base_url)
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
        """Return aggregated tool list from all MCP servers the agent can reach."""
        agent_cfg = identity.get_agent_config(session.agent_id)
        if agent_cfg is None:
            raise HTTPException(status_code=403, detail="Unknown agent")

        import httpx
        tools = []
        async with httpx.AsyncClient() as client:
            for server_name in agent_cfg.mcp_servers:
                server_cfg = config.mcp_servers.get(server_name)
                if server_cfg is None:
                    continue
                token = credentials.get_token(server_name)
                headers = {}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                try:
                    resp = await client.post(
                        server_cfg.url,
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                        headers={**headers, "Content-Type": "application/json", "Accept": "application/json"},
                        timeout=10.0,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    server_tools = data.get("result", {}).get("tools", [])
                    if not agent_cfg.log_only:
                        effective_rules = get_effective_rules(config, session.agent_id, server_name)
                        if effective_rules is not None:
                            server_tools = [
                                t for t in server_tools
                                if check_tool(effective_rules, t["name"])[0]
                            ]
                        else:
                            server_tools = []
                    tools.extend(server_tools)
                except Exception as e:
                    log.warning("Could not fetch tools from %s: %s", server_name, e)

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

    return app
