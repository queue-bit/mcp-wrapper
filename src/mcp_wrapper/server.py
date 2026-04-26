from __future__ import annotations

"""Streamable HTTP MCP wrapper server.

Presents a standard MCP endpoint. Agents authenticate via:
    Authorization: Bearer <token>

All calls are forwarded to the appropriate downstream MCP server after
logging. Phase 1: log-only, no enforcement.
"""

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .credentials import CredentialBroker, SecretResolver, VaultClient
from .identity import IdentityResolver
from .logger import AuditLogger
from .models import AuditEvent, Session, WrapperConfig
from .proxy import McpProxy

log = logging.getLogger(__name__)


class ToolCallRequest(BaseModel):
    tool: str
    params: dict[str, Any] = {}


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
    proxy = McpProxy(config, identity, audit, credentials)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await audit.start()
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
        try:
            result = await proxy.call_tool(session, body.tool, body.params)
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
                    resp = await client.get(
                        f"{server_cfg.url}/tools", headers=headers, timeout=10.0
                    )
                    resp.raise_for_status()
                    server_tools = resp.json().get("tools", [])
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

    @app.get("/audit/recent")
    async def recent_logs(
        limit: int = 50,
        session: Session = Depends(get_session),
    ) -> JSONResponse:
        """Return recent audit log entries for the authenticated agent."""
        import aiosqlite
        rows = []
        async with aiosqlite.connect(config.logging.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM audit_log WHERE agent_id = ? ORDER BY id DESC LIMIT ?",
                (session.agent_id, limit),
            ) as cursor:
                async for row in cursor:
                    rows.append(dict(row))
        return JSONResponse(content={"entries": rows})

    return app
