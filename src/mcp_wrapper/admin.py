from __future__ import annotations

import json
import logging
import re
import sys
import time
from urllib.parse import quote as _url_quote
from typing import Any

import httpx

log = logging.getLogger(__name__)

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .admin_auth import AdminAuthRequired, AdminSessionStore, hash_password, make_require_session, verify_password
from .config_writer import ConfigWriter
from .credentials import OAuthTokenManager, VaultClient
from .dlp import DlpPattern, INBOUND_DEFAULTS, OUTBOUND_DEFAULTS
from .logger import AuditLogger
from .mcp_client import mcp_request
from .models import ParamConstraint, RateLimitConfig, ServerRules, ToolConstraint, WrapperConfig
from .native_tools import NativeToolRegistry
from .plugin_tools import PluginRegistry
from .rules import get_effective_rules

_NATIVE = NativeToolRegistry.VIRTUAL_SERVER_NAME
_PLUGINS = PluginRegistry.VIRTUAL_SERVER_NAME
_VIRTUAL_DISPLAY = {_NATIVE: "Local Tools", _PLUGINS: "Plugin Tools"}

_restart_required: bool = False


def _mark_restart_required() -> None:
    global _restart_required
    _restart_required = True


_vault_client_ref: VaultClient | None = None


def _ctx(session_info: tuple[str, str], **extra: Any) -> dict:
    _, csrf_token = session_info
    return {"csrf_token": csrf_token, "restart_required": _restart_required,
            "vault_configured": _vault_client_ref is not None, **extra}


def create_admin_router(
    config: WrapperConfig,
    config_dir: str,
    session_store: AdminSessionStore,
    audit: AuditLogger,
    templates: Jinja2Templates,
    credentials: Any = None,
    oauth_manager: OAuthTokenManager | None = None,
    vault_client: VaultClient | None = None,
    reload_config: Any = None,  # async () -> None; if set, hot-reloads instead of marking restart
) -> APIRouter:
    global _vault_client_ref
    _vault_client_ref = vault_client
    router = APIRouter()
    writer = ConfigWriter(config_dir)
    require_session = make_require_session(session_store)
    # In-memory PKCE state store: state_token → {server_name, code_verifier, expires_at}
    # Entries expire after 10 minutes (RFC 6749 §4.1).
    _oauth_state: dict[str, dict] = {}
    _OAUTH_STATE_TTL = 600

    # In-memory login attempt counter: ip → (count, window_start)
    _login_attempts: dict[str, tuple[int, float]] = {}
    _LOGIN_MAX = 10
    _LOGIN_WINDOW = 900  # 15 minutes

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    @router.get("/login")
    async def login_page(request: Request):
        return templates.TemplateResponse(request, "admin/login.html", {})

    @router.post("/login")
    async def login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
    ):
        ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        count, window_start = _login_attempts.get(ip, (0, now))
        if now - window_start > _LOGIN_WINDOW:
            count, window_start = 0, now
        count += 1
        _login_attempts[ip] = (count, window_start)
        if count > _LOGIN_MAX:
            return templates.TemplateResponse(
                request,
                "admin/login.html",
                {"error": "Too many login attempts. Try again later."},
                status_code=429,
            )

        if (
            config.admin.password_hash
            and username == config.admin.username
            and verify_password(password, config.admin.password_hash)
        ):
            _login_attempts.pop(ip, None)
            session_token, _ = session_store.create_session(username)
            response = RedirectResponse("/admin/dashboard", status_code=303)
            response.set_cookie(
                "admin_session",
                session_token,
                httponly=True,
                secure=request.url.scheme == "https",
                samesite="lax",
                max_age=config.admin.session_timeout_hours * 3600,
            )
            return response
        return templates.TemplateResponse(
            request,
            "admin/login.html",
            {"error": "Invalid username or password"},
            status_code=401,
        )

    @router.post("/logout")
    async def logout(request: Request):
        session_token = request.cookies.get("admin_session", "")
        session_store.delete_session(session_token)
        response = RedirectResponse("/admin/login", status_code=303)
        response.delete_cookie("admin_session")
        return response

    @router.get("/setup")
    async def setup_page(request: Request):
        if config.admin.password_hash:
            return RedirectResponse("/admin/login", status_code=302)
        return templates.TemplateResponse(request, "admin/setup.html", {})

    @router.post("/setup")
    async def setup_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        password_confirm: str = Form(...),
    ):
        if config.admin.password_hash:
            return RedirectResponse("/admin/login", status_code=303)
        if password != password_confirm:
            return templates.TemplateResponse(request, "admin/setup.html", {"error": "Passwords do not match"})
        if len(password) < 8:
            return templates.TemplateResponse(request, "admin/setup.html", {"error": "Password must be at least 8 characters"})
        hashed = hash_password(password)
        admin_data = {
            "enabled": True,
            "username": username,
            "password_hash": hashed,
            "session_timeout_hours": config.admin.session_timeout_hours,
        }
        await writer.write_wrapper_toml({}, admin_data)
        # Update in-memory config so the operator can log in immediately
        config.admin.username = username
        config.admin.password_hash = hashed
        return RedirectResponse("/admin/login", status_code=303)

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    @router.get("/")
    async def admin_root():
        return RedirectResponse("/admin/dashboard", status_code=302)

    @router.get("/dashboard")
    async def dashboard(request: Request, session_info=Depends(require_session)):
        stats = await audit.query_global_stats()
        recent = await audit.query_entries_admin(limit=20)
        return templates.TemplateResponse(
            request,
            "admin/dashboard.html",
            _ctx(session_info,
                 active="dashboard",
                 stats=stats,
                 recent_events=recent,
                 agents=list(config.agents.keys())),
        )

    @router.get("/api/restart-status")
    async def restart_status(session_info=Depends(require_session)):
        if _restart_required:
            return HTMLResponse(
                '<div class="banner banner-warn" '
                'hx-get="/admin/api/restart-status" hx-trigger="every 30s" hx-swap="outerHTML">'
                "&#9888; Config changed — restart required: <code>docker compose restart mcp-wrapper</code>"
                "</div>"
            )
        return HTMLResponse("")

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------

    @router.get("/agents")
    async def agents_list(request: Request, session_info=Depends(require_session), saved: str = ""):
        flash_text = "Applied." if saved == "live" else "Saved. Restart to apply."
        fp_counts = await audit.fingerprint_counts()
        return templates.TemplateResponse(
            request,
            "admin/agents.html",
            _ctx(session_info,
                 active="agents",
                 agents=config.agents,
                 fp_counts=fp_counts,
                 flash={"type": "success", "text": flash_text} if saved else None),
        )

    @router.post("/agents/new")
    async def agent_create(
        request: Request,
        session_info=Depends(require_session),
        csrf_token: str = Form(...),
        agent_id: str = Form(...),
        token: str = Form(...),
        mcp_servers: str = Form(""),
        log_only: str = Form(""),
        shared_key_action: str = Form("warn"),
        store_in_vault: str = Form(""),
    ):
        _validate_csrf(session_info, csrf_token, session_store)
        _validate_id(agent_id)
        if agent_id in config.agents:
            raise HTTPException(400, f"Agent '{agent_id}' already exists")
        servers = [s.strip() for s in mcp_servers.split(",") if s.strip()]
        if store_in_vault:
            token = _maybe_store_in_vault(vault_client, f"mcp-wrapper/agents/{agent_id}", "token", token)
        agents_raw = {k: _agent_to_dict(v) for k, v in config.agents.items()}
        agents_raw[agent_id] = {
            "token": token,
            "mcp_servers": servers,
            "log_only": bool(log_only),
            "shared_key_action": shared_key_action if shared_key_action in ("allow", "block", "warn", "notify") else "warn",
        }
        await writer.write_agents_toml(agents_raw)
        if reload_config:
            await reload_config()
            return RedirectResponse("/admin/agents?saved=live", status_code=303)
        _mark_restart_required()
        return RedirectResponse("/admin/agents?saved=1", status_code=303)

    @router.get("/agents/{agent_id}/edit")
    async def agent_edit_page(request: Request, agent_id: str, session_info=Depends(require_session)):
        if agent_id not in config.agents:
            raise HTTPException(404)
        return templates.TemplateResponse(
            request,
            "admin/agent_edit.html",
            _ctx(session_info,
                 active="agents",
                 agent_id=agent_id,
                 agent=config.agents[agent_id]),
        )

    @router.post("/agents/{agent_id}/edit")
    async def agent_edit_submit(
        request: Request,
        agent_id: str,
        session_info=Depends(require_session),
        csrf_token: str = Form(...),
        token: str = Form(""),
        mcp_servers: str = Form(""),
        log_only: str = Form(""),
        shared_key_action: str = Form("warn"),
        store_in_vault: str = Form(""),
    ):
        _validate_csrf(session_info, csrf_token, session_store)
        if agent_id not in config.agents:
            raise HTTPException(404)
        servers = [s.strip() for s in mcp_servers.split(",") if s.strip()]
        effective_token = token.strip() or config.agents[agent_id].token
        if store_in_vault and token.strip():
            effective_token = _maybe_store_in_vault(vault_client, f"mcp-wrapper/agents/{agent_id}", "token", token.strip())
        agents_raw = {k: _agent_to_dict(v) for k, v in config.agents.items()}
        agents_raw[agent_id]["token"] = effective_token
        agents_raw[agent_id]["mcp_servers"] = servers
        agents_raw[agent_id]["log_only"] = bool(log_only)
        agents_raw[agent_id]["shared_key_action"] = shared_key_action if shared_key_action in ("allow", "block", "warn", "notify") else "warn"
        await writer.write_agents_toml(agents_raw)
        if reload_config:
            await reload_config()
            return RedirectResponse("/admin/agents?saved=live", status_code=303)
        _mark_restart_required()
        return RedirectResponse("/admin/agents?saved=1", status_code=303)

    @router.post("/agents/{agent_id}/delete")
    async def agent_delete(
        request: Request,
        agent_id: str,
        session_info=Depends(require_session),
        csrf_token: str = Form(...),
    ):
        _validate_csrf(session_info, csrf_token, session_store)
        agents_raw = {k: _agent_to_dict(v) for k, v in config.agents.items() if k != agent_id}
        await writer.write_agents_toml(agents_raw)
        if reload_config:
            await reload_config()
            return RedirectResponse("/admin/agents?saved=live", status_code=303)
        _mark_restart_required()
        return RedirectResponse("/admin/agents?saved=1", status_code=303)

    # ------------------------------------------------------------------
    # MCP Servers
    # ------------------------------------------------------------------

    @router.get("/servers")
    async def servers_list(request: Request, session_info=Depends(require_session), saved: str = ""):
        oauth_status: dict[str, str] = {}
        if oauth_manager:
            for name in config.mcp_servers:
                oauth_status[name] = oauth_manager.get_connection_status(name)
        flash_text = "Applied." if saved == "live" else "Saved. Restart to apply."
        return templates.TemplateResponse(
            request,
            "admin/servers.html",
            _ctx(session_info,
                 active="servers",
                 servers=config.mcp_servers,
                 oauth_status=oauth_status,
                 flash={"type": "success", "text": flash_text} if saved else None),
        )

    @router.post("/servers/new")
    async def server_create(
        request: Request,
        session_info=Depends(require_session),
        csrf_token: str = Form(...),
        server_name: str = Form(...),
        url: str = Form(...),
        transport: str = Form("http"),
        credential: str = Form(""),
        response_fields: str = Form(""),
        max_response_chars: str = Form(""),
        oauth_grant_type: str = Form(""),
        oauth_client_id: str = Form(""),
        oauth_client_secret: str = Form(""),
        oauth_token_url: str = Form(""),
        oauth_authorize_url: str = Form(""),
        oauth_pkce: str = Form(""),
        oauth_scopes: str = Form(""),
        oauth_user_scopes: str = Form(""),
        oauth_audience: str = Form(""),
        store_in_vault: str = Form(""),
    ):
        _validate_csrf(session_info, csrf_token, session_store)
        _validate_id(server_name)
        if server_name in config.mcp_servers:
            raise HTTPException(400, f"Server '{server_name}' already exists")
        if store_in_vault and credential.strip():
            credential = _maybe_store_in_vault(vault_client, f"mcp-wrapper/servers/{server_name}", "credential", credential.strip())
        servers_raw = {k: _server_to_dict(v) for k, v in config.mcp_servers.items()}
        d = _build_server_dict(url, transport, credential, response_fields, max_response_chars)
        if oauth_grant_type.strip() and oauth_client_id.strip() and oauth_token_url.strip():
            od: dict = {
                "grant_type": oauth_grant_type.strip(),
                "client_id": oauth_client_id.strip(),
                "token_url": oauth_token_url.strip(),
            }
            if oauth_client_secret.strip():
                od["client_secret"] = oauth_client_secret.strip()
            if oauth_authorize_url.strip():
                od["authorize_url"] = oauth_authorize_url.strip()
            scopes = [s for s in oauth_scopes.split() if s]
            if scopes:
                od["scopes"] = scopes
            user_scopes = [s for s in oauth_user_scopes.split() if s]
            if user_scopes:
                od["user_scopes"] = user_scopes
            if oauth_audience.strip():
                od["audience"] = oauth_audience.strip()
            od["pkce"] = bool(oauth_pkce)
            d["oauth"] = od
        servers_raw[server_name] = d
        await writer.write_mcp_servers_toml(servers_raw)
        if reload_config:
            await reload_config()
            return RedirectResponse("/admin/servers?saved=live", status_code=303)
        _mark_restart_required()
        return RedirectResponse("/admin/servers?saved=1", status_code=303)

    @router.get("/servers/{server_name}/edit")
    async def server_edit_page(request: Request, server_name: str, session_info=Depends(require_session)):
        if server_name not in config.mcp_servers:
            raise HTTPException(404)
        return templates.TemplateResponse(
            request,
            "admin/server_edit.html",
            _ctx(session_info,
                 active="servers",
                 server_name=server_name,
                 server=config.mcp_servers[server_name]),
        )

    @router.post("/servers/{server_name}/edit")
    async def server_edit_submit(
        request: Request,
        server_name: str,
        session_info=Depends(require_session),
        csrf_token: str = Form(...),
        url: str = Form(...),
        transport: str = Form("http"),
        credential: str = Form(""),
        response_fields: str = Form(""),
        max_response_chars: str = Form(""),
        oauth_grant_type: str = Form(""),
        oauth_client_id: str = Form(""),
        oauth_client_secret: str = Form(""),
        oauth_token_url: str = Form(""),
        oauth_authorize_url: str = Form(""),
        oauth_pkce: str = Form(""),
        oauth_scopes: str = Form(""),
        oauth_user_scopes: str = Form(""),
        oauth_audience: str = Form(""),
        store_in_vault: str = Form(""),
        store_oauth_secret_in_vault: str = Form(""),
    ):
        _validate_csrf(session_info, csrf_token, session_store)
        if server_name not in config.mcp_servers:
            raise HTTPException(404)
        if store_in_vault and credential.strip():
            credential = _maybe_store_in_vault(vault_client, f"mcp-wrapper/servers/{server_name}", "credential", credential.strip())
        elif not credential.strip():
            credential = config.mcp_servers[server_name].credential or ""
        servers_raw = {k: _server_to_dict(v) for k, v in config.mcp_servers.items()}
        d = _build_server_dict(url, transport, credential, response_fields, max_response_chars)
        if oauth_grant_type.strip() and oauth_client_id.strip() and oauth_token_url.strip():
            existing_oauth = config.mcp_servers[server_name].oauth
            # Keep existing secret if blank was submitted
            secret = oauth_client_secret.strip()
            if not secret and existing_oauth and existing_oauth.client_secret:
                secret = existing_oauth.client_secret
            if store_oauth_secret_in_vault and secret:
                secret = _maybe_store_in_vault(vault_client, f"mcp-wrapper/servers/{server_name}", "oauth_client_secret", secret)
            od: dict = {
                "grant_type": oauth_grant_type.strip(),
                "client_id": oauth_client_id.strip(),
                "token_url": oauth_token_url.strip(),
            }
            if secret:
                od["client_secret"] = secret
            if oauth_authorize_url.strip():
                od["authorize_url"] = oauth_authorize_url.strip()
            scopes = [s for s in oauth_scopes.split() if s]
            if scopes:
                od["scopes"] = scopes
            user_scopes = [s for s in oauth_user_scopes.split() if s]
            if user_scopes:
                od["user_scopes"] = user_scopes
            if oauth_audience.strip():
                od["audience"] = oauth_audience.strip()
            od["pkce"] = bool(oauth_pkce)
            d["oauth"] = od
        servers_raw[server_name] = d
        await writer.write_mcp_servers_toml(servers_raw)
        if reload_config:
            await reload_config()
            return RedirectResponse("/admin/servers?saved=live", status_code=303)
        _mark_restart_required()
        return RedirectResponse("/admin/servers?saved=1", status_code=303)

    @router.post("/servers/{server_name}/delete")
    async def server_delete(
        request: Request,
        server_name: str,
        session_info=Depends(require_session),
        csrf_token: str = Form(...),
    ):
        _validate_csrf(session_info, csrf_token, session_store)
        servers_raw = {k: _server_to_dict(v) for k, v in config.mcp_servers.items() if k != server_name}
        await writer.write_mcp_servers_toml(servers_raw)
        if reload_config:
            await reload_config()
            return RedirectResponse("/admin/servers?saved=live", status_code=303)
        _mark_restart_required()
        return RedirectResponse("/admin/servers?saved=1", status_code=303)

    # ------------------------------------------------------------------
    # Explorer
    # ------------------------------------------------------------------

    @router.get("/explore")
    async def explore_root(request: Request, session_info=Depends(require_session)):
        first = next(iter(config.mcp_servers), None)
        if first:
            return RedirectResponse(f"/admin/explore/{first}", status_code=302)
        return templates.TemplateResponse(
            request, "admin/explore.html",
            _ctx(session_info, active="explore", servers=list(config.mcp_servers), server_name=None,
                 tools=[], entities=[], error=None, entity_error=None),
        )

    @router.get("/explore/{server_name}")
    async def explore_server(request: Request, server_name: str, session_info=Depends(require_session)):
        if server_name not in config.mcp_servers:
            raise HTTPException(404)
        server_cfg = config.mcp_servers[server_name]
        token: str | None = None
        if credentials is not None:
            try:
                token = await credentials.get_token(server_name)
            except Exception:
                pass

        raw_tools, tools_error = await _fetch_full_tools(server_cfg.url, token, server_cfg.transport)
        tools = [_extract_tool_info(t) for t in raw_tools]

        entities: list[dict] = []
        entity_error: str | None = None
        if any(t["name"] == "GetLiveContext" for t in raw_tools):
            ctx_text, entity_error = await _call_tool_raw(server_cfg.url, token, "GetLiveContext", {}, server_cfg.transport)
            if ctx_text:
                entities = _parse_live_context(ctx_text)

        return templates.TemplateResponse(
            request, "admin/explore.html",
            _ctx(session_info, active="explore",
                 servers=list(config.mcp_servers),
                 server_name=server_name,
                 tools=tools,
                 entities=entities,
                 error=tools_error,
                 entity_error=entity_error),
        )

    # ------------------------------------------------------------------
    # Entity-level access
    # ------------------------------------------------------------------

    @router.get("/rules/agent/{agent_id}/entity-access/{server_name}")
    async def entity_access_page(
        request: Request, agent_id: str, server_name: str,
        session_info=Depends(require_session), saved: str = "",
    ):
        if agent_id not in config.agents or server_name not in config.mcp_servers:
            raise HTTPException(404)
        server_cfg = config.mcp_servers[server_name]
        token = await _get_credential_token(credentials, server_name)
        raw_tools, tools_error = await _fetch_full_tools(server_cfg.url, token, server_cfg.transport)
        name_tools = [t["name"] for t in raw_tools
                      if "name" in t.get("inputSchema", {}).get("properties", {})]
        other_tools = [t["name"] for t in raw_tools
                       if "name" not in t.get("inputSchema", {}).get("properties", {})]
        entities: list[dict] = []
        entity_error: str | None = None
        if any(t["name"] == "GetLiveContext" for t in raw_tools):
            ctx_text, entity_error = await _call_tool_raw(server_cfg.url, token, "GetLiveContext", {}, server_cfg.transport)
            if ctx_text:
                entities = _parse_live_context(ctx_text)
        rules = get_effective_rules(config, agent_id, server_name)
        tool_states = _build_entity_tool_states(rules, name_tools)
        other_tool_states = _build_other_tool_states(rules, other_tools)
        return templates.TemplateResponse(
            request, "admin/entity_access.html",
            _ctx(session_info, active="rules",
                 agent_id=agent_id, server_name=server_name,
                 entities=entities, entity_error=entity_error,
                 name_tools=name_tools, other_tools=other_tools,
                 tool_states=tool_states, other_tool_states=other_tool_states,
                 tools_error=tools_error,
                 flash=("Applied." if saved == "live" else "Saved — restart to apply.") if saved else None),
        )

    @router.post("/rules/agent/{agent_id}/entity-access/{server_name}")
    async def entity_access_save(
        request: Request, agent_id: str, server_name: str,
        session_info=Depends(require_session),
    ):
        form = await request.form()
        _validate_csrf(session_info, str(form.get("csrf_token", "")), session_store)
        if agent_id not in config.agents or server_name not in config.mcp_servers:
            raise HTTPException(404)

        # Reconstruct tool and entity name lists from hidden form fields
        name_tools: list[str] = []
        i = 0
        while f"tool_{i}" in form:
            name_tools.append(str(form[f"tool_{i}"]))
            i += 1
        entity_names: list[str] = []
        j = 0
        while f"entity_{j}" in form:
            entity_names.append(str(form[f"entity_{j}"]))
            j += 1

        existing = get_effective_rules(config, agent_id, server_name)
        new_constrain: dict[str, ToolConstraint] = {}
        new_allow: list[str] = []

        # Build per-tool constraints from matrix
        for ti, tool_name in enumerate(name_tools):
            checked = [entity_names[ei] for ei in range(len(entity_names))
                       if str(form.get(f"cell_{ei}_{ti}", "")) == "on"]
            gate = str(form.get(f"gate_{ti}", "")) == "1"
            existing_tc = existing.constrain.get(tool_name) if existing else None
            existing_rate = existing_tc.rate_limit if existing_tc else None
            existing_other = {k: v for k, v in (existing_tc.allowed_params.items()
                              if existing_tc else []) if k != "name"}
            if checked:
                allowed_params = {"name": ParamConstraint(allowlist=checked), **existing_other}
                new_constrain[tool_name] = ToolConstraint(
                    require_approval=gate, rate_limit=existing_rate, allowed_params=allowed_params)
            elif gate or existing_rate or existing_other:
                new_constrain[tool_name] = ToolConstraint(
                    require_approval=gate, rate_limit=existing_rate, allowed_params=existing_other)

        # Build other-tool allow/constrain from simple checkboxes
        k = 0
        while f"other_name_{k}" in form:
            other_tool = str(form[f"other_name_{k}"])
            allowed = str(form.get(f"other_{k}", "")) == "on"
            gate = str(form.get(f"other_gate_{k}", "")) == "1"
            existing_tc = existing.constrain.get(other_tool) if existing else None
            if allowed:
                if gate or (existing_tc and (existing_tc.rate_limit or existing_tc.allowed_params)):
                    new_constrain[other_tool] = ToolConstraint(
                        require_approval=gate,
                        rate_limit=existing_tc.rate_limit if existing_tc else None,
                        allowed_params=existing_tc.allowed_params if existing_tc else {},
                    )
                else:
                    new_allow.append(other_tool)
            k += 1

        if existing:
            new_allow.extend(_glob_patterns(existing))

        new_rules = {**{aid: dict(srvs) for aid, srvs in config.agent_overrides.items()}}
        new_rules.setdefault(agent_id, {})[server_name] = ServerRules(
            allow=new_allow, constrain=new_constrain)
        await writer.write_agent_overrides(new_rules)
        if reload_config:
            await reload_config()
            return RedirectResponse(
                f"/admin/rules/agent/{_url_quote(agent_id)}/entity-access/{_url_quote(server_name)}?saved=live",
                status_code=303)
        _mark_restart_required()
        return RedirectResponse(
            f"/admin/rules/agent/{_url_quote(agent_id)}/entity-access/{_url_quote(server_name)}?saved=1",
            status_code=303)

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    @router.get("/rules")
    async def rules_page(request: Request, session_info=Depends(require_session)):
        agent_rows = _build_agent_rows(config)
        server_rows = _build_server_rows(config)
        return templates.TemplateResponse(
            request,
            "admin/rules.html",
            _ctx(session_info, active="rules", agent_rows=agent_rows, server_rows=server_rows),
        )

    @router.get("/rules/agent/{agent_id}/panel")
    async def agent_rules_panel(request: Request, agent_id: str, session_info=Depends(require_session)):
        if agent_id not in config.agents:
            raise HTTPException(404)
        _, csrf_token = session_info
        panel_data = await _build_agent_panel_data(config, agent_id, credentials)
        return templates.TemplateResponse(
            request,
            "admin/partials/agent_rules_panel.html",
            {"csrf_token": csrf_token, "agent_id": agent_id, "servers": panel_data},
        )

    @router.post("/rules/agent/{agent_id}")
    async def save_agent_rules(request: Request, agent_id: str, session_info=Depends(require_session)):
        form = await request.form()
        _validate_csrf(session_info, str(form.get("csrf_token", "")), session_store)
        if agent_id not in config.agents:
            raise HTTPException(404)

        agent = config.agents[agent_id]
        new_server_rules: dict[str, ServerRules] = {}

        for server_name in list(agent.mcp_servers) + _virtual_servers(config):
            existing = get_effective_rules(config, agent_id, server_name)

            # Checked exact-match tools
            checked: set[str] = set()
            for key, val in form.multi_items():
                prefix = f"{server_name}__tool__"
                if key.startswith(prefix) and val == "on":
                    checked.add(key[len(prefix):])

            # Glob patterns from text field
            raw_patterns = str(form.get(f"{server_name}__patterns", "")).strip()
            patterns = [
                p.strip() for p in raw_patterns.split(",")
                if p.strip() and any(c in p for c in ("*", "?", "["))
            ]

            new_allow: list[str] = list(patterns)
            new_constrain: dict[str, ToolConstraint] = {}
            for tool_name in sorted(checked):
                existing_tc = existing.constrain.get(tool_name) if existing else None
                if existing_tc is not None:
                    new_constrain[tool_name] = existing_tc
                else:
                    new_allow.append(tool_name)

            new_server_rules[server_name] = ServerRules(allow=new_allow, constrain=new_constrain)

        # Merge into the full overrides dict and write
        all_overrides = {
            aid: dict(srvs) for aid, srvs in config.agent_overrides.items()
        }
        all_overrides[agent_id] = new_server_rules
        await writer.write_agent_overrides(all_overrides)
        if reload_config:
            await reload_config()
        else:
            _mark_restart_required()

        _, csrf_token = session_info
        panel_data = await _build_agent_panel_data_from(config, agent_id, new_server_rules, credentials)
        return templates.TemplateResponse(
            request,
            "admin/partials/agent_rules_panel.html",
            {
                "csrf_token": csrf_token,
                "agent_id": agent_id,
                "servers": panel_data,
                "flash": "Applied." if reload_config else "Saved — restart to apply.",
            },
        )

    @router.get("/rules/server/{server_name}/panel")
    async def server_rules_panel(request: Request, server_name: str, session_info=Depends(require_session)):
        if server_name not in config.mcp_servers and server_name not in _VIRTUAL_DISPLAY:
            raise HTTPException(404)
        _, csrf_token = session_info
        panel_data = await _build_server_panel_data(config, server_name, credentials)
        return templates.TemplateResponse(
            request,
            "admin/partials/server_rules_panel.html",
            {"csrf_token": csrf_token, "server_name": server_name, **panel_data},
        )

    @router.post("/rules/server/{server_name}/defaults")
    async def save_server_defaults(request: Request, server_name: str, session_info=Depends(require_session)):
        form = await request.form()
        _validate_csrf(session_info, str(form.get("csrf_token", "")), session_store)
        if server_name not in config.mcp_servers and server_name not in _VIRTUAL_DISPLAY:
            raise HTTPException(404)

        existing = config.server_rules.get(server_name)
        checked: set[str] = set()
        for key, val in form.multi_items():
            prefix = f"{server_name}__tool__"
            if key.startswith(prefix) and val == "on":
                checked.add(key[len(prefix):])

        raw_patterns = str(form.get(f"{server_name}__patterns", "")).strip()
        patterns = [
            p.strip() for p in raw_patterns.split(",")
            if p.strip() and any(c in p for c in ("*", "?", "["))
        ]

        new_allow: list[str] = list(patterns)
        new_constrain: dict[str, ToolConstraint] = {}
        for tool_name in sorted(checked):
            existing_tc = existing.constrain.get(tool_name) if existing else None
            if existing_tc is not None:
                new_constrain[tool_name] = existing_tc
            else:
                new_allow.append(tool_name)

        new_rules = {**config.server_rules, server_name: ServerRules(allow=new_allow, constrain=new_constrain)}
        await writer.write_server_rules(new_rules)
        if reload_config:
            await reload_config()
        else:
            _mark_restart_required()

        _, csrf_token = session_info
        panel_data = await _build_server_panel_data_from(config, server_name, new_rules[server_name], credentials)
        return templates.TemplateResponse(
            request,
            "admin/partials/server_rules_panel.html",
            {"csrf_token": csrf_token, "server_name": server_name,
             "flash": "Applied." if reload_config else "Saved — restart to apply.", **panel_data},
        )

    # ------------------------------------------------------------------
    # Tool constraint editor
    # ------------------------------------------------------------------

    @router.post("/rules/tool/parse-toml")
    async def parse_tool_toml(request: Request, session_info=Depends(require_session)):
        body = await request.json()
        tc, err = _toml_to_tc(str(body.get("toml", "")))
        if err:
            return JSONResponse({"error": err}, status_code=400)  # lgtm[py/stack-trace-exposure]
        return JSONResponse({
            "require_approval": tc.require_approval if tc else False,
            "response_jq":  tc.response_jq  or "" if tc else "",
            "response_grep": tc.response_grep or "" if tc else "",
            "per_minute": tc.rate_limit.per_minute if tc and tc.rate_limit else "",
            "per_hour":   tc.rate_limit.per_hour   if tc and tc.rate_limit else "",
            "params": [
                {"name": pname,
                 "allowlist": ", ".join(pc.allowlist) if pc.allowlist else "",
                 "pattern":  pc.pattern  or "",
                 "minimum":  pc.minimum  if pc.minimum  is not None else "",
                 "maximum":  pc.maximum  if pc.maximum  is not None else ""}
                for pname, pc in (tc.allowed_params.items() if tc else [])
            ],
        })

    @router.get("/rules/agent/{agent_id}/tool/{server_name}/{tool_name}")
    async def agent_tool_constraint_editor(
        request: Request, agent_id: str, server_name: str, tool_name: str,
        session_info=Depends(require_session),
    ):
        if agent_id not in config.agents:
            raise HTTPException(404)
        existing = get_effective_rules(config, agent_id, server_name)
        tc = existing.constrain.get(tool_name) if existing else None
        return templates.TemplateResponse(
            request, "admin/tool_constraint_editor.html",
            _ctx(session_info, active="rules",
                 agent_id=agent_id, server_name=server_name, tool_name=tool_name,
                 initial_toml=_constraint_to_toml(tc),
                 fields=_tc_to_fields(tc),
                 save_url=f"/admin/rules/agent/{agent_id}/tool/{server_name}/{tool_name}",
                 back_url="/admin/rules",
                 context_label=f"{agent_id} › {server_name}",
                 error=None),
        )

    @router.post("/rules/agent/{agent_id}/tool/{server_name}/{tool_name}")
    async def save_agent_tool_constraint(
        request: Request, agent_id: str, server_name: str, tool_name: str,
        session_info=Depends(require_session),
    ):
        form = await request.form()
        _validate_csrf(session_info, str(form.get("csrf_token", "")), session_store)
        if agent_id not in config.agents:
            raise HTTPException(404)
        toml_str = str(form.get("constraint_toml", "")).strip()
        tc, err = _toml_to_tc(toml_str)
        if err:
            return templates.TemplateResponse(
                request, "admin/tool_constraint_editor.html",
                _ctx(session_info, active="rules",
                     agent_id=agent_id, server_name=server_name, tool_name=tool_name,
                     initial_toml=toml_str, fields=_tc_to_fields(None),
                     save_url=f"/admin/rules/agent/{agent_id}/tool/{server_name}/{tool_name}",
                     back_url="/admin/rules",
                     context_label=f"{agent_id} › {server_name}",
                     error=f"TOML error: {err}"),
                status_code=400,
            )
        existing_rules = get_effective_rules(config, agent_id, server_name)
        new_allow = [t for t in (existing_rules.allow if existing_rules else []) if t != tool_name]
        new_constrain = dict(existing_rules.constrain if existing_rules else {})
        new_constrain.pop(tool_name, None)
        if tc is not None:
            new_constrain[tool_name] = tc
        else:
            new_allow.append(tool_name)
        all_overrides = {aid: dict(srvs) for aid, srvs in config.agent_overrides.items()}
        all_overrides.setdefault(agent_id, {})[server_name] = ServerRules(
            allow=new_allow, constrain=new_constrain)
        await writer.write_agent_overrides(all_overrides)
        if reload_config:
            await reload_config()
        else:
            _mark_restart_required()
        return RedirectResponse("/admin/rules", status_code=303)

    @router.get("/rules/server/{server_name}/tool/{tool_name}")
    async def server_tool_constraint_editor(
        request: Request, server_name: str, tool_name: str,
        session_info=Depends(require_session),
    ):
        if server_name not in config.mcp_servers and server_name not in _VIRTUAL_DISPLAY:
            raise HTTPException(404)
        existing = config.server_rules.get(server_name)
        tc = existing.constrain.get(tool_name) if existing else None
        return templates.TemplateResponse(
            request, "admin/tool_constraint_editor.html",
            _ctx(session_info, active="rules",
                 agent_id=None, server_name=server_name, tool_name=tool_name,
                 initial_toml=_constraint_to_toml(tc),
                 fields=_tc_to_fields(tc),
                 save_url=f"/admin/rules/server/{server_name}/tool/{tool_name}",
                 back_url="/admin/rules",
                 context_label=f"{server_name} (defaults)",
                 error=None),
        )

    @router.post("/rules/server/{server_name}/tool/{tool_name}")
    async def save_server_tool_constraint(
        request: Request, server_name: str, tool_name: str,
        session_info=Depends(require_session),
    ):
        form = await request.form()
        _validate_csrf(session_info, str(form.get("csrf_token", "")), session_store)
        if server_name not in config.mcp_servers and server_name not in _VIRTUAL_DISPLAY:
            raise HTTPException(404)
        toml_str = str(form.get("constraint_toml", "")).strip()
        tc, err = _toml_to_tc(toml_str)
        if err:
            return templates.TemplateResponse(
                request, "admin/tool_constraint_editor.html",
                _ctx(session_info, active="rules",
                     agent_id=None, server_name=server_name, tool_name=tool_name,
                     initial_toml=toml_str, fields=_tc_to_fields(None),
                     save_url=f"/admin/rules/server/{server_name}/tool/{tool_name}",
                     back_url="/admin/rules",
                     context_label=f"{server_name} (defaults)",
                     error=f"TOML error: {err}"),
                status_code=400,
            )
        existing = config.server_rules.get(server_name)
        new_allow = [t for t in (existing.allow if existing else []) if t != tool_name]
        new_constrain = dict(existing.constrain if existing else {})
        new_constrain.pop(tool_name, None)
        if tc is not None:
            new_constrain[tool_name] = tc
        else:
            new_allow.append(tool_name)
        new_rules = {**config.server_rules,
                     server_name: ServerRules(allow=new_allow, constrain=new_constrain)}
        await writer.write_server_rules(new_rules)
        if reload_config:
            await reload_config()
        else:
            _mark_restart_required()
        return RedirectResponse("/admin/rules", status_code=303)

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    @router.get("/audit")
    async def audit_view(
        request: Request,
        session_info=Depends(require_session),
        agent_id: str = "",
        tool: str = "",
        decision: str = "",
        since: str = "",
        until: str = "",
        limit: int = 100,
    ):
        entries = await audit.query_entries_admin(
            agent_id=agent_id or None,
            limit=min(limit, 500),
            tool=tool or None,
            decision=decision or None,
            since=since or None,
            until=until or None,
        )
        ctx = _ctx(session_info,
                   active="audit",
                   entries=entries,
                   agents=list(config.agents.keys()),
                   filters={"agent_id": agent_id, "tool": tool, "decision": decision,
                             "since": since, "until": until, "limit": limit})
        if request.headers.get("HX-Request"):
            return templates.TemplateResponse(request, "admin/partials/audit_table.html", ctx)
        return templates.TemplateResponse(request, "admin/audit.html", ctx)

    @router.get("/audit/{event_id:int}")
    async def audit_event_detail(
        request: Request,
        event_id: int,
        session_info=Depends(require_session),
    ):
        entry = await audit.get_entry_by_id(event_id)
        if entry is None:
            return HTMLResponse(
                "<div class='audit-pane-loading'>Event not found.</div>", status_code=404
            )
        params_pretty: str | None = None
        if entry.get("params"):
            try:
                params_pretty = json.dumps(json.loads(entry["params"]), indent=2)
            except Exception:
                params_pretty = entry["params"]
        response_pretty: str | None = None
        if entry.get("response"):
            try:
                response_pretty = json.dumps(json.loads(entry["response"]), indent=2)
            except Exception:
                response_pretty = entry["response"]
        anomaly_list: list[str] | None = None
        if entry.get("anomalies"):
            try:
                anomaly_list = json.loads(entry["anomalies"])
            except Exception:
                anomaly_list = [entry["anomalies"]]
        _, csrf_token = session_info
        return templates.TemplateResponse(
            request,
            "admin/partials/audit_detail.html",
            {"entry": entry, "params_pretty": params_pretty,
             "response_pretty": response_pretty, "anomaly_list": anomaly_list,
             "csrf_token": csrf_token},
        )

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    @router.get("/settings")
    async def settings_page(request: Request, session_info=Depends(require_session), saved: str = ""):
        return templates.TemplateResponse(
            request,
            "admin/settings.html",
            _ctx(session_info,
                 active="settings",
                 cfg=config,
                 flash={"type": "success", "text": "Saved. Restart to apply."} if saved else None),
        )

    @router.post("/settings")
    async def settings_save(request: Request, session_info=Depends(require_session)):
        form = await request.form()
        _validate_csrf(session_info, str(form.get("csrf_token", "")), session_store)

        updates: dict[str, Any] = {
            "server": {
                "host": str(form.get("server_host", "127.0.0.1")),
                "port": int(form.get("server_port", 8080)),
            },
            "logging": {
                "db_path": str(form.get("logging_db_path", "audit.db")),
                "level": str(form.get("logging_level", "INFO")),
            },
            "approval": {
                "base_url": str(form.get("approval_base_url", "http://localhost:8080")),
                "timeout_seconds": int(form.get("approval_timeout_seconds", 300)),
            },
            "anomaly": {
                "denial_burst_threshold": int(form.get("anomaly_burst_threshold", 5)),
                "denial_burst_window_seconds": int(form.get("anomaly_burst_window", 60)),
                "business_hours_enabled": bool(form.get("anomaly_biz_hours")),
                "business_hours_start": int(form.get("anomaly_biz_start", 9)),
                "business_hours_end": int(form.get("anomaly_biz_end", 18)),
                "business_hours_timezone": str(form.get("anomaly_biz_tz", "UTC")),
            },
        }

        # Vault section — only write if an address is provided
        vault_addr = str(form.get("vault_addr", "")).strip()
        if vault_addr:
            vault_method = str(form.get("vault_auth_method", "token"))
            vault_auth: dict[str, Any] = {"method": vault_method}
            _existing_vault = config.secrets.vault if config.secrets else None
            _existing_auth = _existing_vault.auth if _existing_vault else None
            if vault_method == "token":
                vault_token_form = str(form.get("vault_token", "")).strip()
                vault_auth["token"] = vault_token_form or (
                    _existing_auth.token if _existing_auth and _existing_auth.method == "token" and _existing_auth.token else ""
                )
            elif vault_method == "approle":
                role_id_form = str(form.get("vault_role_id", "")).strip()
                secret_id_form = str(form.get("vault_secret_id", "")).strip()
                vault_auth["role_id"] = role_id_form or (
                    _existing_auth.role_id if _existing_auth and _existing_auth.role_id else ""
                )
                vault_auth["secret_id"] = secret_id_form or (
                    _existing_auth.secret_id if _existing_auth and _existing_auth.secret_id else ""
                )
            elif vault_method in ("aws", "kubernetes", "gcp"):
                vault_auth["role"] = str(form.get("vault_role", ""))
            updates["secrets"] = {
                "vault": {
                    "addr": vault_addr,
                    "kv_mount": str(form.get("vault_kv_mount", "secret")),
                    "kv_version": int(form.get("vault_kv_version", 2)),
                    "tls_verify": bool(form.get("vault_tls_verify", "on")),
                    "path_field_separator": str(form.get("vault_sep", "#")),
                    "auth": vault_auth,
                }
            }

        # Slack
        slack_token = str(form.get("slack_bot_token", "")).strip()
        slack_signing = str(form.get("slack_signing_secret", "")).strip()
        if slack_token or slack_signing:
            existing_slack = config.notifications.slack
            if form.get("store_slack_bot_token_in_vault") and slack_token:
                slack_token = _maybe_store_in_vault(vault_client, "mcp-wrapper/notifications/slack", "bot_token", slack_token)
            elif not slack_token and existing_slack:
                slack_token = existing_slack.bot_token
            if form.get("store_slack_signing_secret_in_vault") and slack_signing:
                slack_signing = _maybe_store_in_vault(vault_client, "mcp-wrapper/notifications/slack", "signing_secret", slack_signing)
            elif not slack_signing and existing_slack:
                slack_signing = existing_slack.signing_secret
            updates["notifications"] = {
                "slack": {
                    "bot_token": slack_token,
                    "channel": str(form.get("slack_channel", "")),
                    "signing_secret": slack_signing,
                }
            }

        # Telegram
        tg_token = str(form.get("telegram_bot_token", "")).strip()
        tg_secret = str(form.get("telegram_secret_token", "")).strip()
        if tg_token or tg_secret:
            existing_tg = config.notifications.telegram
            if form.get("store_telegram_bot_token_in_vault") and tg_token:
                tg_token = _maybe_store_in_vault(vault_client, "mcp-wrapper/notifications/telegram", "bot_token", tg_token)
            elif not tg_token and existing_tg:
                tg_token = existing_tg.bot_token
            if form.get("store_telegram_secret_token_in_vault") and tg_secret:
                tg_secret = _maybe_store_in_vault(vault_client, "mcp-wrapper/notifications/telegram", "secret_token", tg_secret)
            elif not tg_secret and existing_tg:
                tg_secret = existing_tg.secret_token or None
            notifs = updates.get("notifications", {})
            notifs["telegram"] = {
                "bot_token": tg_token,
                "chat_id": str(form.get("telegram_chat_id", "")),
                "secret_token": tg_secret or None,
            }
            updates["notifications"] = notifs

        admin_data = {
            "enabled": config.admin.enabled,
            "username": config.admin.username,
            "password_hash": config.admin.password_hash,
            "session_timeout_hours": config.admin.session_timeout_hours,
        }
        await writer.write_wrapper_toml(updates, admin_data)
        _mark_restart_required()
        return RedirectResponse("/admin/settings?saved=1", status_code=303)

    # ------------------------------------------------------------------
    # OAuth
    # ------------------------------------------------------------------

    @router.get("/oauth/connect/{server_name}")
    async def oauth_connect(request: Request, server_name: str, session_info=Depends(require_session)):
        if server_name not in config.mcp_servers:
            raise HTTPException(404)
        if oauth_manager is None or not oauth_manager.has_oauth(server_name):
            raise HTTPException(400, "No OAuth config for this server")

        base_url = str(request.base_url).rstrip("/")
        redirect_uri = f"{base_url}/admin/oauth/callback"
        try:
            authorize_url, state, code_verifier = oauth_manager.build_authorize_url(
                server_name, redirect_uri
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))

        _oauth_state[state] = {"server_name": server_name, "code_verifier": code_verifier, "expires_at": time.monotonic() + _OAUTH_STATE_TTL}
        return RedirectResponse(authorize_url, status_code=302)

    @router.get("/oauth/callback")
    async def oauth_callback(
        request: Request,
        code: str = "",
        state: str = "",
        error: str = "",
        error_description: str = "",
        session_info=Depends(require_session),
    ):
        if error:
            return templates.TemplateResponse(
                request, "admin/oauth_result.html",
                _ctx(session_info, active="servers",
                     success=False,
                     server_name="",
                     error=error_description or error),
                status_code=400,
            )
        pending = _oauth_state.pop(state, None)
        if not state or pending is None or time.monotonic() > pending.get("expires_at", 0):
            raise HTTPException(400, "Invalid or expired OAuth state")
        server_name = pending["server_name"]
        code_verifier = pending["code_verifier"]

        base_url = str(request.base_url).rstrip("/")
        redirect_uri = f"{base_url}/admin/oauth/callback"
        try:
            await oauth_manager.exchange_code(server_name, code, redirect_uri, code_verifier)
        except Exception as exc:
            return templates.TemplateResponse(
                request, "admin/oauth_result.html",
                _ctx(session_info, active="servers",
                     success=False,
                     server_name=server_name,
                     error=str(exc)),
                status_code=400,
            )

        return templates.TemplateResponse(
            request, "admin/oauth_result.html",
            _ctx(session_info, active="servers",
                 success=True,
                 server_name=server_name,
                 error=None),
        )

    # ------------------------------------------------------------------
    # Gateway tools — credential management
    # ------------------------------------------------------------------

    @router.get("/gateway")
    async def gateway_list(request: Request, session_info=Depends(require_session), saved: str = ""):
        tools = []
        for name, cfg in config.gateway_tools.items():
            tools.append({
                "name": name,
                "type": cfg.type,
                "description": cfg.description,
                "has_credentials": bool(cfg.credentials),
                "credential_count": len(cfg.credentials),
            })
        flash = None
        if saved == "1":
            flash = {"type": "success", "text": "Credentials saved — restart required to apply."}
        elif saved == "live":
            flash = {"type": "success", "text": "Credentials saved and applied."}
        return templates.TemplateResponse(
            request,
            "admin/gateway_list.html",
            _ctx(session_info, active="gateway", tools=tools, flash=flash),
        )

    @router.get("/gateway/{tool_name}/credentials")
    async def gateway_credentials_page(
        request: Request, tool_name: str, session_info=Depends(require_session)
    ):
        if tool_name not in config.gateway_tools:
            raise HTTPException(404)
        cfg = config.gateway_tools[tool_name]
        return templates.TemplateResponse(
            request,
            "admin/gateway_credentials.html",
            _ctx(session_info, active="gateway", tool_name=tool_name, tool=cfg),
        )

    @router.post("/gateway/{tool_name}/credentials")
    async def gateway_credentials_submit(
        request: Request,
        tool_name: str,
        session_info=Depends(require_session),
        csrf_token: str = Form(...),
    ):
        _validate_csrf(session_info, csrf_token, session_store)
        if tool_name not in config.gateway_tools:
            raise HTTPException(404)
        cfg = config.gateway_tools[tool_name]
        form = await request.form()

        updated_creds: dict[str, str] = dict(cfg.credentials)
        for key in cfg.credentials:
            new_val = str(form.get(f"cred_value_{key}", "")).strip()
            store_vault = str(form.get(f"cred_vault_{key}", "")).strip()
            if new_val:
                if store_vault:
                    current_ref = cfg.credentials.get(key, "")
                    if current_ref.startswith("vault:"):
                        # Overwrite the existing vault location, keep the same reference
                        sep = vault_client._sep if vault_client else "#"  # type: ignore[union-attr]
                        parts = current_ref[len("vault:"):].split(sep, 1)
                        if len(parts) == 2:
                            vault_client.write_secret(parts[0], parts[1], new_val)  # type: ignore[union-attr]
                            updated_creds[key] = current_ref
                        else:
                            updated_creds[key] = _maybe_store_in_vault(
                                vault_client, f"mcp-wrapper/gateway/{tool_name}", key, new_val
                            )
                    else:
                        updated_creds[key] = _maybe_store_in_vault(
                            vault_client, f"mcp-wrapper/gateway/{tool_name}", key, new_val
                        )
                else:
                    updated_creds[key] = new_val
            # else: keep existing reference unchanged

        # Serialise gateway tools back to dict and write
        raw: dict[str, Any] = {}
        for name, tool_cfg in config.gateway_tools.items():
            d: dict[str, Any] = {"type": tool_cfg.type}
            if tool_cfg.description:
                d["description"] = tool_cfg.description
            if tool_cfg.path:
                d["path"] = tool_cfg.path
            if tool_cfg.command:
                d["command"] = tool_cfg.command
            if tool_cfg.url:
                d["url"] = tool_cfg.url
            if tool_cfg.method != "POST":
                d["method"] = tool_cfg.method
            if tool_cfg.headers:
                d["headers"] = tool_cfg.headers
            if tool_cfg.schema:
                d["schema"] = tool_cfg.schema
            if tool_cfg.required:
                d["required"] = tool_cfg.required
            if tool_cfg.timeout_seconds != 30.0:
                d["timeout_seconds"] = tool_cfg.timeout_seconds
            if tool_cfg.response_fields:
                d["response_fields"] = tool_cfg.response_fields
            if tool_cfg.max_response_chars:
                d["max_response_chars"] = tool_cfg.max_response_chars
            creds = updated_creds if name == tool_name else dict(tool_cfg.credentials)
            if creds:
                d["credentials"] = creds
            raw[name] = d

        await writer.write_gateway_toml(raw)
        if reload_config:
            await reload_config()
            return RedirectResponse(f"/admin/gateway?saved=live", status_code=303)
        _mark_restart_required()
        return RedirectResponse(f"/admin/gateway?saved=1", status_code=303)

    # ------------------------------------------------------------------
    # Plugin tools — credential management
    # ------------------------------------------------------------------

    @router.get("/plugins")
    async def plugin_list(request: Request, session_info=Depends(require_session), saved: str = ""):
        tools = []
        for name, cfg in config.plugin_tools.items():
            tools.append({
                "name": name,
                "path": cfg.path,
                "has_credentials": bool(cfg.credentials),
                "credential_count": len(cfg.credentials),
            })
        flash = None
        if saved == "1":
            flash = {"type": "success", "text": "Credentials saved — restart required to apply."}
        elif saved == "live":
            flash = {"type": "success", "text": "Credentials saved and applied."}
        return templates.TemplateResponse(
            request,
            "admin/plugin_list.html",
            _ctx(session_info, active="plugins", tools=tools, flash=flash),
        )

    @router.get("/plugins/{tool_name}/credentials")
    async def plugin_credentials_page(
        request: Request, tool_name: str, session_info=Depends(require_session)
    ):
        if tool_name not in config.plugin_tools:
            raise HTTPException(404)
        cfg = config.plugin_tools[tool_name]
        return templates.TemplateResponse(
            request,
            "admin/plugin_credentials.html",
            _ctx(session_info, active="plugins", tool_name=tool_name, tool=cfg),
        )

    @router.post("/plugins/{tool_name}/credentials")
    async def plugin_credentials_submit(
        request: Request,
        tool_name: str,
        session_info=Depends(require_session),
        csrf_token: str = Form(...),
    ):
        _validate_csrf(session_info, csrf_token, session_store)
        if tool_name not in config.plugin_tools:
            raise HTTPException(404)
        cfg = config.plugin_tools[tool_name]
        form = await request.form()

        updated_creds: dict[str, str] = dict(cfg.credentials)
        for key in cfg.credentials:
            new_val = str(form.get(f"cred_value_{key}", "")).strip()
            store_vault = str(form.get(f"cred_vault_{key}", "")).strip()
            if new_val:
                if store_vault:
                    current_ref = cfg.credentials.get(key, "")
                    if current_ref.startswith("vault:"):
                        sep = vault_client._sep if vault_client else "#"  # type: ignore[union-attr]
                        parts = current_ref[len("vault:"):].split(sep, 1)
                        if len(parts) == 2:
                            vault_client.write_secret(parts[0], parts[1], new_val)  # type: ignore[union-attr]
                            updated_creds[key] = current_ref
                        else:
                            updated_creds[key] = _maybe_store_in_vault(
                                vault_client, f"mcp-wrapper/plugins/{tool_name}", key, new_val
                            )
                    else:
                        updated_creds[key] = _maybe_store_in_vault(
                            vault_client, f"mcp-wrapper/plugins/{tool_name}", key, new_val
                        )
                else:
                    updated_creds[key] = new_val

        await writer.write_plugin_credentials(tool_name, updated_creds)
        if reload_config:
            await reload_config()
            return RedirectResponse(f"/admin/plugins?saved=live", status_code=303)
        _mark_restart_required()
        return RedirectResponse(f"/admin/plugins?saved=1", status_code=303)

    # ------------------------------------------------------------------
    # DLP rules
    # ------------------------------------------------------------------

    @router.get("/dlp")
    async def dlp_page(request: Request, session_info=Depends(require_session), saved: str = ""):
        outbound_rows, inbound_rows = _build_dlp_rows(config)
        flash = None
        if saved == "1":
            flash = {"type": "success", "text": "Saved — restart to apply."}
        elif saved == "live":
            flash = {"type": "success", "text": "Applied."}
        return templates.TemplateResponse(
            request, "admin/dlp.html",
            _ctx(session_info, active="dlp", dlp=config.dlp,
                 outbound_rows=outbound_rows, inbound_rows=inbound_rows, flash=flash),
        )

    @router.post("/dlp/settings")
    async def dlp_settings_save(
        request: Request,
        session_info=Depends(require_session),
        csrf_token: str = Form(...),
        dlp_enabled: str = Form(""),
        use_builtin_outbound: str = Form(""),
        use_builtin_inbound: str = Form(""),
    ):
        _validate_csrf(session_info, csrf_token, session_store)
        dlp_data = {
            "enabled": bool(dlp_enabled),
            "use_builtin_outbound": bool(use_builtin_outbound),
            "use_builtin_inbound": bool(use_builtin_inbound),
            "outbound": [p.model_dump() for p in config.dlp.outbound],
            "inbound": [p.model_dump() for p in config.dlp.inbound],
        }
        await writer.write_dlp_config(dlp_data)
        if reload_config:
            await reload_config()
            return RedirectResponse("/admin/dlp?saved=live", status_code=303)
        _mark_restart_required()
        return RedirectResponse("/admin/dlp?saved=1", status_code=303)

    @router.get("/dlp/edit")
    async def dlp_pattern_edit_page(
        request: Request,
        session_info=Depends(require_session),
        name: str = "",
        direction: str = "outbound",
    ):
        direction = direction if direction in ("outbound", "inbound") else "outbound"
        pattern: DlpPattern | None = None
        is_new = not name
        if name:
            customs = config.dlp.outbound if direction == "outbound" else config.dlp.inbound
            pattern = next((p for p in customs if p.name == name), None)
            if pattern is None:
                builtins = OUTBOUND_DEFAULTS if direction == "outbound" else INBOUND_DEFAULTS
                bp = next((p for p in builtins if p.name == name), None)
                if bp:
                    # Pre-fill from built-in so the user can customise
                    pattern = DlpPattern(name=bp.name, pattern=bp.pattern, action=bp.action, enabled=bp.enabled)
                    is_new = True  # creating a new custom override
        return templates.TemplateResponse(
            request, "admin/dlp_pattern.html",
            _ctx(session_info, active="dlp", direction=direction,
                 pattern=pattern, is_new=is_new, error=None),
        )

    @router.post("/dlp/save")
    async def dlp_pattern_save(
        request: Request,
        session_info=Depends(require_session),
        csrf_token: str = Form(...),
        direction: str = Form("outbound"),
        name: str = Form(""),
        pattern: str = Form(""),
        action: str = Form("warn"),
        enabled: str = Form(""),
    ):
        _validate_csrf(session_info, csrf_token, session_store)
        direction = direction if direction in ("outbound", "inbound") else "outbound"
        name = name.strip()
        pattern = pattern.strip()
        action = action if action in ("block", "redact", "warn", "approve") else "warn"
        p = DlpPattern(name=name, pattern=pattern, action=action, enabled=bool(enabled))

        if not name or not pattern:
            return templates.TemplateResponse(
                request, "admin/dlp_pattern.html",
                _ctx(session_info, active="dlp", direction=direction,
                     pattern=p, is_new=True, error="Name and pattern are required."),
                status_code=400,
            )
        try:
            re.compile(pattern)
        except re.error as exc:
            return templates.TemplateResponse(
                request, "admin/dlp_pattern.html",
                _ctx(session_info, active="dlp", direction=direction,
                     pattern=p, is_new=True, error=f"Invalid regex: {exc}"),
                status_code=400,
            )

        if direction == "outbound":
            new_outbound = [x for x in config.dlp.outbound if x.name != name] + [p]
            new_inbound = list(config.dlp.inbound)
        else:
            new_outbound = list(config.dlp.outbound)
            new_inbound = [x for x in config.dlp.inbound if x.name != name] + [p]

        dlp_data = {
            "enabled": config.dlp.enabled,
            "use_builtin_outbound": config.dlp.use_builtin_outbound,
            "use_builtin_inbound": config.dlp.use_builtin_inbound,
            "outbound": [x.model_dump() for x in new_outbound],
            "inbound": [x.model_dump() for x in new_inbound],
        }
        await writer.write_dlp_config(dlp_data)
        if reload_config:
            await reload_config()
            return RedirectResponse("/admin/dlp?saved=live", status_code=303)
        _mark_restart_required()
        return RedirectResponse("/admin/dlp?saved=1", status_code=303)

    @router.post("/dlp/delete")
    async def dlp_pattern_delete(
        request: Request,
        session_info=Depends(require_session),
        csrf_token: str = Form(...),
        name: str = Form(...),
        direction: str = Form("outbound"),
    ):
        _validate_csrf(session_info, csrf_token, session_store)
        direction = direction if direction in ("outbound", "inbound") else "outbound"
        if direction == "outbound":
            new_outbound = [p for p in config.dlp.outbound if p.name != name]
            new_inbound = list(config.dlp.inbound)
        else:
            new_outbound = list(config.dlp.outbound)
            new_inbound = [p for p in config.dlp.inbound if p.name != name]
        dlp_data = {
            "enabled": config.dlp.enabled,
            "use_builtin_outbound": config.dlp.use_builtin_outbound,
            "use_builtin_inbound": config.dlp.use_builtin_inbound,
            "outbound": [p.model_dump() for p in new_outbound],
            "inbound": [p.model_dump() for p in new_inbound],
        }
        await writer.write_dlp_config(dlp_data)
        if reload_config:
            await reload_config()
            return RedirectResponse("/admin/dlp?saved=live", status_code=303)
        _mark_restart_required()
        return RedirectResponse("/admin/dlp?saved=1", status_code=303)

    @router.post("/oauth/disconnect/{server_name}")
    async def oauth_disconnect(
        request: Request,
        server_name: str,
        session_info=Depends(require_session),
        csrf_token: str = Form(...),
    ):
        _validate_csrf(session_info, csrf_token, session_store)
        if oauth_manager:
            await oauth_manager.disconnect(server_name)
        return RedirectResponse("/admin/servers?saved=1", status_code=303)

    @router.post("/oauth/connect/{server_name}/client-credentials")
    async def oauth_fetch_client_credentials(
        request: Request,
        server_name: str,
        session_info=Depends(require_session),
        csrf_token: str = Form(...),
    ):
        """Manually trigger a client_credentials token fetch (useful for testing)."""
        _validate_csrf(session_info, csrf_token, session_store)
        if server_name not in config.mcp_servers:
            raise HTTPException(404)
        if oauth_manager is None or not oauth_manager.has_oauth(server_name):
            raise HTTPException(400, "No OAuth config for this server")
        try:
            await oauth_manager.get_token(server_name)
        except Exception as exc:
            raise HTTPException(400, f"Token fetch failed: {exc}")
        return RedirectResponse("/admin/servers?saved=1", status_code=303)

    return router


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

# ------------------------------------------------------------------
# Rules page helpers
# ------------------------------------------------------------------

async def _fetch_live_tools(url: str, token: str | None, transport: str = "http") -> tuple[list[dict], str | None]:
    """Call tools/list on a downstream MCP server.
    Returns ([{name, param_names}], None) on success, ([], error_message) on failure."""
    try:
        data = await mcp_request(url, token, transport, "tools/list", timeout=10.0)
        tools = []
        for t in data.get("result", {}).get("tools", []):
            param_names = list(t.get("inputSchema", {}).get("properties", {}).keys())
            tools.append({"name": t["name"], "param_names": param_names})
        return tools, None
    except Exception as exc:
        log.warning("Could not fetch live tools from %s: %s", url, exc)
        return [], str(exc)


def _virtual_servers(config: WrapperConfig) -> list[str]:
    result = []
    if config.native_tools:
        result.append(_NATIVE)
    if config.plugin_tools:
        result.append(_PLUGINS)
    return result


def _virtual_live_tools(config: WrapperConfig, server_name: str) -> list[dict]:
    if server_name == _NATIVE:
        return [{"name": t, "param_names": []} for t in config.native_tools]
    if server_name == _PLUGINS:
        return [{"name": t, "param_names": []} for t in config.plugin_tools]
    return []


def _known_tools(config: WrapperConfig, server_name: str) -> list[str]:
    """All exact tool names mentioned in any rules for this server."""
    tools: set[str] = set()
    for rules in [config.server_rules.get(server_name),
                  *[ovr.get(server_name) for ovr in config.agent_overrides.values()]]:
        if rules:
            tools.update(t for t in rules.allow if not any(c in t for c in ("*", "?", "[")))
            tools.update(rules.constrain.keys())
    return sorted(tools)


def _glob_patterns(rules: Any) -> list[str]:
    return [t for t in rules.allow if any(c in t for c in ("*", "?", "["))]


def _constraint_label(tc: Any) -> str:
    parts = []
    if tc.require_approval:
        parts.append("approval")
    if tc.rate_limit:
        if tc.rate_limit.per_minute:
            parts.append(f"{tc.rate_limit.per_minute}/min")
        if tc.rate_limit.per_hour:
            parts.append(f"{tc.rate_limit.per_hour}/hr")
    if tc.allowed_params:
        n = len(tc.allowed_params)
        parts.append(f"{n} param{'s' if n != 1 else ''}")
    if tc.response_jq:
        parts.append("jq")
    if tc.response_grep:
        parts.append("grep")
    return " · ".join(parts)


def _build_agent_rows(config: WrapperConfig) -> list[dict]:
    rows = []
    for agent_id, agent in config.agents.items():
        servers = []
        all_servers = list(agent.mcp_servers) + _virtual_servers(config)
        for server_name in all_servers:
            rules = get_effective_rules(config, agent_id, server_name)
            tool_count = (len(rules.allow) + len(rules.constrain)) if rules else 0
            has_override = (agent_id in config.agent_overrides and
                           server_name in config.agent_overrides[agent_id])
            servers.append({
                "name": server_name,
                "display_name": _VIRTUAL_DISPLAY.get(server_name, server_name),
                "tool_count": tool_count,
                "has_override": has_override,
            })
        rows.append({"agent_id": agent_id, "servers": servers})
    return rows


def _build_server_rows(config: WrapperConfig) -> list[dict]:
    rows = []
    all_server_names = list(config.mcp_servers) + _virtual_servers(config)
    for server_name in all_server_names:
        agents = []
        for agent_id, agent in config.agents.items():
            if server_name in list(agent.mcp_servers) + _virtual_servers(config):
                rules = get_effective_rules(config, agent_id, server_name)
                tool_count = (len(rules.allow) + len(rules.constrain)) if rules else 0
                has_override = (agent_id in config.agent_overrides and
                               server_name in config.agent_overrides[agent_id])
                agents.append({"agent_id": agent_id, "tool_count": tool_count, "has_override": has_override})
        default_rules = config.server_rules.get(server_name)
        default_count = (len(default_rules.allow) + len(default_rules.constrain)) if default_rules else 0
        rows.append({
            "server_name": server_name,
            "display_name": _VIRTUAL_DISPLAY.get(server_name, server_name),
            "agents": agents,
            "default_tool_count": default_count,
        })
    return rows


def _server_tool_list(config: WrapperConfig, server_name: str, active_rules: Any,
                      live_tools: list[dict] | None = None) -> list[dict]:
    """Build the tool list for a checkbox panel, merging rules-known and live-discovered tools."""
    known: set[str] = set(_known_tools(config, server_name))
    live_info: dict[str, list[str]] = {}  # tool_name → param_names from schema
    if live_tools:
        for lt in live_tools:
            known.add(lt["name"])
            live_info[lt["name"]] = lt.get("param_names", [])
    tools = []
    for tool_name in sorted(known):
        checked = (
            active_rules is not None and
            (tool_name in active_rules.constrain or tool_name in active_rules.allow)
        )
        tc = active_rules.constrain.get(tool_name) if active_rules else None
        existing_params = []
        if tc and tc.allowed_params:
            for pname, pc in tc.allowed_params.items():
                existing_params.append({
                    "name": pname,
                    "allowlist": pc.allowlist,
                    "pattern": pc.pattern,
                    "minimum": pc.minimum,
                    "maximum": pc.maximum,
                })
        tools.append({
            "name": tool_name,
            "checked": checked,
            "constraint_label": _constraint_label(tc) if tc else "",
            "require_approval": tc.require_approval if tc else False,
            "per_minute": tc.rate_limit.per_minute if tc and tc.rate_limit else None,
            "per_hour": tc.rate_limit.per_hour if tc and tc.rate_limit else None,
            "response_jq": tc.response_jq if tc else "",
            "response_grep": tc.response_grep if tc else "",
            "param_names": live_info.get(tool_name, []),
            "params": existing_params,
        })
    return tools


async def _build_agent_panel_data(config: WrapperConfig, agent_id: str,
                                   credentials: Any = None) -> list[dict]:
    agent = config.agents[agent_id]
    result = []
    for server_name in list(agent.mcp_servers) + _virtual_servers(config):
        rules = get_effective_rules(config, agent_id, server_name)
        has_override = (agent_id in config.agent_overrides and
                       server_name in config.agent_overrides[agent_id])
        if server_name in _VIRTUAL_DISPLAY:
            live_tools = _virtual_live_tools(config, server_name)
            live_error = None
        else:
            live_tools, live_error = await _fetch_server_tools(config, server_name, credentials)
        result.append({
            "name": server_name,
            "display_name": _VIRTUAL_DISPLAY.get(server_name, server_name),
            "has_override": has_override,
            "tools": _server_tool_list(config, server_name, rules, live_tools),
            "patterns": _glob_patterns(rules) if rules else [],
            "live_error": live_error,
        })
    return result


async def _build_agent_panel_data_from(config: WrapperConfig, agent_id: str,
                                        saved: dict[str, Any],
                                        credentials: Any = None) -> list[dict]:
    """Same as _build_agent_panel_data but uses freshly-saved rules instead of config."""
    agent = config.agents[agent_id]
    result = []
    for server_name in list(agent.mcp_servers) + _virtual_servers(config):
        rules = saved.get(server_name)
        if server_name in _VIRTUAL_DISPLAY:
            live_tools = _virtual_live_tools(config, server_name)
            live_error = None
        else:
            live_tools, live_error = await _fetch_server_tools(config, server_name, credentials)
        result.append({
            "name": server_name,
            "display_name": _VIRTUAL_DISPLAY.get(server_name, server_name),
            "has_override": True,
            "tools": _server_tool_list(config, server_name, rules, live_tools),
            "patterns": _glob_patterns(rules) if rules else [],
            "live_error": live_error,
        })
    return result


async def _build_server_panel_data(config: WrapperConfig, server_name: str,
                                    credentials: Any = None) -> dict:
    default_rules = config.server_rules.get(server_name)
    agents_info = []
    for agent_id, agent in config.agents.items():
        if server_name in list(agent.mcp_servers) + _virtual_servers(config):
            rules = get_effective_rules(config, agent_id, server_name)
            has_override = (agent_id in config.agent_overrides and
                           server_name in config.agent_overrides[agent_id])
            tool_count = (len(rules.allow) + len(rules.constrain)) if rules else 0
            agents_info.append({"agent_id": agent_id, "tool_count": tool_count, "has_override": has_override})
    if server_name in _VIRTUAL_DISPLAY:
        live_tools = _virtual_live_tools(config, server_name)
        live_error = None
    else:
        live_tools, live_error = await _fetch_server_tools(config, server_name, credentials)
    return {
        "agents_info": agents_info,
        "tools": _server_tool_list(config, server_name, default_rules, live_tools),
        "patterns": _glob_patterns(default_rules) if default_rules else [],
        "live_error": live_error,
    }


async def _build_server_panel_data_from(config: WrapperConfig, server_name: str,
                                         saved: Any, credentials: Any = None) -> dict:
    agents_info = []
    for agent_id, agent in config.agents.items():
        if server_name in list(agent.mcp_servers) + _virtual_servers(config):
            has_override = (agent_id in config.agent_overrides and
                           server_name in config.agent_overrides[agent_id])
            tool_count = (len(saved.allow) + len(saved.constrain)) if saved else 0
            agents_info.append({"agent_id": agent_id, "tool_count": tool_count, "has_override": has_override})
    if server_name in _VIRTUAL_DISPLAY:
        live_tools = _virtual_live_tools(config, server_name)
        live_error = None
    else:
        live_tools, live_error = await _fetch_server_tools(config, server_name, credentials)
    return {
        "agents_info": agents_info,
        "tools": _server_tool_list(config, server_name, saved, live_tools),
        "patterns": _glob_patterns(saved) if saved else [],
        "live_error": live_error,
    }


async def _get_credential_token(credentials: Any, server_name: str) -> str | None:
    if credentials is None:
        return None
    try:
        return await credentials.get_token(server_name)
    except Exception:
        return None


def _build_entity_tool_states(rules: Any, name_tools: list[str]) -> dict[str, dict]:
    """For each tool that accepts a 'name' param, return its current allowlist + gate."""
    result = {}
    for tn in name_tools:
        tc = rules.constrain.get(tn) if rules else None
        pc = tc.allowed_params.get("name") if tc else None
        result[tn] = {
            "require_approval": tc.require_approval if tc else False,
            "allowlist": pc.allowlist if pc else None,  # None = unrestricted
        }
    return result


def _build_other_tool_states(rules: Any, other_tools: list[str]) -> dict[str, dict]:
    """For tools without a 'name' param, return their current allow/gate state."""
    import fnmatch as _fnmatch
    result = {}
    for tn in other_tools:
        tc = rules.constrain.get(tn) if rules else None
        allowed = False
        if rules:
            allowed = (tn in rules.constrain or tn in rules.allow or
                       any(_fnmatch.fnmatch(tn, p) for p in rules.allow))
        result[tn] = {
            "allowed": allowed,
            "require_approval": tc.require_approval if tc else False,
        }
    return result


async def _fetch_full_tools(url: str, token: str | None, transport: str = "http") -> tuple[list[dict], str | None]:
    """Fetch complete tool objects (name, description, inputSchema) from a server."""
    try:
        data = await mcp_request(url, token, transport, "tools/list", timeout=10.0)
        return data.get("result", {}).get("tools", []), None
    except Exception as exc:
        log.warning("Could not fetch tools from %s: %s", url, exc)
        return [], str(exc)


async def _call_tool_raw(url: str, token: str | None, tool_name: str, arguments: dict, transport: str = "http") -> tuple[str | None, str | None]:
    """Call a tool on a downstream MCP server and return the first text content."""
    try:
        data = await mcp_request(url, token, transport, "tools/call",
                                 {"name": tool_name, "arguments": arguments}, timeout=15.0)
        for item in data.get("result", {}).get("content", []):
            if item.get("type") == "text":
                return item["text"], None
        return None, None
    except Exception as exc:
        log.warning("Could not call %s on %s: %s", tool_name, url, exc)
        return None, str(exc)


def _extract_tool_info(raw: dict) -> dict:
    """Flatten a raw MCP tool object into a template-friendly dict."""
    params = []
    for pname, pschema in raw.get("inputSchema", {}).get("properties", {}).items():
        enum_vals = pschema.get("enum") or pschema.get("items", {}).get("enum") or []
        params.append({
            "name": pname,
            "type": pschema.get("type", ""),
            "description": pschema.get("description", ""),
            "enum": enum_vals,
        })
    required = set(raw.get("inputSchema", {}).get("required", []))
    for p in params:
        p["required"] = p["name"] in required
    return {
        "name": raw["name"],
        "description": raw.get("description", ""),
        "params": params,
    }


def _parse_live_context(text: str) -> list[dict]:
    """Parse the YAML-like GetLiveContext response into a list of entity dicts."""
    import json as _json
    try:
        inner = _json.loads(text)
        text = inner.get("result", text)
    except Exception:
        pass
    entities: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        if line.startswith("- names:"):
            if current:
                entities.append(current)
            current = {"name": line[8:].strip(), "domain": "", "state": "", "area": ""}
        elif current is not None:
            if line.startswith("  domain:"):
                current["domain"] = line[9:].strip()
            elif line.startswith("  state:"):
                current["state"] = line[8:].strip().strip("'\"")
            elif line.startswith("  areas:"):
                current["area"] = line[8:].strip()
    if current:
        entities.append(current)
    return entities


async def _fetch_server_tools(config: WrapperConfig, server_name: str,
                              credentials: Any) -> tuple[list[dict], str | None]:
    """Fetch live tool names for server_name.
    Returns (tool_names, None) on success, ([], error_message) on failure."""
    server_cfg = config.mcp_servers.get(server_name)
    if server_cfg is None:
        return [], None
    token: str | None = None
    token_error: str | None = None
    if credentials is not None:
        try:
            token = await credentials.get_token(server_name)
        except Exception as exc:
            token_error = str(exc)
    tools, fetch_error = await _fetch_live_tools(server_cfg.url, token, server_cfg.transport)
    error = fetch_error or token_error
    return tools, error


# ------------------------------------------------------------------
# Misc helpers
# ------------------------------------------------------------------

def _tc_from_form(form: Any, server_name: str, tool_name: str, existing: Any) -> ToolConstraint | None:
    """Build a ToolConstraint from submitted form fields for a single tool.
    Returns None if no constraints are set (tool goes into plain allow list)."""
    require_approval = str(form.get(f"{server_name}__constrain__{tool_name}__require_approval", "")) == "1"
    per_min_str = str(form.get(f"{server_name}__constrain__{tool_name}__per_minute", "")).strip()
    per_hr_str = str(form.get(f"{server_name}__constrain__{tool_name}__per_hour", "")).strip()
    per_minute: int | None = int(per_min_str) if per_min_str.isdigit() else None
    per_hour: int | None = int(per_hr_str) if per_hr_str.isdigit() else None

    # Parse param constraints — discover param names by scanning form keys
    param_prefix = f"{server_name}__constrain__{tool_name}__param__"
    _PARAM_SUFFIXES = ("__allowlist", "__pattern", "__minimum", "__maximum")
    param_names_found: set[str] = set()
    for key in form.keys():
        if key.startswith(param_prefix):
            rest = key[len(param_prefix):]
            for suffix in _PARAM_SUFFIXES:
                if rest.endswith(suffix):
                    pname = rest[: -len(suffix)]
                    if pname:
                        param_names_found.add(pname)
                    break

    allowed_params: dict[str, ParamConstraint] = {}
    for pname in param_names_found:
        base = f"{param_prefix}{pname}"
        allowlist_str = str(form.get(f"{base}__allowlist", "")).strip()
        pattern_str = str(form.get(f"{base}__pattern", "")).strip()
        min_str = str(form.get(f"{base}__minimum", "")).strip()
        max_str = str(form.get(f"{base}__maximum", "")).strip()
        allowlist = [v.strip() for v in allowlist_str.split(",") if v.strip()] or None
        pattern = pattern_str or None
        minimum = float(min_str) if min_str else None
        maximum = float(max_str) if max_str else None
        if allowlist or pattern or minimum is not None or maximum is not None:
            allowed_params[pname] = ParamConstraint(
                allowlist=allowlist, pattern=pattern, minimum=minimum, maximum=maximum
            )

    response_jq   = str(form.get(f"{server_name}__constrain__{tool_name}__response_jq",   "")).strip() or None
    response_grep = str(form.get(f"{server_name}__constrain__{tool_name}__response_grep", "")).strip() or None

    if not (require_approval or per_minute is not None or per_hour is not None
            or allowed_params or response_jq or response_grep):
        return None
    rate_limit = RateLimitConfig(per_minute=per_minute, per_hour=per_hour) if (per_minute is not None or per_hour is not None) else None
    return ToolConstraint(require_approval=require_approval, rate_limit=rate_limit,
                          allowed_params=allowed_params, response_jq=response_jq, response_grep=response_grep)


def _validate_csrf(session_info: tuple[str, str], submitted: str, store: AdminSessionStore) -> None:
    session_token, _ = session_info
    if not store.validate_csrf(session_token, submitted):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def _validate_id(value: str) -> None:
    import re
    if not re.match(r"^[a-zA-Z0-9_-]+$", value):
        raise HTTPException(400, "ID must be alphanumeric with hyphens/underscores only")


def _agent_to_dict(agent: Any) -> dict:
    return {
        "token": agent.token,
        "mcp_servers": list(agent.mcp_servers),
        "log_only": agent.log_only,
        "shared_key_action": agent.shared_key_action,
    }


def _server_to_dict(server: Any) -> dict:
    d: dict = {"url": server.url}
    if server.transport != "http":
        d["transport"] = server.transport
    if server.credential:
        d["credential"] = server.credential
    if server.response_fields:
        d["response_fields"] = server.response_fields
    if server.max_response_chars is not None:
        d["max_response_chars"] = server.max_response_chars
    if server.oauth is not None:
        oauth = server.oauth
        od: dict = {
            "grant_type": oauth.grant_type,
            "client_id": oauth.client_id,
            "token_url": oauth.token_url,
        }
        if oauth.client_secret:
            od["client_secret"] = oauth.client_secret
        if oauth.authorize_url:
            od["authorize_url"] = oauth.authorize_url
        if oauth.scopes:
            od["scopes"] = oauth.scopes
        if oauth.user_scopes:
            od["user_scopes"] = oauth.user_scopes
        if oauth.audience:
            od["audience"] = oauth.audience
        if not oauth.pkce:
            od["pkce"] = False
        d["oauth"] = od
    return d


def _toml_literal(s: str) -> str:
    if "'" not in s and "\n" not in s and "\r" not in s:
        return f"'{s}'"
    escaped = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")
    return f'"{escaped}"'


def _constraint_to_toml(tc: ToolConstraint | None) -> str:
    if tc is None:
        return ""
    lines: list[str] = []
    if tc.require_approval:
        lines.append("require_approval = true")
    if tc.response_jq:
        lines.append(f"response_jq = {_toml_literal(tc.response_jq)}")
    if tc.response_grep:
        lines.append(f"response_grep = {_toml_literal(tc.response_grep)}")
    if tc.rate_limit and (tc.rate_limit.per_minute or tc.rate_limit.per_hour):
        lines.append("")
        lines.append("[rate_limit]")
        if tc.rate_limit.per_minute:
            lines.append(f"per_minute = {tc.rate_limit.per_minute}")
        if tc.rate_limit.per_hour:
            lines.append(f"per_hour = {tc.rate_limit.per_hour}")
    for pname, pc in sorted(tc.allowed_params.items()):
        lines.append("")
        lines.append(f"[allowed_params.{pname}]")
        if pc.allowlist:
            vals = ", ".join(f'"{v}"' for v in pc.allowlist)
            lines.append(f"allowlist = [{vals}]")
        if pc.pattern:
            lines.append(f"pattern = {_toml_literal(pc.pattern)}")
        if pc.minimum is not None:
            lines.append(f"minimum = {pc.minimum}")
        if pc.maximum is not None:
            lines.append(f"maximum = {pc.maximum}")
    return "\n".join(lines).strip()


def _toml_to_tc(toml_str: str) -> tuple[ToolConstraint | None, str | None]:
    """Parse a TOML constraint block. Returns (tc, error); tc=None means plain allow."""
    try:
        data = tomllib.loads(toml_str or "")
    except Exception as exc:
        return None, str(exc)
    require_approval = bool(data.get("require_approval", False))
    response_jq   = str(data.get("response_jq",   "")).strip() or None
    response_grep = str(data.get("response_grep",  "")).strip() or None
    rl = data.get("rate_limit") or {}
    per_min = int(rl["per_minute"]) if "per_minute" in rl else None
    per_hr  = int(rl["per_hour"])   if "per_hour"   in rl else None
    rate_limit = RateLimitConfig(per_minute=per_min, per_hour=per_hr) if (per_min or per_hr) else None
    allowed_params: dict[str, ParamConstraint] = {}
    for pname, pdata in (data.get("allowed_params") or {}).items():
        if not isinstance(pdata, dict):
            continue
        allowed_params[pname] = ParamConstraint(
            allowlist=pdata.get("allowlist") or None,
            pattern=str(pdata.get("pattern", "")).strip() or None,
            minimum=float(pdata["minimum"]) if "minimum" in pdata else None,
            maximum=float(pdata["maximum"]) if "maximum" in pdata else None,
        )
    if not any([require_approval, response_jq, response_grep, rate_limit, allowed_params]):
        return None, None
    return ToolConstraint(
        require_approval=require_approval,
        response_jq=response_jq,
        response_grep=response_grep,
        rate_limit=rate_limit,
        allowed_params=allowed_params,
    ), None


def _tc_to_fields(tc: ToolConstraint | None) -> dict:
    if tc is None:
        return {"require_approval": False, "response_jq": "", "response_grep": "",
                "per_minute": "", "per_hour": "", "params": []}
    return {
        "require_approval": tc.require_approval,
        "response_jq":  tc.response_jq  or "",
        "response_grep": tc.response_grep or "",
        "per_minute": tc.rate_limit.per_minute if tc.rate_limit else "",
        "per_hour":   tc.rate_limit.per_hour   if tc.rate_limit else "",
        "params": [
            {"name": pname,
             "allowlist": ", ".join(pc.allowlist) if pc.allowlist else "",
             "pattern":  pc.pattern  or "",
             "minimum":  pc.minimum  if pc.minimum  is not None else "",
             "maximum":  pc.maximum  if pc.maximum  is not None else ""}
            for pname, pc in tc.allowed_params.items()
        ],
    }


def _maybe_store_in_vault(vault_client: VaultClient | None, path: str, field: str, value: str) -> str:
    """Store value in Vault and return a vault: reference, or raise HTTPException on failure."""
    if vault_client is None:
        raise HTTPException(400, "Vault is not configured — cannot store in Vault")
    try:
        vault_client.write_secret(path, field, value)
    except Exception as exc:
        raise HTTPException(500, f"Failed to store secret in Vault: {exc}")
    return vault_client.vault_ref(path, field)


def _build_server_dict(url: str, transport: str, credential: str, response_fields: str, max_response_chars: str) -> dict:
    d: dict = {"url": url}
    if transport and transport != "http":
        d["transport"] = transport
    if credential.strip():
        d["credential"] = credential.strip()
    fields = [f.strip() for f in response_fields.split(",") if f.strip()]
    if fields:
        d["response_fields"] = fields
    if max_response_chars.strip().isdigit():
        d["max_response_chars"] = int(max_response_chars.strip())
    return d


def _build_dlp_rows(config: WrapperConfig) -> tuple[list[dict], list[dict]]:
    """Build merged outbound and inbound pattern rows for the DLP admin page.

    Each row has: name, pattern, action, enabled, source (builtin/override/custom).
    Built-in patterns that have a matching custom entry are shown as "override".
    """
    def merge(builtins: list[DlpPattern], customs: list[DlpPattern]) -> list[dict]:
        builtin_map = {p.name: p for p in builtins}
        custom_map = {p.name: p for p in customs}
        rows: list[dict] = []
        for name, bp in builtin_map.items():
            if name in custom_map:
                cp = custom_map[name]
                rows.append({
                    "name": name, "pattern": cp.pattern, "action": cp.action,
                    "enabled": cp.enabled, "source": "override",
                    "builtin_action": bp.action,
                })
            else:
                rows.append({
                    "name": name, "pattern": bp.pattern, "action": bp.action,
                    "enabled": True, "source": "builtin",
                })
        for name, cp in custom_map.items():
            if name not in builtin_map:
                rows.append({
                    "name": name, "pattern": cp.pattern, "action": cp.action,
                    "enabled": cp.enabled, "source": "custom",
                })
        return rows

    return (
        merge(OUTBOUND_DEFAULTS, config.dlp.outbound),
        merge(INBOUND_DEFAULTS, config.dlp.inbound),
    )
