import asyncio
import json

import pytest

from mcp_wrapper.approvals import ApprovalManager
from mcp_wrapper.credentials import CredentialBroker, SecretResolver
from mcp_wrapper.dlp import DlpConfig, DlpPattern, DlpScanner
from mcp_wrapper.identity import IdentityResolver
from mcp_wrapper.limiter import RateLimiter
from mcp_wrapper.logger import AuditLogger
from mcp_wrapper.models import (
    AgentConfig,
    McpServerConfig,
    ParamConstraint,
    RateLimitConfig,
    ServerRules,
    Session,
    ToolConstraint,
    WrapperConfig,
)
from mcp_wrapper.proxy import McpProxy, ToolDeniedError

SESSION = Session(agent_id="test-agent")
HA_URL = "http://fake-ha:8123/api/mcp"


def _make_config(server_rules=None, agent_overrides=None, log_only=False) -> WrapperConfig:
    cfg = WrapperConfig(
        mcp_servers={"homeassistant": McpServerConfig(url=HA_URL)},
        agents={
            "test-agent": AgentConfig(
                token="tok",
                mcp_servers=["homeassistant"],
                log_only=log_only,
            )
        },
    )
    cfg.server_rules = server_rules or {}
    cfg.agent_overrides = agent_overrides or {}
    return cfg


def _make_proxy(
    cfg: WrapperConfig,
    audit: AuditLogger,
    timeout: int = 5,
    dlp: DlpScanner | None = None,
) -> tuple[McpProxy, ApprovalManager]:
    resolver = SecretResolver()
    approvals = ApprovalManager(webhook_url=None, base_url="http://localhost:8080", timeout_seconds=timeout)
    proxy = McpProxy(
        cfg,
        IdentityResolver(cfg, resolver),
        audit,
        CredentialBroker(cfg.mcp_servers, resolver),
        RateLimiter(),
        approvals,
        dlp=dlp,
    )
    return proxy, approvals


def _ha_response(result: dict) -> dict:
    return {"jsonrpc": "2.0", "result": result}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def audit(tmp_path):
    al = AuditLogger(db_path=str(tmp_path / "test.db"))
    await al.start()
    yield al
    await al.stop()


@pytest.fixture
async def proxy(audit):
    cfg = _make_config(server_rules={"homeassistant": ServerRules(allow=["GetDateTime"])})
    p, _ = _make_proxy(cfg, audit)
    return p


# ---------------------------------------------------------------------------
# Denial — no HTTP call, all resolved before downstream
# ---------------------------------------------------------------------------

async def test_denied_tool_not_in_ruleset(proxy):
    with pytest.raises(ToolDeniedError, match="not in allowed list"):
        await proxy.call_tool(SESSION, "NotAllowedTool", {})


async def test_denied_no_rules_for_server(audit):
    cfg = _make_config(server_rules={})
    p, _ = _make_proxy(cfg, audit)
    with pytest.raises(ToolDeniedError, match="access not configured"):
        await p.call_tool(SESSION, "GetDateTime", {})


async def test_denied_param_constraint_violation(audit):
    tc = ToolConstraint(allowed_params={"brightness": ParamConstraint(maximum=80)})
    cfg = _make_config(server_rules={"homeassistant": ServerRules(constrain={"HassLightSet": tc})})
    p, _ = _make_proxy(cfg, audit)
    with pytest.raises(ToolDeniedError, match="above maximum"):
        await p.call_tool(SESSION, "HassLightSet", {"brightness": 100})


async def test_denied_rate_limit_exceeded(audit, httpx_mock):
    httpx_mock.add_response(method="POST", url=HA_URL, json=_ha_response({"content": []}))
    tc = ToolConstraint(rate_limit=RateLimitConfig(per_minute=1))
    cfg = _make_config(server_rules={"homeassistant": ServerRules(constrain={"GetDateTime": tc})})
    p, _ = _make_proxy(cfg, audit)

    await p.call_tool(SESSION, "GetDateTime", {})  # first call — allowed

    with pytest.raises(ToolDeniedError, match="rate limit"):
        await p.call_tool(SESSION, "GetDateTime", {})  # second — rate limit hit before httpx


# ---------------------------------------------------------------------------
# Allowed — downstream forwarded
# ---------------------------------------------------------------------------

async def test_allowed_tool_forwarded(proxy, httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url=HA_URL,
        json=_ha_response({"content": [{"type": "text", "text": "2024-01-01"}]}),
    )
    result = await proxy.call_tool(SESSION, "GetDateTime", {})
    assert result == {"content": [{"type": "text", "text": "2024-01-01"}]}


async def test_reason_stripped_before_forwarding(proxy, httpx_mock):
    httpx_mock.add_response(method="POST", url=HA_URL, json=_ha_response({"content": []}))
    await proxy.call_tool(SESSION, "GetDateTime", {"_reason": "testing"})

    forwarded = json.loads(httpx_mock.get_requests()[0].content)
    assert "_reason" not in forwarded["params"]["arguments"]


async def test_log_only_bypasses_enforcement(audit, httpx_mock):
    httpx_mock.add_response(method="POST", url=HA_URL, json=_ha_response({"content": []}))
    cfg = _make_config(
        server_rules={"homeassistant": ServerRules(allow=["GetDateTime"])},
        log_only=True,
    )
    p, _ = _make_proxy(cfg, audit)
    # Tool not in ruleset — allowed in log_only mode
    result = await p.call_tool(SESSION, "AnyToolNotInRules", {})
    assert result is not None


# ---------------------------------------------------------------------------
# Audit — reason recorded
# ---------------------------------------------------------------------------

async def test_reason_recorded_in_audit(audit, httpx_mock, tmp_path):
    httpx_mock.add_response(method="POST", url=HA_URL, json=_ha_response({"content": []}))
    cfg = _make_config(server_rules={"homeassistant": ServerRules(allow=["GetDateTime"])})
    p, _ = _make_proxy(cfg, audit)
    await p.call_tool(SESSION, "GetDateTime", {"_reason": "checking the time"})

    import aiosqlite
    async with aiosqlite.connect(str(tmp_path / "test.db")) as db:
        async with db.execute("SELECT reason FROM audit_log WHERE tool='GetDateTime'") as cur:
            row = await cur.fetchone()
    assert row[0] == "checking the time"


# ---------------------------------------------------------------------------
# Approval gate
# ---------------------------------------------------------------------------

def _make_proxy_with_approvals(
    cfg: WrapperConfig,
    audit: AuditLogger,
    timeout: int = 5,
    dlp: DlpScanner | None = None,
) -> tuple[McpProxy, ApprovalManager]:
    resolver = SecretResolver()
    approvals = ApprovalManager(webhook_url=None, base_url="http://localhost:8080", timeout_seconds=timeout)
    p = McpProxy(
        cfg, IdentityResolver(cfg, resolver), audit,
        CredentialBroker(cfg.mcp_servers, resolver), RateLimiter(), approvals,
        dlp=dlp,
    )
    return p, approvals


async def test_require_approval_approved(audit, httpx_mock):
    httpx_mock.add_response(method="POST", url=HA_URL, json=_ha_response({"content": []}))
    tc = ToolConstraint(require_approval=True)
    cfg = _make_config(server_rules={"homeassistant": ServerRules(constrain={"HassTurnOff": tc})})
    p, approvals = _make_proxy_with_approvals(cfg, audit)

    async def approve_soon():
        await asyncio.sleep(0.05)
        approval_id = next(iter(approvals._pending))
        approvals.resolve(approval_id, approved=True, note="ok")

    asyncio.create_task(approve_soon())
    result = await p.call_tool(SESSION, "HassTurnOff", {"_reason": "test"})
    assert result is not None


async def test_require_approval_denied(audit):
    tc = ToolConstraint(require_approval=True)
    cfg = _make_config(server_rules={"homeassistant": ServerRules(constrain={"HassTurnOff": tc})})
    p, approvals = _make_proxy_with_approvals(cfg, audit)

    async def deny_soon():
        await asyncio.sleep(0.05)
        approval_id = next(iter(approvals._pending))
        approvals.resolve(approval_id, approved=False, note="not allowed")

    asyncio.create_task(deny_soon())
    with pytest.raises(ToolDeniedError, match="approval not granted"):
        await p.call_tool(SESSION, "HassTurnOff", {})


# ---------------------------------------------------------------------------
# DLP — approval gate
# ---------------------------------------------------------------------------

async def test_dlp_outbound_approve_gates_call(audit, httpx_mock):
    """Outbound DLP approve pattern must trigger approval before forwarding."""
    httpx_mock.add_response(method="POST", url=HA_URL, json=_ha_response({"content": []}))
    dlp = DlpScanner(DlpConfig(
        use_builtin_outbound=False,
        outbound=[DlpPattern(name="ssn", pattern=r"\b\d{3}-\d{2}-\d{4}\b", action="approve")],
    ))
    cfg = _make_config(server_rules={"homeassistant": ServerRules(allow=["GetDateTime"])})
    p, approvals = _make_proxy_with_approvals(cfg, audit, dlp=dlp)

    async def approve_soon():
        await asyncio.sleep(0.05)
        approval_id = next(iter(approvals._pending))
        approvals.resolve(approval_id, approved=True, note="ok")

    asyncio.create_task(approve_soon())
    result = await p.call_tool(SESSION, "GetDateTime", {"note": "SSN 123-45-6789"})
    assert result is not None


async def test_dlp_outbound_approve_denied_blocks_call(audit):
    """Denying the DLP outbound approval must prevent the call."""
    dlp = DlpScanner(DlpConfig(
        use_builtin_outbound=False,
        outbound=[DlpPattern(name="ssn", pattern=r"\b\d{3}-\d{2}-\d{4}\b", action="approve")],
    ))
    cfg = _make_config(server_rules={"homeassistant": ServerRules(allow=["GetDateTime"])})
    p, approvals = _make_proxy_with_approvals(cfg, audit, dlp=dlp)

    async def deny_soon():
        await asyncio.sleep(0.05)
        approval_id = next(iter(approvals._pending))
        approvals.resolve(approval_id, approved=False, note="PII not allowed")

    asyncio.create_task(deny_soon())
    with pytest.raises(ToolDeniedError, match="DLP approval not granted"):
        await p.call_tool(SESSION, "GetDateTime", {"note": "SSN 123-45-6789"})


async def test_dlp_inbound_approve_gates_response(audit, httpx_mock):
    """Inbound DLP approve pattern must trigger approval before the response reaches the agent."""
    httpx_mock.add_response(
        method="POST", url=HA_URL,
        json=_ha_response({"content": [{"type": "text", "text": "value: 123-45-6789"}]}),
    )
    dlp = DlpScanner(DlpConfig(
        use_builtin_inbound=False,
        inbound=[DlpPattern(name="ssn", pattern=r"\b\d{3}-\d{2}-\d{4}\b", action="approve")],
    ))
    cfg = _make_config(server_rules={"homeassistant": ServerRules(allow=["GetDateTime"])})
    p, approvals = _make_proxy_with_approvals(cfg, audit, dlp=dlp)

    async def approve_soon():
        await asyncio.sleep(0.05)
        approval_id = next(iter(approvals._pending))
        approvals.resolve(approval_id, approved=True, note="ok")

    asyncio.create_task(approve_soon())
    result = await p.call_tool(SESSION, "GetDateTime", {})
    assert result is not None


async def test_dlp_inbound_approve_denied_blocks_response(audit, httpx_mock):
    """Denying the DLP inbound approval must prevent the response from reaching the agent."""
    httpx_mock.add_response(
        method="POST", url=HA_URL,
        json=_ha_response({"content": [{"type": "text", "text": "value: 123-45-6789"}]}),
    )
    dlp = DlpScanner(DlpConfig(
        use_builtin_inbound=False,
        inbound=[DlpPattern(name="ssn", pattern=r"\b\d{3}-\d{2}-\d{4}\b", action="approve")],
    ))
    cfg = _make_config(server_rules={"homeassistant": ServerRules(allow=["GetDateTime"])})
    p, approvals = _make_proxy_with_approvals(cfg, audit, dlp=dlp)

    async def deny_soon():
        await asyncio.sleep(0.05)
        approval_id = next(iter(approvals._pending))
        approvals.resolve(approval_id, approved=False, note="not approved")

    asyncio.create_task(deny_soon())
    with pytest.raises(ToolDeniedError, match="DLP inbound approval not granted"):
        await p.call_tool(SESSION, "GetDateTime", {})
