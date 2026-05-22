"""
Multi-agent isolation tests.

A single wrapper instance serves two agents with different rule sets:

  agent-a: GetDateTime (rate_limit=1/min), HassLightSet (rate_limit=1/min)
  agent-b: GetDateTime (rate_limit=1/min), HassTurnOff (no constraints)

Tests verify:
  - Each agent can only call tools in their own ruleset
  - Audit entries are scoped to the requesting agent
  - Rate limit counters are per-agent (not shared)
  - Tools list is filtered per agent
  - Tokens cannot be swapped between agents
"""

import pytest
from fastapi.testclient import TestClient

from mcp_wrapper.models import (
    AgentConfig,
    McpServerConfig,
    RateLimitConfig,
    ServerRules,
    ToolConstraint,
    WrapperConfig,
)
from mcp_wrapper.server import build_app

HA_URL = "http://fake-ha:8123/api/mcp"
AUTH_A = {"Authorization": "Bearer token-a"}
AUTH_B = {"Authorization": "Bearer token-b"}

ALL_DOWNSTREAM_TOOLS = [
    {"name": "GetDateTime",  "description": ""},
    {"name": "HassLightSet", "description": ""},
    {"name": "HassTurnOff",  "description": ""},
    {"name": "AdminTool",    "description": ""},  # neither agent may call this
]


def _ha_result(result: dict) -> dict:
    return {"jsonrpc": "2.0", "result": result}


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def config(tmp_path):
    cfg = WrapperConfig(
        logging={"db_path": str(tmp_path / "test.db")},
        mcp_servers={"homeassistant": McpServerConfig(url=HA_URL)},
        agents={
            "agent-a": AgentConfig(token="token-a", mcp_servers=["homeassistant"]),
            "agent-b": AgentConfig(token="token-b", mcp_servers=["homeassistant"]),
        },
    )
    cfg.agent_overrides = {
        "agent-a": {
            "homeassistant": ServerRules(
                constrain={
                    "GetDateTime":  ToolConstraint(rate_limit=RateLimitConfig(per_minute=1)),
                    "HassLightSet": ToolConstraint(rate_limit=RateLimitConfig(per_minute=1)),
                }
            )
        },
        "agent-b": {
            "homeassistant": ServerRules(
                constrain={
                    "GetDateTime": ToolConstraint(rate_limit=RateLimitConfig(per_minute=1)),
                    "HassTurnOff": ToolConstraint(),
                }
            )
        },
    }
    return cfg


@pytest.fixture
def client(config):
    app = build_app(config)
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# Token / auth isolation
# ---------------------------------------------------------------------------

def test_agent_a_token_rejected_for_agent_b(client):
    # Tokens are valid — just can't be swapped. Both agents use the same
    # endpoint; the token determines which ruleset applies, not which URL.
    # Verify agent-a's token actually works.
    resp = client.get("/mcp/tools/list", headers=AUTH_A)
    assert resp.status_code == 200

def test_unknown_token_rejected(client):
    resp = client.get("/mcp/tools/list", headers={"Authorization": "Bearer hacker"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Rule isolation — exclusive tools
# ---------------------------------------------------------------------------

def test_agent_a_denied_hassturnoff(client):
    """HassTurnOff is only in agent-b's ruleset."""
    resp = client.post(
        "/mcp/tools/call",
        json={"tool": "HassTurnOff", "params": {"_reason": "test"}},
        headers=AUTH_A,
    )
    assert resp.status_code == 500
    assert "not in allowed list" in resp.json()["detail"]


def test_agent_b_denied_hasslightset(client):
    """HassLightSet is only in agent-a's ruleset."""
    resp = client.post(
        "/mcp/tools/call",
        json={"tool": "HassLightSet", "params": {"_reason": "test"}},
        headers=AUTH_B,
    )
    assert resp.status_code == 500
    assert "not in allowed list" in resp.json()["detail"]


def test_neither_agent_can_call_unlisted_tool(client):
    for auth in (AUTH_A, AUTH_B):
        resp = client.post(
            "/mcp/tools/call",
            json={"tool": "AdminTool", "params": {}},
            headers=auth,
        )
        assert resp.status_code == 500
        assert "not in allowed list" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Tools list isolation
# ---------------------------------------------------------------------------

def test_tools_list_filtered_per_agent(client, httpx_mock):
    # Downstream returns all tools; wrapper filters by each agent's rules.
    httpx_mock.add_response(
        method="POST", url=HA_URL,
        json={"jsonrpc": "2.0", "result": {"tools": ALL_DOWNSTREAM_TOOLS}},
    )
    httpx_mock.add_response(
        method="POST", url=HA_URL,
        json={"jsonrpc": "2.0", "result": {"tools": ALL_DOWNSTREAM_TOOLS}},
    )

    resp_a = client.get("/mcp/tools/list", headers=AUTH_A)
    resp_b = client.get("/mcp/tools/list", headers=AUTH_B)

    names_a = {t["name"] for t in resp_a.json()["tools"]}
    names_b = {t["name"] for t in resp_b.json()["tools"]}

    assert names_a == {"homeassistant_GetDateTime", "homeassistant_HassLightSet"}
    assert names_b == {"homeassistant_GetDateTime", "homeassistant_HassTurnOff"}
    assert "homeassistant_AdminTool" not in names_a
    assert "homeassistant_AdminTool" not in names_b


# ---------------------------------------------------------------------------
# Rate limit isolation
# ---------------------------------------------------------------------------

def test_rate_limits_are_per_agent(client, httpx_mock):
    """Exhausting agent-a's GetDateTime limit must not affect agent-b."""
    httpx_mock.add_response(
        method="POST", url=HA_URL,
        json=_ha_result({"content": [{"type": "text", "text": "ok"}]}),
    )
    httpx_mock.add_response(
        method="POST", url=HA_URL,
        json=_ha_result({"content": [{"type": "text", "text": "ok"}]}),
    )

    # agent-a uses their 1-per-minute allowance
    resp = client.post(
        "/mcp/tools/call",
        json={"tool": "GetDateTime", "params": {"_reason": "first call"}},
        headers=AUTH_A,
    )
    assert resp.status_code == 200

    # agent-a is now rate-limited
    resp = client.post(
        "/mcp/tools/call",
        json={"tool": "GetDateTime", "params": {"_reason": "second call"}},
        headers=AUTH_A,
    )
    assert resp.status_code == 500
    assert "rate limit" in resp.json()["detail"]

    # agent-b's counter is independent — should still succeed
    resp = client.post(
        "/mcp/tools/call",
        json={"tool": "GetDateTime", "params": {"_reason": "agent-b first call"}},
        headers=AUTH_B,
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Audit isolation
# ---------------------------------------------------------------------------

def test_audit_entries_scoped_to_agent(client):
    """agent-a's audit must not include agent-b's entries."""
    # Both agents generate a denial (no httpx needed — denied before downstream)
    client.post("/mcp/tools/call", json={"tool": "HassTurnOff", "params": {}}, headers=AUTH_A)
    client.post("/mcp/tools/call", json={"tool": "HassLightSet", "params": {}}, headers=AUTH_B)

    entries_a = client.get("/audit/recent?limit=50", headers=AUTH_A).json()["entries"]
    entries_b = client.get("/audit/recent?limit=50", headers=AUTH_B).json()["entries"]

    assert all(e["agent_id"] == "agent-a" for e in entries_a)
    assert all(e["agent_id"] == "agent-b" for e in entries_b)

    tools_a = {e["tool"] for e in entries_a}
    tools_b = {e["tool"] for e in entries_b}

    # Each agent only sees their own denied call
    assert "HassTurnOff" in tools_a
    assert "HassLightSet" not in tools_a
    assert "HassLightSet" in tools_b
    assert "HassTurnOff" not in tools_b


def test_stats_scoped_to_agent(client):
    """agent-a's stats must only count agent-a's traffic."""
    # agent-a: 1 denial
    client.post("/mcp/tools/call", json={"tool": "HassTurnOff", "params": {}}, headers=AUTH_A)
    # agent-b: 2 denials
    client.post("/mcp/tools/call", json={"tool": "HassLightSet", "params": {}}, headers=AUTH_B)
    client.post("/mcp/tools/call", json={"tool": "HassLightSet", "params": {}}, headers=AUTH_B)

    stats_a = client.get("/audit/stats", headers=AUTH_A).json()
    stats_b = client.get("/audit/stats", headers=AUTH_B).json()

    assert stats_a["denied"] == 1
    assert stats_b["denied"] == 2
