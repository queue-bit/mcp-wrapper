import pytest
from fastapi.testclient import TestClient

from mcp_wrapper.models import (
    AgentConfig,
    McpServerConfig,
    ServerRules,
    WrapperConfig,
)
from mcp_wrapper.server import build_app

HA_URL = "http://fake-ha:8123/api/mcp"
AUTH = {"Authorization": "Bearer testtoken123"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_TOKEN", "testtoken123")
    return WrapperConfig(
        logging={"db_path": str(tmp_path / "test.db")},
        agents={
            "test-agent": AgentConfig(
                token="env:TEST_TOKEN",
                mcp_servers=[],
            )
        },
    )


@pytest.fixture
def config_with_rules(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_TOKEN", "testtoken123")
    cfg = WrapperConfig(
        logging={"db_path": str(tmp_path / "test.db")},
        mcp_servers={"homeassistant": McpServerConfig(url=HA_URL)},
        agents={
            "test-agent": AgentConfig(
                token="env:TEST_TOKEN",
                mcp_servers=["homeassistant"],
            )
        },
    )
    cfg.server_rules = {"homeassistant": ServerRules(allow=["GetDateTime"])}
    return cfg


@pytest.fixture
def client(config):
    app = build_app(config)
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def client_with_rules(config_with_rules):
    app = build_app(config_with_rules)
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


def _ha_response(result: dict) -> dict:
    return {"jsonrpc": "2.0", "result": result}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_unauthenticated_returns_401(client):
    resp = client.post("/mcp/tools/call", json={"tool": "thing", "params": {}})
    assert resp.status_code == 401


def test_invalid_token_returns_401(client):
    resp = client.post(
        "/mcp/tools/call",
        json={"tool": "thing", "params": {}},
        headers={"Authorization": "Bearer wrongtoken"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Tools list
# ---------------------------------------------------------------------------

def test_list_tools_empty(client):
    resp = client.get("/mcp/tools/list", headers=AUTH)
    assert resp.status_code == 200
    assert resp.json() == {"tools": []}


def test_list_tools_filtered_by_rules(client_with_rules, httpx_mock):
    downstream_tools = [
        {"name": "GetDateTime", "description": ""},
        {"name": "HassTurnOff", "description": ""},  # not in rules
    ]
    httpx_mock.add_response(
        method="POST",
        url=HA_URL,
        json={"jsonrpc": "2.0", "result": {"tools": downstream_tools}},
    )
    resp = client_with_rules.get("/mcp/tools/list", headers=AUTH)
    assert resp.status_code == 200
    names = [t["name"] for t in resp.json()["tools"]]
    assert "homeassistant_GetDateTime" in names
    assert "homeassistant_HassTurnOff" not in names


# ---------------------------------------------------------------------------
# Tool calls — enforcement
# ---------------------------------------------------------------------------

def test_tool_not_in_ruleset_denied(client_with_rules):
    resp = client_with_rules.post(
        "/mcp/tools/call",
        json={"tool": "NotAllowedTool", "params": {}},
        headers=AUTH,
    )
    assert resp.status_code == 500
    assert "not in allowed list" in resp.json()["detail"]


def test_allowed_tool_succeeds(client_with_rules, httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url=HA_URL,
        json=_ha_response({"content": [{"type": "text", "text": "2024-01-01"}]}),
    )
    resp = client_with_rules.post(
        "/mcp/tools/call",
        json={"tool": "GetDateTime", "params": {}},
        headers=AUTH,
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# _reason / _warning
# ---------------------------------------------------------------------------

def test_warning_injected_when_no_reason(client_with_rules, httpx_mock):
    httpx_mock.add_response(
        method="POST", url=HA_URL, json=_ha_response({"content": [{"type": "text", "text": "ok"}]})
    )
    resp = client_with_rules.post(
        "/mcp/tools/call",
        json={"tool": "GetDateTime", "params": {}},
        headers=AUTH,
    )
    assert resp.status_code == 200
    assert "_warning" in resp.json()


def test_no_warning_when_reason_provided(client_with_rules, httpx_mock):
    httpx_mock.add_response(
        method="POST", url=HA_URL, json=_ha_response({"content": [{"type": "text", "text": "ok"}]})
    )
    resp = client_with_rules.post(
        "/mcp/tools/call",
        json={"tool": "GetDateTime", "params": {"_reason": "user asked for time"}},
        headers=AUTH,
    )
    assert resp.status_code == 200
    assert "_warning" not in resp.json()


# ---------------------------------------------------------------------------
# Approval endpoint
# ---------------------------------------------------------------------------

def test_approval_unknown_id_returns_404(client):
    resp = client.post("/approval/nonexistent", json={"approved": True})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def test_audit_log_accessible(client):
    resp = client.get("/audit/recent", headers=AUTH)
    assert resp.status_code == 200
    assert "entries" in resp.json()


def test_audit_filter_by_decision(client_with_rules):
    # Generate a denial
    client_with_rules.post(
        "/mcp/tools/call",
        json={"tool": "NotAllowedTool", "params": {}},
        headers=AUTH,
    )
    resp = client_with_rules.get("/audit/recent?decision=denied", headers=AUTH)
    assert resp.status_code == 200
    entries = resp.json()["entries"]
    assert entries
    assert all(e["decision"] == "denied" for e in entries)


def test_audit_filter_no_results(client_with_rules):
    resp = client_with_rules.get("/audit/recent?since=2099-01-01T00:00:00", headers=AUTH)
    assert resp.status_code == 200
    assert resp.json()["entries"] == []


def test_audit_stats_endpoint(client_with_rules):
    # Generate some traffic first
    client_with_rules.post(
        "/mcp/tools/call",
        json={"tool": "NotAllowedTool", "params": {}},
        headers=AUTH,
    )
    resp = client_with_rules.get("/audit/stats", headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "allowed" in data
    assert "denied" in data
    assert "denial_rate_pct" in data
    assert "top_tools" in data
    assert "by_server" in data
    assert data["denied"] >= 1


def test_audit_stats_requires_auth(client):
    resp = client.get("/audit/stats")
    assert resp.status_code == 401


def test_audit_records_denial(client_with_rules):
    client_with_rules.post(
        "/mcp/tools/call",
        json={"tool": "NotAllowedTool", "params": {}},
        headers=AUTH,
    )
    resp = client_with_rules.get("/audit/recent?limit=5", headers=AUTH)
    entries = resp.json()["entries"]
    denials = [e for e in entries if e["decision"] == "denied"]
    assert denials
    assert denials[0]["tool"] == "NotAllowedTool"
