import os
import pytest
from fastapi.testclient import TestClient

from mcp_wrapper.models import AgentConfig, McpServerConfig, WrapperConfig
from mcp_wrapper.server import build_app


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
def client(config):
    app = build_app(config)
    # Use lifespan in TestClient
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_unauthenticated_call_tool(client):
    resp = client.post("/mcp/tools/call", json={"tool": "test.thing", "params": {}})
    assert resp.status_code == 401


def test_invalid_token(client):
    resp = client.post(
        "/mcp/tools/call",
        json={"tool": "test.thing", "params": {}},
        headers={"Authorization": "Bearer wrongtoken"},
    )
    assert resp.status_code == 401


def test_authenticated_list_tools(client):
    resp = client.get(
        "/mcp/tools/list",
        headers={"Authorization": "Bearer testtoken123"},
    )
    # No servers configured, should return empty tool list
    assert resp.status_code == 200
    assert resp.json() == {"tools": []}


def test_audit_log_accessible(client):
    resp = client.get(
        "/audit/recent",
        headers={"Authorization": "Bearer testtoken123"},
    )
    assert resp.status_code == 200
    assert "entries" in resp.json()
