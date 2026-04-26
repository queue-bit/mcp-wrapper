import pytest

from mcp_wrapper.credentials import SecretResolver
from mcp_wrapper.identity import IdentityResolver
from mcp_wrapper.models import AgentConfig, WrapperConfig


def make_config(token_value: str) -> WrapperConfig:
    return WrapperConfig(
        agents={
            "test-agent": AgentConfig(
                token=token_value,
                mcp_servers=[],
            )
        }
    )


def test_resolve_valid_env_token(monkeypatch):
    monkeypatch.setenv("TEST_TOKEN", "secret123")
    config = make_config("env:TEST_TOKEN")
    resolver = IdentityResolver(config, SecretResolver())
    session = resolver.resolve("secret123")
    assert session is not None
    assert session.agent_id == "test-agent"


def test_resolve_invalid_token(monkeypatch):
    monkeypatch.setenv("TEST_TOKEN", "secret123")
    config = make_config("env:TEST_TOKEN")
    resolver = IdentityResolver(config, SecretResolver())
    session = resolver.resolve("wrongtoken")
    assert session is None


def test_resolve_literal_token():
    config = make_config("mytoken")
    resolver = IdentityResolver(config, SecretResolver())
    session = resolver.resolve("mytoken")
    assert session is not None
    assert session.agent_id == "test-agent"


def test_session_has_unique_id(monkeypatch):
    monkeypatch.setenv("TEST_TOKEN", "abc")
    config = make_config("env:TEST_TOKEN")
    resolver = IdentityResolver(config, SecretResolver())
    s1 = resolver.resolve("abc")
    s2 = resolver.resolve("abc")
    assert s1 is not None and s2 is not None
    assert s1.session_id != s2.session_id
