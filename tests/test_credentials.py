from __future__ import annotations

import os
from unittest.mock import MagicMock, patch, mock_open

import pytest

from mcp_wrapper.credentials import (
    SecretResolver,
    VaultClient,
    _resolve_simple,
)
from mcp_wrapper.models import VaultAuthConfig, VaultConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_vault_config(**auth_kwargs) -> VaultConfig:
    return VaultConfig(
        addr="https://vault.test:8200",
        auth=VaultAuthConfig(**auth_kwargs),
        kv_mount="secret",
        kv_version=2,
        path_field_separator="#",
    )


def mock_hvac_client(is_authenticated=True, secret_data=None):
    client = MagicMock()
    client.is_authenticated.return_value = is_authenticated
    if secret_data is not None:
        client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": secret_data}
        }
    return client


# ---------------------------------------------------------------------------
# _resolve_simple
# ---------------------------------------------------------------------------

def test_resolve_simple_env(monkeypatch):
    monkeypatch.setenv("MY_VAR", "hello")
    assert _resolve_simple("env:MY_VAR") == "hello"


def test_resolve_simple_env_missing(monkeypatch):
    monkeypatch.delenv("MISSING_VAR", raising=False)
    with pytest.raises(RuntimeError, match="not set"):
        _resolve_simple("env:MISSING_VAR")


def test_resolve_simple_literal():
    assert _resolve_simple("plaintext") == "plaintext"


def test_resolve_simple_rejects_vault_ref():
    with pytest.raises(RuntimeError, match="circular"):
        _resolve_simple("vault:some/path#field")


# ---------------------------------------------------------------------------
# SecretResolver — env and literal
# ---------------------------------------------------------------------------

def test_secret_resolver_env(monkeypatch):
    monkeypatch.setenv("TOKEN", "abc123")
    r = SecretResolver()
    assert r.resolve("env:TOKEN") == "abc123"


def test_secret_resolver_literal_warns(caplog):
    r = SecretResolver()
    import logging
    with caplog.at_level(logging.WARNING, logger="mcp_wrapper.credentials"):
        result = r.resolve("plaintext_value")
    assert result == "plaintext_value"
    assert "plaintext" in caplog.text


def test_secret_resolver_vault_without_client():
    r = SecretResolver(vault=None)
    with pytest.raises(RuntimeError, match="no \\[secrets.vault\\] config"):
        r.resolve("vault:some/path#field")


# ---------------------------------------------------------------------------
# SecretResolver — vault references
# ---------------------------------------------------------------------------

def test_secret_resolver_vault_reads_field(monkeypatch):
    cfg = make_vault_config(method="token", token="env:VAULT_TOKEN")
    monkeypatch.setenv("VAULT_TOKEN", "root")

    client_mock = mock_hvac_client(secret_data={"token": "ha-secret-token"})

    with patch("hvac.Client", return_value=client_mock):
        vault = VaultClient(cfg)
        r = SecretResolver(vault=vault)
        assert r.resolve("vault:mcp-wrapper/homeassistant#token") == "ha-secret-token"


def test_secret_resolver_custom_separator(monkeypatch):
    cfg = make_vault_config(method="token", token="env:VAULT_TOKEN")
    cfg = cfg.model_copy(update={"path_field_separator": ":"})
    monkeypatch.setenv("VAULT_TOKEN", "root")

    client_mock = mock_hvac_client(secret_data={"token": "my-token"})

    with patch("hvac.Client", return_value=client_mock):
        vault = VaultClient(cfg)
        r = SecretResolver(vault=vault)
        assert r.resolve("vault:mcp-wrapper/homeassistant:token") == "my-token"


def test_secret_resolver_vault_missing_separator():
    cfg = make_vault_config(method="token", token="literal-token")
    vault = VaultClient(cfg)
    r = SecretResolver(vault=vault)
    with pytest.raises(RuntimeError, match="expected vault"):
        r.resolve("vault:no-separator-here")


def test_secret_resolver_vault_missing_field(monkeypatch):
    cfg = make_vault_config(method="token", token="env:VAULT_TOKEN")
    monkeypatch.setenv("VAULT_TOKEN", "root")

    client_mock = mock_hvac_client(secret_data={"other_field": "value"})

    with patch("hvac.Client", return_value=client_mock):
        vault = VaultClient(cfg)
        r = SecretResolver(vault=vault)
        with pytest.raises(RuntimeError, match="not found"):
            r.resolve("vault:some/path#missing_field")


# ---------------------------------------------------------------------------
# VaultClient — auth methods
# ---------------------------------------------------------------------------

def test_vault_token_auth(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "root-token")
    cfg = make_vault_config(method="token", token="env:VAULT_TOKEN")
    client_mock = mock_hvac_client(secret_data={"key": "val"})

    with patch("hvac.Client", return_value=client_mock) as hvac_cls:
        vc = VaultClient(cfg)
        vc.read_secret("my/path", "key")
        hvac_cls.assert_called_once_with(
            url="https://vault.test:8200", namespace=None, verify=True
        )
        assert client_mock.token == "root-token"


def test_vault_approle_auth(monkeypatch):
    monkeypatch.setenv("ROLE_ID", "role-abc")
    monkeypatch.setenv("SECRET_ID", "secret-xyz")
    cfg = make_vault_config(
        method="approle",
        role_id="env:ROLE_ID",
        secret_id="env:SECRET_ID",
    )
    client_mock = mock_hvac_client(secret_data={"key": "val"})

    with patch("hvac.Client", return_value=client_mock):
        vc = VaultClient(cfg)
        vc.read_secret("my/path", "key")
        client_mock.auth.approle.login.assert_called_once_with(
            role_id="role-abc",
            secret_id="secret-xyz",
            mount_point="approle",
        )


def test_vault_approle_missing_credentials():
    cfg = make_vault_config(method="approle")  # no role_id / secret_id
    with patch("hvac.Client", return_value=mock_hvac_client()):
        vc = VaultClient(cfg)
        with pytest.raises(RuntimeError, match="AppRole auth requires"):
            vc._authenticate()


def test_vault_kubernetes_auth(tmp_path):
    jwt_file = tmp_path / "token"
    jwt_file.write_text("k8s-jwt-token")

    cfg = make_vault_config(
        method="kubernetes",
        role="my-role",
        jwt_path=str(jwt_file),
    )
    client_mock = mock_hvac_client(secret_data={"key": "val"})

    with patch("hvac.Client", return_value=client_mock):
        vc = VaultClient(cfg)
        vc.read_secret("my/path", "key")
        client_mock.auth.kubernetes.login.assert_called_once_with(
            role="my-role",
            jwt="k8s-jwt-token",
            mount_point="kubernetes",
        )


def test_vault_kubernetes_missing_jwt(tmp_path):
    cfg = make_vault_config(
        method="kubernetes",
        role="my-role",
        jwt_path=str(tmp_path / "nonexistent"),
    )
    with patch("hvac.Client", return_value=mock_hvac_client()):
        vc = VaultClient(cfg)
        with pytest.raises(RuntimeError, match="could not read service account JWT"):
            vc._authenticate()


def test_vault_kubernetes_missing_role(tmp_path):
    jwt_file = tmp_path / "token"
    jwt_file.write_text("jwt")
    cfg = make_vault_config(method="kubernetes", jwt_path=str(jwt_file))  # no role
    with patch("hvac.Client", return_value=mock_hvac_client()):
        vc = VaultClient(cfg)
        with pytest.raises(RuntimeError, match="requires.*role"):
            vc._authenticate()


def test_vault_aws_auth():
    cfg = make_vault_config(method="aws", role="my-aws-role")
    client_mock = mock_hvac_client(secret_data={"key": "val"})

    frozen_creds = MagicMock()
    frozen_creds.access_key = "AKIA..."
    frozen_creds.secret_key = "secret"
    frozen_creds.token = None

    boto_session = MagicMock()
    boto_session.get_credentials.return_value.get_frozen_credentials.return_value = frozen_creds

    mock_boto3 = MagicMock()
    mock_boto3.Session.return_value = boto_session

    with patch("hvac.Client", return_value=client_mock), \
         patch.dict("sys.modules", {"boto3": mock_boto3}):
        vc = VaultClient(cfg)
        vc.read_secret("my/path", "key")
        client_mock.auth.aws.iam_login.assert_called_once_with(
            access_key="AKIA...",
            secret_key="secret",
            session_token=None,
            role="my-aws-role",
            mount_point="aws",
        )


def test_vault_aws_missing_boto3():
    cfg = make_vault_config(method="aws", role="my-role")
    client_mock = mock_hvac_client()
    with patch("hvac.Client", return_value=client_mock), \
         patch.dict("sys.modules", {"boto3": None}):
        vc = VaultClient(cfg)
        with pytest.raises(RuntimeError, match="boto3"):
            vc._authenticate()


def _mock_google_modules(mock_creds=None):
    """Return a sys.modules patch dict for google-auth optional dependency.

    The parent mock's attributes are wired explicitly so that attribute access
    like ``google.auth.default`` resolves to the same mock as
    ``sys.modules["google.auth"].default``, regardless of whether Python's
    import machinery sets the attribute on the parent.
    """
    mock_google_auth_transport_requests = MagicMock()
    mock_google_auth_transport = MagicMock()
    mock_google_auth_transport.requests = mock_google_auth_transport_requests

    mock_google_auth = MagicMock()
    mock_google_auth.transport = mock_google_auth_transport
    if mock_creds is not None:
        mock_google_auth.default.return_value = (mock_creds, "my-project")

    mock_google = MagicMock()
    mock_google.auth = mock_google_auth  # wire explicitly — don't rely on import machinery

    return {
        "google": mock_google,
        "google.auth": mock_google_auth,
        "google.auth.transport": mock_google_auth_transport,
        "google.auth.transport.requests": mock_google_auth_transport_requests,
    }


def test_vault_gcp_iam_auth():
    cfg = make_vault_config(method="gcp", role="my-gcp-role", gcp_auth_type="iam")
    client_mock = mock_hvac_client(secret_data={"key": "val"})

    mock_creds = MagicMock()
    mock_creds.token = "gcp-jwt"

    google_mocks = _mock_google_modules(mock_creds)

    with patch("hvac.Client", return_value=client_mock), \
         patch.dict("sys.modules", google_mocks):
        vc = VaultClient(cfg)
        vc.read_secret("my/path", "key")
        client_mock.auth.gcp.login.assert_called_once_with(
            role="my-gcp-role",
            jwt="gcp-jwt",
            mount_point="gcp",
        )


def test_vault_gcp_missing_role():
    cfg = make_vault_config(method="gcp")  # no role
    google_mocks = _mock_google_modules(MagicMock())
    with patch("hvac.Client", return_value=mock_hvac_client()), \
         patch.dict("sys.modules", google_mocks):
        vc = VaultClient(cfg)
        with pytest.raises(RuntimeError, match="requires.*role"):
            vc._authenticate()


# ---------------------------------------------------------------------------
# VaultClient — re-auth on 403
# ---------------------------------------------------------------------------

def test_vault_reauth_on_403(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "root")
    cfg = make_vault_config(method="token", token="env:VAULT_TOKEN")

    call_count = 0

    def read_side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise Exception("403 permission denied")
        return {"data": {"data": {"key": "recovered"}}}

    client_mock = MagicMock()
    client_mock.is_authenticated.return_value = True
    client_mock.secrets.kv.v2.read_secret_version.side_effect = read_side_effect

    with patch("hvac.Client", return_value=client_mock):
        vc = VaultClient(cfg)
        result = vc.read_secret("my/path", "key")
        assert result == "recovered"
        assert call_count == 2


def test_vault_kv_v1(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "root")
    cfg = make_vault_config(method="token", token="env:VAULT_TOKEN")
    cfg = cfg.model_copy(update={"kv_version": 1})

    client_mock = mock_hvac_client()
    client_mock.secrets.kv.v1.read_secret.return_value = {"data": {"key": "v1-value"}}

    with patch("hvac.Client", return_value=client_mock):
        vc = VaultClient(cfg)
        result = vc.read_secret("my/path", "key")
        assert result == "v1-value"
        client_mock.secrets.kv.v1.read_secret.assert_called_once_with(
            path="my/path", mount_point="secret"
        )
