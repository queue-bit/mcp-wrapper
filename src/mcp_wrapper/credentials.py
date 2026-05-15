from __future__ import annotations

"""Credential resolution and broker.

Secret reference prefixes
-------------------------
env:<VAR>                       Read from environment variable.
keyring:<service>:<username>    Read from system keyring (macOS Keychain, libsecret, …).
vault:<path><sep><field>        Read from HashiCorp Vault KV store.
                                <sep> is configured via VaultConfig.path_field_separator
                                (default "#"). Example: vault:mcp-wrapper/ha#token
<literal>                       Bare string — plaintext, dev/testing only. Logs a warning.

VaultClient auth methods
------------------------
token       — static Vault token (env var or keyring)
approle     — role_id + secret_id
aws         — IAM; uses boto3 default credential chain (instance profile, env, ~/.aws)
              requires: pip install mcp-wrapper[vault-aws]
kubernetes  — service account JWT at jwt_path
gcp         — service account IAM JWT via google-auth ADC
              requires: pip install mcp-wrapper[vault-gcp]
              set gcp_auth_type = "gce" to use GCE instance identity instead
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    import hvac

from .models import OAuthConfig, VaultConfig

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_AUTH_METHOD_DEFAULTS: dict[str, str] = {
    "approle": "approle",
    "aws": "aws",
    "kubernetes": "kubernetes",
    "gcp": "gcp",
}


def _resolve_simple(value: str) -> str:
    """Resolve env: and keyring: references only.

    Used internally by VaultClient to resolve its own auth credentials —
    using vault: here would create a circular dependency.
    """
    if value.startswith("env:"):
        var = value[4:]
        secret = os.environ.get(var)
        if secret is None:
            raise RuntimeError(f"Environment variable {var!r} not set")
        return secret

    if value.startswith("keyring:"):
        try:
            import keyring
        except ImportError:
            raise RuntimeError(
                "keyring: reference used but 'keyring' is not installed. "
                "Run: pip install keyring"
            )
        _, service, username = value.split(":", 2)
        secret = keyring.get_password(service, username)
        if secret is None:
            raise RuntimeError(
                f"No keyring entry for service={service!r} username={username!r}"
            )
        return secret

    if value.startswith("vault:"):
        raise RuntimeError(
            "vault: references cannot be used for Vault's own auth credentials "
            "(that would be circular). Use env: or keyring: instead."
        )

    return value


# ---------------------------------------------------------------------------
# VaultClient
# ---------------------------------------------------------------------------

class VaultClient:
    """Wraps hvac.Client with lazy authentication and automatic re-auth on 403."""

    def __init__(self, config: VaultConfig) -> None:
        self._config = config
        self._client: hvac.Client | None = None

    # ------------------------------------------------------------------
    # Auth methods
    # ------------------------------------------------------------------

    def _authenticate(self) -> hvac.Client:
        try:
            import hvac as _hvac
        except ImportError:
            raise RuntimeError(
                "hvac is required for Vault integration. Run: pip install hvac"
            )

        cfg = self._config
        client = _hvac.Client(
            url=cfg.addr,
            namespace=cfg.namespace or None,
            verify=cfg.tls_verify,
        )

        method = cfg.auth.method
        mount = cfg.auth.mount or _AUTH_METHOD_DEFAULTS.get(method, method)

        if method == "token":
            if cfg.auth.token is None:
                raise RuntimeError(
                    "Vault token auth requires [secrets.vault.auth] token = \"env:VAULT_TOKEN\""
                )
            client.token = _resolve_simple(cfg.auth.token)

        elif method == "approle":
            if cfg.auth.role_id is None or cfg.auth.secret_id is None:
                raise RuntimeError(
                    "Vault AppRole auth requires role_id and secret_id in [secrets.vault.auth]"
                )
            role_id = _resolve_simple(cfg.auth.role_id)
            secret_id = _resolve_simple(cfg.auth.secret_id)
            client.auth.approle.login(
                role_id=role_id,
                secret_id=secret_id,
                mount_point=mount,
            )

        elif method == "aws":
            self._auth_aws(client, mount)

        elif method == "kubernetes":
            self._auth_kubernetes(client, mount)

        elif method == "gcp":
            self._auth_gcp(client, mount)

        else:
            raise RuntimeError(f"Unsupported Vault auth method: {method!r}")

        if not client.is_authenticated():
            raise RuntimeError(
                f"Vault authentication failed (method={method!r}, addr={cfg.addr!r})"
            )

        log.info("Authenticated with Vault (method=%s, addr=%s)", method, cfg.addr)
        return client

    def _auth_aws(self, client: hvac.Client, mount: str) -> None:
        try:
            import boto3
        except ImportError:
            raise RuntimeError(
                "AWS IAM auth requires boto3. Run: pip install mcp-wrapper[vault-aws]"
            )

        role = self._config.auth.role
        session = boto3.Session()
        creds = session.get_credentials()
        if creds is None:
            raise RuntimeError(
                "No AWS credentials found. Configure an instance profile, "
                "IRSA, or environment variables (AWS_ACCESS_KEY_ID etc.)."
            )
        frozen = creds.get_frozen_credentials()
        client.auth.aws.iam_login(
            access_key=frozen.access_key,
            secret_key=frozen.secret_key,
            session_token=frozen.token,
            role=role,
            mount_point=mount,
        )

    def _auth_kubernetes(self, client: hvac.Client, mount: str) -> None:
        jwt_path = self._config.auth.jwt_path
        try:
            with open(jwt_path) as f:
                jwt = f.read().strip()
        except OSError as e:
            raise RuntimeError(
                f"Kubernetes auth: could not read service account JWT from {jwt_path!r}: {e}"
            )
        role = self._config.auth.role
        if role is None:
            raise RuntimeError(
                "Kubernetes auth requires [secrets.vault.auth] role = \"<vault-role-name>\""
            )
        client.auth.kubernetes.login(
            role=role,
            jwt=jwt,
            mount_point=mount,
        )

    def _auth_gcp(self, client: hvac.Client, mount: str) -> None:
        try:
            import google.auth
            import google.auth.transport.requests
        except ImportError:
            raise RuntimeError(
                "GCP auth requires google-auth. Run: pip install mcp-wrapper[vault-gcp]"
            )

        role = self._config.auth.role
        if role is None:
            raise RuntimeError(
                "GCP auth requires [secrets.vault.auth] role = \"<vault-role-name>\""
            )

        auth_type = self._config.auth.gcp_auth_type

        if auth_type == "gce":
            # GCE instance identity token from metadata server
            import urllib.request
            metadata_url = (
                "http://metadata.google.internal/computeMetadata/v1/instance/"
                f"service-accounts/default/identity?audience={self._config.addr}"
                f"/vault/{role}&format=full"
            )
            req = urllib.request.Request(
                metadata_url, headers={"Metadata-Flavor": "Google"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                jwt = resp.read().decode()
        else:
            # IAM — sign a JWT using google-auth ADC
            credentials, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            auth_req = google.auth.transport.requests.Request()
            credentials.refresh(auth_req)
            jwt = credentials.token

        client.auth.gcp.login(role=role, jwt=jwt, mount_point=mount)

    # ------------------------------------------------------------------
    # Secret reading
    # ------------------------------------------------------------------

    def _get_client(self) -> hvac.Client:
        if self._client is not None and self._client.is_authenticated():
            return self._client
        self._client = self._authenticate()
        return self._client

    def read_secret(self, path: str, field: str) -> str:
        """Read a single field from a KV secret, re-authing once on 403."""
        for attempt in range(2):
            client = self._get_client()
            try:
                return self._read_field(client, path, field)
            except Exception as e:
                err_str = str(e)
                is_auth_error = "403" in err_str or "permission denied" in err_str.lower()
                if is_auth_error and attempt == 0:
                    log.warning("Vault returned 403 — re-authenticating")
                    self._client = None
                    continue
                raise RuntimeError(
                    f"Failed to read Vault secret path={path!r} field={field!r}: {e}"
                ) from e
        raise RuntimeError("Vault re-authentication did not resolve the 403")  # pragma: no cover

    def _read_field(self, client: hvac.Client, path: str, field: str) -> str:
        cfg = self._config
        if cfg.kv_version == 2:
            response = client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=cfg.kv_mount
            )
            data: dict = response["data"]["data"]
        else:
            response = client.secrets.kv.v1.read_secret(
                path=path, mount_point=cfg.kv_mount
            )
            data = response["data"]

        if field not in data:
            raise RuntimeError(
                f"Field {field!r} not found in Vault secret at {path!r}. "
                f"Available fields: {list(data.keys())}"
            )
        return str(data[field])


# ---------------------------------------------------------------------------
# SecretResolver — public interface for the rest of the codebase
# ---------------------------------------------------------------------------

class SecretResolver:
    """Resolves secret references from any configured backend.

    Accepts an optional VaultClient. If no vault client is provided,
    vault: references will raise a RuntimeError.
    """

    def __init__(self, vault: VaultClient | None = None) -> None:
        self._vault = vault

    def resolve(self, value: str) -> str:
        if value.startswith("env:"):
            var = value[4:]
            secret = os.environ.get(var)
            if secret is None:
                raise RuntimeError(f"Environment variable {var!r} not set")
            return secret

        if value.startswith("keyring:"):
            try:
                import keyring
            except ImportError:
                raise RuntimeError(
                    "keyring: reference used but 'keyring' is not installed. "
                    "Run: pip install keyring"
                )
            _, service, username = value.split(":", 2)
            secret = keyring.get_password(service, username)
            if secret is None:
                raise RuntimeError(
                    f"No keyring entry for service={service!r} username={username!r}"
                )
            return secret

        if value.startswith("vault:"):
            if self._vault is None:
                raise RuntimeError(
                    "vault: reference used but no [secrets.vault] config is present in wrapper.toml"
                )
            remainder = value[6:]
            sep = self._vault._config.path_field_separator
            idx = remainder.rfind(sep)
            if idx == -1:
                raise RuntimeError(
                    f"Invalid vault: reference {value!r} — "
                    f"expected vault:<path>{sep}<field> "
                    f"(separator configured as {sep!r})"
                )
            path, field = remainder[:idx], remainder[idx + len(sep):]
            return self._vault.read_secret(path, field)

        log.warning(
            "Secret value used as literal plaintext — "
            "use env:, keyring:, or vault: prefix in production"
        )
        return value


# ---------------------------------------------------------------------------
# OAuthTokenStore — file-backed token persistence
# ---------------------------------------------------------------------------

class OAuthTokenStore:
    """Persist OAuth tokens to a JSON file so they survive restarts."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = asyncio.Lock()
        self._tokens: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                with open(self._path) as f:
                    self._tokens = json.load(f)
            except Exception as exc:
                log.warning("Could not load OAuth token store from %s: %s", self._path, exc)

    def _write(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Write atomically: temp file → rename, then restrict permissions.
        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(self._tokens, f, indent=2)
        os.chmod(tmp, 0o600)
        tmp.replace(self._path)

    async def save(self, server_name: str, token_data: dict) -> None:
        async with self._lock:
            self._tokens[server_name] = token_data
            self._write()

    def get(self, server_name: str) -> dict | None:
        return self._tokens.get(server_name)

    async def delete(self, server_name: str) -> None:
        async with self._lock:
            self._tokens.pop(server_name, None)
            self._write()


# ---------------------------------------------------------------------------
# OAuthTokenManager — token lifecycle: fetch, refresh, PKCE
# ---------------------------------------------------------------------------

class OAuthTokenManager:
    """Manages OAuth token lifecycle for MCP servers configured with oauth."""

    def __init__(self, server_configs: dict, resolver: SecretResolver, store: OAuthTokenStore) -> None:
        self._configs = server_configs
        self._resolver = resolver
        self._store = store

    def has_oauth(self, server_name: str) -> bool:
        cfg = self._configs.get(server_name)
        return cfg is not None and cfg.oauth is not None

    def get_connection_status(self, server_name: str) -> str:
        """Return 'connected', 'expired', or 'disconnected'."""
        if not self.has_oauth(server_name):
            return "not_configured"
        token_data = self._store.get(server_name)
        if token_data is None:
            return "disconnected"
        expires_at = token_data.get("expires_at")
        if expires_at and datetime.fromtimestamp(expires_at, tz=timezone.utc) < datetime.now(timezone.utc):
            return "expired"
        return "connected"

    async def get_token(self, server_name: str) -> str | None:
        """Return a valid access token, refreshing or re-fetching as needed."""
        cfg = self._configs.get(server_name)
        if cfg is None or cfg.oauth is None:
            return None

        token_data = self._store.get(server_name)

        # Still valid (60 s buffer)
        if token_data:
            expires_at = token_data.get("expires_at")
            if expires_at is None or (
                datetime.fromtimestamp(expires_at, tz=timezone.utc)
                > datetime.now(timezone.utc) + timedelta(seconds=60)
            ):
                return token_data["access_token"]

        # Try refresh token first
        if token_data and token_data.get("refresh_token"):
            try:
                return await self._refresh_token(server_name, cfg.oauth, token_data["refresh_token"])
            except Exception as exc:
                log.warning("OAuth refresh failed for %s: %s", server_name, exc)

        # Client credentials: auto-fetch (no user interaction needed)
        if cfg.oauth.grant_type == "client_credentials":
            return await self._fetch_client_credentials(server_name, cfg.oauth)

        # Authorization code: must wait for user to connect via /admin/oauth/connect
        return None

    async def _fetch_client_credentials(self, server_name: str, oauth: OAuthConfig) -> str:
        data: dict = {
            "grant_type": "client_credentials",
            "client_id": oauth.client_id,
        }
        if oauth.client_secret:
            data["client_secret"] = self._resolver.resolve(oauth.client_secret)
        if oauth.scopes:
            data["scope"] = " ".join(oauth.scopes)
        if oauth.audience:
            data["audience"] = oauth.audience

        async with httpx.AsyncClient() as client:
            resp = await client.post(oauth.token_url, data=data, timeout=10.0)
            resp.raise_for_status()

        return await self._store_token(server_name, resp.json())

    async def _refresh_token(self, server_name: str, oauth: OAuthConfig, refresh_token: str) -> str:
        data: dict = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": oauth.client_id,
        }
        if oauth.client_secret:
            data["client_secret"] = self._resolver.resolve(oauth.client_secret)

        async with httpx.AsyncClient() as client:
            resp = await client.post(oauth.token_url, data=data, timeout=10.0)
            resp.raise_for_status()

        token_response = resp.json()
        # Some providers don't re-issue a refresh token — keep the old one
        if "refresh_token" not in token_response and refresh_token:
            token_response["refresh_token"] = refresh_token
        return await self._store_token(server_name, token_response)

    async def _store_token(self, server_name: str, token_response: dict) -> str:
        # Slack's oauth.v2.access buries the user token at authed_user.access_token.
        # The top-level access_token is the bot token (xoxb-), which most MCP
        # servers reject. Prefer the user token when present.
        authed_user = token_response.get("authed_user", {})
        access_token = authed_user.get("access_token") or token_response["access_token"]
        refresh_token = authed_user.get("refresh_token") or token_response.get("refresh_token")

        expires_in_raw = token_response.get("expires_in")
        expires_at = (
            (datetime.now(timezone.utc) + timedelta(seconds=int(expires_in_raw))).timestamp()
            if expires_in_raw is not None
            else None  # provider (e.g. Slack) issues non-expiring tokens
        )
        token_data = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": expires_at,
        }
        await self._store.save(server_name, token_data)
        return token_data["access_token"]

    def build_authorize_url(self, server_name: str, redirect_uri: str) -> tuple[str, str, str]:
        """Return (full authorize URL, state token, code_verifier).

        code_verifier is empty string when PKCE is disabled.
        """
        cfg = self._configs.get(server_name)
        if cfg is None or cfg.oauth is None:
            raise ValueError(f"No OAuth config for server {server_name!r}")
        oauth = cfg.oauth
        if oauth.grant_type != "authorization_code":
            raise ValueError(f"Server {server_name!r} uses client_credentials, not authorization_code")
        if not oauth.authorize_url:
            raise ValueError(f"Server {server_name!r} has no authorize_url configured")

        state = secrets.token_urlsafe(32)
        params: dict[str, str] = {
            "response_type": "code",
            "client_id": oauth.client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
        if oauth.scopes:
            params["scope"] = " ".join(oauth.scopes)
        if oauth.user_scopes:
            params["user_scope"] = " ".join(oauth.user_scopes)
        if oauth.audience:
            params["audience"] = oauth.audience

        code_verifier = ""
        if oauth.pkce:
            code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).rstrip(b"=").decode()
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        full_url = oauth.authorize_url + "?" + urllib.parse.urlencode(params)
        return full_url, state, code_verifier

    async def exchange_code(
        self, server_name: str, code: str, redirect_uri: str, code_verifier: str
    ) -> None:
        """Exchange an authorization code for tokens and persist them."""
        cfg = self._configs.get(server_name)
        if cfg is None or cfg.oauth is None:
            raise ValueError(f"No OAuth config for server {server_name!r}")
        oauth = cfg.oauth

        data: dict = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": oauth.client_id,
        }
        if oauth.client_secret:
            data["client_secret"] = self._resolver.resolve(oauth.client_secret)
        if code_verifier:
            data["code_verifier"] = code_verifier

        log.info("OAuth exchange for %s: url=%s redirect_uri=%s pkce=%s",
                 server_name, oauth.token_url, redirect_uri, bool(code_verifier))
        async with httpx.AsyncClient() as client:
            resp = await client.post(oauth.token_url, data=data, timeout=10.0)
            resp.raise_for_status()

        token_response = resp.json()
        if token_response.get("ok") is False:
            error = token_response.get("error", "unknown_error")
            log.error("OAuth token exchange failed for %s: %s — sent redirect_uri=%s — full response: %s",
                      server_name, error, redirect_uri, token_response)
            raise ValueError(f"Slack OAuth error: {error}")

        await self._store_token(server_name, token_response)

    async def disconnect(self, server_name: str) -> None:
        await self._store.delete(server_name)


# ---------------------------------------------------------------------------
# CredentialBroker
# ---------------------------------------------------------------------------

class CredentialBroker:
    """Retrieves and injects credentials for outbound MCP server calls."""

    def __init__(
        self,
        server_configs: dict,
        resolver: SecretResolver,
        oauth_manager: OAuthTokenManager | None = None,
    ) -> None:
        self._configs = server_configs
        self._resolver = resolver
        self._oauth = oauth_manager

    async def get_token(self, server_name: str) -> str | None:
        """Return the resolved bearer token for a named MCP server, or None."""
        if self._oauth and self._oauth.has_oauth(server_name):
            try:
                return await self._oauth.get_token(server_name)
            except Exception as exc:
                log.warning("OAuth token fetch failed for %s: %s", server_name, exc)
                return None

        cfg = self._configs.get(server_name)
        if cfg is None or cfg.credential is None:
            return None
        token = self._resolver.resolve(cfg.credential)
        log.debug("credential_accessed: server=%s", server_name)
        return token
