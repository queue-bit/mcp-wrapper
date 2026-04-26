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

import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import hvac

from .models import VaultConfig

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
# CredentialBroker
# ---------------------------------------------------------------------------

class CredentialBroker:
    """Retrieves and injects credentials for outbound MCP server calls."""

    def __init__(self, server_configs: dict, resolver: SecretResolver) -> None:
        self._configs = server_configs
        self._resolver = resolver

    def get_token(self, server_name: str) -> str | None:
        """Return the resolved bearer token for a named MCP server, or None."""
        cfg = self._configs.get(server_name)
        if cfg is None or cfg.credential is None:
            return None
        token = self._resolver.resolve(cfg.credential)
        log.debug("credential_accessed: server=%s", server_name)
        return token
