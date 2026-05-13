from __future__ import annotations

import logging
from typing import Any

import httpx

from .credentials import SecretResolver
from .models import NativeToolConfig, NativeToolCredentialInjection
from .response import shape_response

log = logging.getLogger(__name__)


class NativeToolRegistry:
    VIRTUAL_SERVER_NAME = "__native__"

    def __init__(self, configs: dict[str, NativeToolConfig], resolver: SecretResolver) -> None:
        self._configs = configs
        self._resolver = resolver
        if configs:
            log.info("Native tool registry loaded: %s", list(configs))

    def has_tool(self, tool_name: str) -> bool:
        return tool_name in self._configs

    def get_tool_definition(self, tool_name: str) -> dict[str, Any] | None:
        cfg = self._configs.get(tool_name)
        if cfg is None:
            return None
        return {
            "name": tool_name,
            "description": cfg.description,
            "inputSchema": cfg.input_schema,
        }

    def list_all_definitions(self) -> list[dict[str, Any]]:
        return [self.get_tool_definition(name) for name in self._configs]  # type: ignore[misc]

    async def execute(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        cfg = self._configs[tool_name]

        credential: str | None = None
        if cfg.credential:
            credential = self._resolver.resolve(cfg.credential)

        headers: dict[str, str] = {"Accept": "application/json"}
        query_params: dict[str, Any] = dict(cfg.static_params)
        body: dict[str, Any] | None = None
        url = cfg.url

        if credential:
            if cfg.credential_injection == NativeToolCredentialInjection.bearer:
                headers["Authorization"] = f"Bearer {credential}"
            elif cfg.credential_injection == NativeToolCredentialInjection.header:
                if cfg.credential_header:
                    headers[cfg.credential_header] = credential
            elif cfg.credential_injection == NativeToolCredentialInjection.query:
                if cfg.credential_param:
                    query_params[cfg.credential_param] = credential

        # Strip agent-supplied keys that would override operator-configured static params
        # or credential injection parameters (Findings 1 & 2).
        for k in cfg.static_params:
            arguments.pop(k, None)
        protected_creds: set[str] = {cfg.credential_param, cfg.credential_header} - {None}  # type: ignore[operator]
        for k in protected_creds:
            arguments.pop(k, None)

        if cfg.param_placement == "query":
            query_params.update(arguments)
        elif cfg.param_placement == "json":
            body = arguments
            headers["Content-Type"] = "application/json"
        elif cfg.param_placement == "path":
            url = cfg.url.format(**arguments)

        async with httpx.AsyncClient() as client:
            resp = await client.request(
                method=cfg.method.upper(),
                url=url,
                params=query_params or None,
                json=body,
                headers=headers,
                timeout=cfg.timeout_seconds,
            )
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            if "application/json" in content_type:
                data: Any = resp.json()
            else:
                data = resp.text

        data = shape_response(data, cfg.response_fields, cfg.max_response_chars)
        return {"content": [{"type": "text", "text": str(data)}]}
