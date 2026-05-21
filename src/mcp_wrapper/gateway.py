from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import sys
from pathlib import Path
from typing import Any

import httpx

from .credentials import SecretResolver
from .models import GatewayToolConfig
from .response import shape_response

log = logging.getLogger(__name__)


class GatewayRegistry:
    """Executes governance-gated tools without an MCP server.

    Supports three backends:
      python — imports a .py file and calls execute(params) -> str | dict
      shell  — runs a shell command; params are passed as JSON on stdin,
               result is read from stdout
      http   — calls an HTTP endpoint with params as the JSON body
    """

    VIRTUAL_SERVER_NAME = "__gateway__"

    def __init__(self, configs: dict[str, GatewayToolConfig], resolver: SecretResolver | None = None) -> None:
        self._configs = configs
        self._resolver = resolver
        self._py_modules: dict[str, Any] = {}
        for name, cfg in configs.items():
            if cfg.type == "python":
                try:
                    self._py_modules[name] = self._load_python(name, cfg.path)  # type: ignore[arg-type]
                    log.info("Gateway python tool loaded: %s from %s", name, cfg.path)
                except Exception as exc:
                    log.error("Failed to load gateway tool %r: %s", name, exc)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def has_tool(self, name: str) -> bool:
        return name in self._configs

    def get_definition(self, name: str) -> dict[str, Any] | None:
        cfg = self._configs.get(name)
        if cfg is None:
            return None
        return {
            "name": name,
            "description": cfg.description,
            "inputSchema": {
                "type": "object",
                "properties": cfg.schema,
                "required": cfg.required,
            },
        }

    def list_all_definitions(self) -> list[dict[str, Any]]:
        return [self.get_definition(n) for n in self._configs]  # type: ignore[misc]

    def reload(self, new_configs: dict[str, GatewayToolConfig]) -> None:
        removed = set(self._configs) - set(new_configs)
        added = set(new_configs) - set(self._configs)
        self._configs.clear()
        self._configs.update(new_configs)
        for name in removed:
            self._py_modules.pop(name, None)
        for name in added:
            cfg = new_configs[name]
            if cfg.type == "python":
                try:
                    self._py_modules[name] = self._load_python(name, cfg.path)  # type: ignore[arg-type]
                except Exception as exc:
                    log.error("Failed to load gateway tool %r: %s", name, exc)

    async def execute(
        self, name: str, params: dict[str, Any], agent_id: str = ""
    ) -> dict[str, Any]:
        cfg = self._configs[name]
        if cfg.type == "python":
            raw = await self._exec_python(name, params, agent_id)
        elif cfg.type == "shell":
            raw = await self._exec_shell(cfg, params)
        elif cfg.type == "http":
            raw = await self._exec_http(cfg, params)
        else:
            raise ValueError(f"Unknown gateway tool type: {cfg.type!r}")

        if isinstance(raw, dict) and "content" in raw:
            shaped = shape_response(raw, cfg.response_fields, cfg.max_response_chars)
            return shaped if isinstance(shaped, dict) else {"content": [{"type": "text", "text": shaped}]}

        data = shape_response(raw, cfg.response_fields, cfg.max_response_chars)
        return {"content": [{"type": "text", "text": str(data)}]}

    # ------------------------------------------------------------------
    # Backends
    # ------------------------------------------------------------------

    @staticmethod
    def _load_python(name: str, path: str) -> Any:
        p = Path(path)
        if not p.is_absolute():
            p = Path.cwd() / p
        if not p.exists():
            raise FileNotFoundError(f"Gateway tool file not found: {p}")
        # Allow tools to import shared helpers from the same directory (e.g. _google_auth.py)
        parent = str(p.parent)
        if parent not in sys.path:
            sys.path.insert(0, parent)
        spec = importlib.util.spec_from_file_location(f"mcp_gateway_{name}", p)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot create module spec for {p}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        if not hasattr(module, "execute"):
            raise AttributeError(f"Gateway tool {name!r} is missing required 'execute' function")
        return module

    async def _exec_python(
        self, name: str, params: dict[str, Any], agent_id: str
    ) -> Any:
        module = self._py_modules.get(name)
        if module is None:
            raise RuntimeError(f"Gateway tool {name!r} failed to load at startup")
        cfg = self._configs[name]
        injected: dict[str, Any] = {**params, "_agent_id": agent_id}
        if self._resolver and cfg.credentials:
            injected["_credentials"] = {
                k: self._resolver.resolve(v) for k, v in cfg.credentials.items()
            }
        result = module.execute(injected)
        if asyncio.iscoroutine(result):
            result = await result
        return result

    async def _exec_shell(
        self, cfg: GatewayToolConfig, params: dict[str, Any]
    ) -> str:
        proc = await asyncio.create_subprocess_shell(
            cfg.command,  # type: ignore[arg-type]
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdin_data = json.dumps(params).encode()
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(stdin_data), timeout=cfg.timeout_seconds
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise RuntimeError(f"Shell tool timed out after {cfg.timeout_seconds}s")

        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            raise RuntimeError(f"Shell tool exited {proc.returncode}: {err}")
        return stdout.decode(errors="replace")

    async def _exec_http(
        self, cfg: GatewayToolConfig, params: dict[str, Any]
    ) -> Any:
        async with httpx.AsyncClient(timeout=cfg.timeout_seconds) as client:
            resp = await client.request(
                method=cfg.method,
                url=cfg.url,  # type: ignore[arg-type]
                json=params,
                headers=cfg.headers,
            )
            resp.raise_for_status()
            try:
                return resp.json()
            except Exception:
                return resp.text
