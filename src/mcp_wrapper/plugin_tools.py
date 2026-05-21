from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from typing import Any

from .credentials import SecretResolver
from .models import PluginToolConfig
from .response import shape_response

log = logging.getLogger(__name__)


class _LoadedPlugin:
    def __init__(self, name: str, module: Any) -> None:
        self.description: str = module.DESCRIPTION
        self.input_schema: dict[str, Any] = module.INPUT_SCHEMA
        self._execute = module.execute

    async def run(self, arguments: dict[str, Any]) -> Any:
        return await self._execute(arguments)


class PluginRegistry:
    VIRTUAL_SERVER_NAME = "__plugins__"

    def __init__(self, configs: dict[str, PluginToolConfig], resolver: SecretResolver | None = None) -> None:
        self._configs = configs
        self._resolver = resolver
        self._plugins: dict[str, _LoadedPlugin] = {}
        for name, cfg in configs.items():
            try:
                self._plugins[name] = self._load(name, cfg.path)
                log.info("Plugin loaded: %s from %s", name, cfg.path)
            except Exception as exc:
                log.error("Failed to load plugin %r from %r: %s", name, cfg.path, exc)

    @staticmethod
    def _load(name: str, path: str) -> _LoadedPlugin:
        p = Path(path)
        if not p.is_absolute():
            p = Path.cwd() / p
        if not p.exists():
            raise FileNotFoundError(f"Plugin file not found: {p}")
        # Allow plugins to import shared helpers from the same directory
        parent = str(p.parent)
        if parent not in sys.path:
            sys.path.insert(0, parent)
        spec = importlib.util.spec_from_file_location(f"mcp_wrapper_plugin_{name}", p)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot create module spec for {p}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        for attr in ("DESCRIPTION", "INPUT_SCHEMA", "execute"):
            if not hasattr(module, attr):
                raise AttributeError(f"Plugin {name!r} is missing required attribute {attr!r}")
        return _LoadedPlugin(name, module)

    def has_tool(self, tool_name: str) -> bool:
        return tool_name in self._plugins

    def get_tool_definition(self, tool_name: str) -> dict[str, Any] | None:
        plugin = self._plugins.get(tool_name)
        if plugin is None:
            return None
        return {
            "name": tool_name,
            "description": plugin.description,
            "inputSchema": plugin.input_schema,
        }

    def list_all_definitions(self) -> list[dict[str, Any]]:
        return [self.get_tool_definition(name) for name in self._plugins]  # type: ignore[misc]

    def reload(self, new_configs: dict[str, PluginToolConfig]) -> None:
        """Update plugin registry in-place — no restart needed."""
        removed = set(self._configs) - set(new_configs)
        added = set(new_configs) - set(self._configs)
        self._configs.clear()
        self._configs.update(new_configs)
        for name in removed:
            self._plugins.pop(name, None)
        for name in added:
            cfg = new_configs[name]
            try:
                self._plugins[name] = self._load(name, cfg.path)
                log.info("Plugin loaded: %s from %s", name, cfg.path)
            except Exception as exc:
                log.error("Failed to load plugin %r from %r: %s", name, cfg.path, exc)

    async def execute(self, tool_name: str, arguments: dict[str, Any], agent_id: str = "") -> dict[str, Any]:
        plugin = self._plugins[tool_name]
        cfg = self._configs[tool_name]
        injected: dict[str, Any] = {**arguments, "_agent_id": agent_id}
        if self._resolver and cfg.credentials:
            injected["_credentials"] = {
                k: self._resolver.resolve(v) for k, v in cfg.credentials.items()
            }
        raw = await plugin.run(injected)

        if isinstance(raw, dict) and "content" in raw:
            shaped = shape_response(raw, cfg.response_fields, cfg.max_response_chars)
            return shaped if isinstance(shaped, dict) else {"content": [{"type": "text", "text": shaped}]}

        data = shape_response(raw, cfg.response_fields, cfg.max_response_chars)
        return {"content": [{"type": "text", "text": str(data)}]}
