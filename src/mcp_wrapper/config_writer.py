from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]

import tomli_w


class ConfigWriter:
    """Writes mcp-wrapper TOML config files.

    Each write_* method handles one config file. Structured sections use
    tomli_w for serialisation; rules files are written as raw text.

    An asyncio.Lock serialises concurrent writes from multiple admin sessions.
    """

    def __init__(self, config_dir: str | Path) -> None:
        self._dir = Path(config_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    def _read_existing(self, filename: str) -> dict[str, Any]:
        path = self._dir / filename
        if not path.exists():
            return {}
        with open(path, "rb") as f:
            return tomllib.load(f)

    def _write(self, filename: str, data: dict[str, Any]) -> None:
        path = self._dir / filename
        with open(path, "wb") as f:
            tomli_w.dump(data, f)

    async def write_wrapper_toml(self, updates: dict[str, Any], admin_data: dict[str, Any]) -> None:
        """Merge updates into wrapper.toml and always preserve the [admin] section."""
        async with self._lock:
            existing = self._read_existing("wrapper.toml")
            existing.update(updates)
            existing["admin"] = admin_data
            self._write("wrapper.toml", existing)

    async def write_agents_toml(self, agents: dict[str, Any]) -> None:
        async with self._lock:
            self._write("agents.toml", {"agents": agents})

    async def write_mcp_servers_toml(self, servers: dict[str, Any]) -> None:
        async with self._lock:
            self._write("mcp-servers.toml", {"mcp_servers": servers})

    async def write_native_tools_toml(self, tools: dict[str, Any]) -> None:
        async with self._lock:
            self._write("native-tools.toml", {"native_tools": tools})

    async def write_plugins_toml(self, plugins: dict[str, Any]) -> None:
        async with self._lock:
            self._write("plugins.toml", {"plugin_tools": plugins})

    async def write_plugin_credentials(self, tool_name: str, credentials: dict[str, str]) -> None:
        """Update the credentials dict for a single plugin tool in plugins.toml."""
        async with self._lock:
            existing = self._read_existing("plugins.toml")
            tools = existing.get("plugin_tools", {})
            if tool_name in tools:
                tools[tool_name]["credentials"] = credentials
            self._write("plugins.toml", {"plugin_tools": tools})

    async def write_gateway_toml(self, tools: dict[str, Any]) -> None:
        async with self._lock:
            self._write("gateway.toml", {"gateway_tools": tools})

    # ------------------------------------------------------------------
    # Structured rules writers
    # ------------------------------------------------------------------

    @staticmethod
    def _rules_to_toml(rules: Any) -> dict[str, Any]:
        """Convert a ServerRules object to a TOML-serialisable dict."""
        d: dict[str, Any] = {}
        if rules.allow:
            d["allow"] = list(rules.allow)
        if rules.constrain:
            constrain: dict[str, Any] = {}
            for tool_name, tc in rules.constrain.items():
                tc_dict: dict[str, Any] = {}
                if tc.require_approval:
                    tc_dict["require_approval"] = True
                if tc.rate_limit:
                    rl = {k: v for k, v in tc.rate_limit.model_dump().items() if v is not None}
                    if rl:
                        tc_dict["rate_limit"] = rl
                if tc.allowed_params:
                    ap: dict[str, Any] = {}
                    for pname, pc in tc.allowed_params.items():
                        pc_d = {k: v for k, v in pc.model_dump().items() if v is not None}
                        if pc_d:
                            ap[pname] = pc_d
                    if ap:
                        tc_dict["allowed_params"] = ap
                if tc.response_jq:
                    tc_dict["response_jq"] = tc.response_jq
                constrain[tool_name] = tc_dict
            d["constrain"] = constrain
        return d

    async def write_server_rules(self, server_rules: dict[str, Any]) -> None:
        """Write rules-defaults.toml from a dict of ServerRules objects."""
        async with self._lock:
            data = {name: self._rules_to_toml(rules) for name, rules in server_rules.items()}
            self._write("rules-defaults.toml", data)

    async def write_agent_overrides(self, overrides: dict[str, Any]) -> None:
        """Write rules-agents.toml from a nested agent→server→ServerRules dict."""
        async with self._lock:
            data = {
                agent_id: {
                    server_name: self._rules_to_toml(rules)
                    for server_name, rules in agent_servers.items()
                }
                for agent_id, agent_servers in overrides.items()
            }
            self._write("rules-agents.toml", data)

    async def write_dlp_config(self, dlp_data: dict[str, Any]) -> None:
        """Update the [dlp] section in wrapper.toml, preserving all other sections."""
        async with self._lock:
            existing = self._read_existing("wrapper.toml")
            existing["dlp"] = dlp_data
            self._write("wrapper.toml", existing)
