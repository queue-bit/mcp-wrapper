from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-reuse-def]

from .models import ServerRules, WrapperConfig

log = logging.getLogger(__name__)

_CONFIG_FILES = ("wrapper.toml", "mcp-servers.toml", "native-tools.toml", "plugins.toml", "agents.toml", "gateway.toml")


def load_config(config_dir: str | Path = "config") -> WrapperConfig:
    config_dir = Path(config_dir)
    raw: dict[str, Any] = {}
    for filename in _CONFIG_FILES:
        p = config_dir / filename
        if p.exists():
            with open(p, "rb") as f:
                raw.update(tomllib.load(f))
    config = WrapperConfig.model_validate(raw)
    config.server_rules = _load_server_rules(config_dir / "rules-defaults.toml")
    config.agent_overrides = _load_agent_overrides(config_dir / "rules-agents.toml")
    return config


def _load_server_rules(path: Path) -> dict[str, ServerRules]:
    if not path.exists():
        log.warning("No servers.toml found at %s — all tool calls will be denied", path)
        return {}
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    rules = {name: ServerRules.model_validate(data) for name, data in raw.items()}
    log.debug("Loaded server rules for: %s", list(rules))
    return rules


def _load_agent_overrides(path: Path) -> dict[str, dict[str, ServerRules]]:
    if not path.exists():
        return {}
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    overrides: dict[str, dict[str, ServerRules]] = {}
    for agent_id, servers in raw.items():
        overrides[agent_id] = {
            server_name: ServerRules.model_validate(server_data)
            for server_name, server_data in servers.items()
        }
    log.debug("Loaded agent overrides for: %s", list(overrides))
    return overrides
