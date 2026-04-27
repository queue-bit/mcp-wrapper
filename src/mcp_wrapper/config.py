from __future__ import annotations

import logging
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-reuse-def]

from .models import ServerRules, WrapperConfig

log = logging.getLogger(__name__)


def load_config(path: str | Path = "config/mcp-servers.toml") -> WrapperConfig:
    path = Path(path)
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    config = WrapperConfig.model_validate(raw)

    config.server_rules = _load_server_rules(path.parent / "rules-defaults.toml")
    config.agent_overrides = _load_agent_overrides(path.parent / "rules-agents.toml")

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
