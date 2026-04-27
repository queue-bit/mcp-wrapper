from __future__ import annotations

import logging
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-reuse-def]

from .models import RuleConfig, WrapperConfig

log = logging.getLogger(__name__)


def load_config(path: str | Path = "config/wrapper.toml") -> WrapperConfig:
    path = Path(path)
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    config = WrapperConfig.model_validate(raw)

    rules_path = path.parent / "rules.toml"
    if rules_path.exists():
        _merge_rules(config, rules_path)
    else:
        log.warning("No rules.toml found at %s — agents without rules will deny all calls", rules_path)

    return config


def _merge_rules(config: WrapperConfig, rules_path: Path) -> None:
    with open(rules_path, "rb") as f:
        raw = tomllib.load(f)

    for agent_id, agent_data in raw.get("agents", {}).items():
        if agent_id not in config.agents:
            log.warning("rules.toml references unknown agent %r — skipping", agent_id)
            continue
        rules = [RuleConfig.model_validate(r) for r in agent_data.get("rules", [])]
        config.agents[agent_id].rules = rules
        log.debug("loaded %d rules for agent %r from rules.toml", len(rules), agent_id)
