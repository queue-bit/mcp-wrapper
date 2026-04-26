from __future__ import annotations

import logging

from .credentials import SecretResolver
from .models import AgentConfig, Session, WrapperConfig

log = logging.getLogger(__name__)


class IdentityResolver:
    """Validates bearer tokens and resolves them to agent identities."""

    def __init__(self, config: WrapperConfig, resolver: SecretResolver) -> None:
        self._token_map: dict[str, str] = {}
        for agent_id, agent_cfg in config.agents.items():
            try:
                token = resolver.resolve(agent_cfg.token)
                self._token_map[token] = agent_id
            except Exception as e:
                log.error("Failed to resolve token for agent %r: %s", agent_id, e)

        self._agent_configs: dict[str, AgentConfig] = dict(config.agents)

    def resolve(self, token: str) -> Session | None:
        """Return an authenticated Session for the token, or None if invalid."""
        agent_id = self._token_map.get(token)
        if agent_id is None:
            return None
        return Session(agent_id=agent_id)

    def get_agent_config(self, agent_id: str) -> AgentConfig | None:
        return self._agent_configs.get(agent_id)
