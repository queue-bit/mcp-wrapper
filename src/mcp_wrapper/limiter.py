from __future__ import annotations

import logging

from limits import parse as parse_limit
from limits.storage import MemoryStorage
from limits.strategies import MovingWindowRateLimiter

from .models import RateLimitConfig

log = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self) -> None:
        self._storage = MemoryStorage()
        self._limiter = MovingWindowRateLimiter(self._storage)

    def check(self, agent_id: str, tool_name: str, config: RateLimitConfig) -> bool:
        """Return True if the call is within limits, False if any limit is exceeded.

        Tests all configured limits before consuming any, so a per-hour failure
        doesn't silently burn the per-minute counter.
        """
        limits = []
        if config.per_minute is not None:
            limits.append((parse_limit(f"{config.per_minute} per minute"), "per_minute"))
        if config.per_hour is not None:
            limits.append((parse_limit(f"{config.per_hour} per hour"), "per_hour"))

        for limit, label in limits:
            if not self._limiter.test(limit, agent_id, tool_name):
                log.warning(
                    "rate_limit_exceeded: agent=%s tool=%s limit=%s",
                    agent_id, tool_name, label,
                )
                return False

        for limit, _ in limits:
            self._limiter.hit(limit, agent_id, tool_name)

        return True
