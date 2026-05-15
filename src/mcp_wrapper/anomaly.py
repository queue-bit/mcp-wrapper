from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .logger import AuditLogger
from .models import AnomalyConfig, AuditEvent, Session

log = logging.getLogger(__name__)


class AnomalyDetector:
    def __init__(self, logger: AuditLogger, config: AnomalyConfig):
        self._logger = logger
        self._config = config
        self._seen_tools: dict[str, set[str]] = {}
        # agent_id -> set of client_info strings seen in previous sessions (seeded from DB)
        self._known_fingerprints: dict[str, set[str]] = {}

    async def check(self, event: AuditEvent) -> list[str]:
        anomalies: list[str] = []
        if event.tool and event.tool != "tools/list":
            if event.decision == "denied":
                anomalies.extend(await self._check_denial_burst(event))
            anomalies.extend(await self._check_new_tool(event))
        if self._config.business_hours_enabled:
            anomalies.extend(self._check_off_hours(event))
        for msg in anomalies:
            log.warning("ANOMALY [%s]: %s", event.agent_id, msg)
        return anomalies

    async def _check_denial_burst(self, event: AuditEvent) -> list[str]:
        cfg = self._config
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=cfg.denial_burst_window_seconds)
        ).isoformat()
        rows = await self._logger.query_entries(
            agent_id=event.agent_id,
            decision="denied",
            since=cutoff,
            limit=cfg.denial_burst_threshold + 1,
        )
        count = len(rows)
        if count >= cfg.denial_burst_threshold:
            return [
                f"denial burst: {count} denials in the last"
                f" {cfg.denial_burst_window_seconds}s"
                f" (threshold: {cfg.denial_burst_threshold})"
            ]
        return []

    async def _check_new_tool(self, event: AuditEvent) -> list[str]:
        agent_id = event.agent_id
        tool = event.tool
        seen = self._seen_tools.setdefault(agent_id, set())
        if tool in seen:
            return []
        rows = await self._logger.query_entries(agent_id=agent_id, tool=tool, limit=2)
        if len(rows) > 1:
            seen.add(tool)
            return []
        return [f"first time tool '{tool}' has been called by this agent"]

    async def check_fingerprint(self, session: Session) -> list[str]:
        """Return an anomaly if this token has been used from more than one client fingerprint."""
        if not session.client_info:
            log.info("fingerprint [%s]: no client_info — skipping check", session.agent_id)
            return []
        agent_id = session.agent_id
        client_info = session.client_info

        if agent_id not in self._known_fingerprints:
            rows = await self._logger.query_entries_admin(
                agent_id=agent_id, decision="session_start", limit=500
            )
            self._known_fingerprints[agent_id] = {
                r["client_info"] for r in rows if r.get("client_info")
            }
            log.info("fingerprint [%s]: seeded %d fingerprint(s) from DB",
                     agent_id, len(self._known_fingerprints[agent_id]))

        known = self._known_fingerprints[agent_id]
        known.add(client_info)

        log.info("fingerprint [%s]: current=%r all_seen=%r", agent_id, client_info, sorted(known))

        if len(known) <= 1:
            return []

        others_str = ", ".join(f"{c!r}" for c in sorted(known - {client_info}))
        msg = f"token used from multiple clients: {client_info!r} (also seen from: {others_str})"
        log.warning("FINGERPRINT [%s]: %s", agent_id, msg)
        return [msg]

    def _check_off_hours(self, event: AuditEvent) -> list[str]:
        cfg = self._config
        try:
            tz = ZoneInfo(cfg.business_hours_timezone)
        except ZoneInfoNotFoundError:
            tz = timezone.utc
        now = datetime.now(tz)
        in_hours = (
            now.weekday() in cfg.business_days
            and cfg.business_hours_start <= now.hour < cfg.business_hours_end
        )
        if not in_hours:
            return [
                f"tool called at {now.strftime('%H:%M')} {cfg.business_hours_timezone}"
                f" outside business hours"
                f" ({cfg.business_hours_start:02d}:00-{cfg.business_hours_end:02d}:00)"
            ]
        return []
