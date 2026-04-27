from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import aiosqlite

from .models import AuditEvent

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    mcp_server          TEXT,
    tool        TEXT,
    params      TEXT,
    decision    TEXT NOT NULL,
    rule_matched        TEXT,
    credential_accessed TEXT,
    response_status     TEXT,
    latency_ms          INTEGER,
    denial_reason       TEXT
)
"""


class AuditLogger:
    def __init__(self, db_path: str, jsonl_path: str | None = None):
        self._db_path = db_path
        self._jsonl_path = Path(jsonl_path) if jsonl_path else None
        self._db: aiosqlite.Connection | None = None

    async def start(self) -> None:
        self._db = await aiosqlite.connect(self._db_path)
        await self._db.execute(CREATE_TABLE)
        # Add columns introduced after initial schema (existing DBs won't have them)
        try:
            await self._db.execute("ALTER TABLE audit_log ADD COLUMN mcp_server TEXT")
        except Exception:
            pass  # column already exists
        await self._db.commit()

    async def stop(self) -> None:
        if self._db:
            await self._db.close()

    async def log(self, event: AuditEvent) -> None:
        if self._db is None:
            raise RuntimeError("AuditLogger not started")

        await self._db.execute(
            """
            INSERT INTO audit_log (
                timestamp, agent_id, session_id, mcp_server, tool, params, decision,
                rule_matched, credential_accessed, response_status,
                latency_ms, denial_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.timestamp.isoformat(),
                event.agent_id,
                event.session_id,
                event.mcp_server,
                event.tool,
                json.dumps(event.params) if event.params is not None else None,
                event.decision,
                event.rule_matched,
                event.credential_accessed,
                event.response_status,
                event.latency_ms,
                event.denial_reason,
            ),
        )
        await self._db.commit()

        if self._jsonl_path:
            with self._jsonl_path.open("a") as f:
                f.write(event.model_dump_json() + "\n")

        log.debug("audit: agent=%s decision=%s tool=%s", event.agent_id, event.decision, event.tool)
