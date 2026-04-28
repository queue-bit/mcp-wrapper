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
    denial_reason       TEXT,
    reason              TEXT,
    approval_id         TEXT,
    approval_note       TEXT
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
        for column, definition in [
            ("mcp_server", "TEXT"),
            ("reason", "TEXT"),
            ("approval_id", "TEXT"),
            ("approval_note", "TEXT"),
        ]:
            try:
                await self._db.execute(f"ALTER TABLE audit_log ADD COLUMN {column} {definition}")
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
                latency_ms, denial_reason, reason, approval_id, approval_note
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                event.reason,
                event.approval_id,
                event.approval_note,
            ),
        )
        await self._db.commit()

        if self._jsonl_path:
            with self._jsonl_path.open("a") as f:
                f.write(event.model_dump_json() + "\n")

        log.debug("audit: agent=%s decision=%s tool=%s", event.agent_id, event.decision, event.tool)

    async def query_entries(
        self,
        agent_id: str,
        limit: int = 50,
        tool: str | None = None,
        mcp_server: str | None = None,
        decision: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict]:
        """Return filtered audit log entries for one agent, newest first."""
        conditions = ["agent_id = ?"]
        params: list = [agent_id]

        if tool:
            conditions.append("tool LIKE ?")
            params.append(tool.replace("*", "%"))
        if mcp_server:
            conditions.append("mcp_server = ?")
            params.append(mcp_server)
        if decision:
            conditions.append("decision = ?")
            params.append(decision)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)
        if until:
            conditions.append("timestamp <= ?")
            params.append(until)

        where = " AND ".join(conditions)
        params.append(limit)

        rows: list[dict] = []
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                f"SELECT * FROM audit_log WHERE {where} ORDER BY id DESC LIMIT ?",
                params,
            ) as cursor:
                async for row in cursor:
                    rows.append(dict(row))
        return rows

    async def query_stats(
        self,
        agent_id: str,
        since: str | None = None,
        until: str | None = None,
    ) -> dict:
        """Return summary statistics for one agent."""
        conditions = ["agent_id = ?"]
        params: list = [agent_id]
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)
        if until:
            conditions.append("timestamp <= ?")
            params.append(until)
        where = " AND ".join(conditions)

        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                f"SELECT COUNT(*) as total,"
                f" SUM(CASE WHEN decision='allowed' THEN 1 ELSE 0 END) as allowed,"
                f" SUM(CASE WHEN decision='denied'  THEN 1 ELSE 0 END) as denied"
                f" FROM audit_log WHERE {where}",
                params,
            ) as cur:
                row = await cur.fetchone()
                total = row[0] or 0
                allowed = row[1] or 0
                denied = row[2] or 0

            async with db.execute(
                f"SELECT tool, COUNT(*) as count,"
                f" SUM(CASE WHEN decision='denied' THEN 1 ELSE 0 END) as denied"
                f" FROM audit_log WHERE {where} AND tool IS NOT NULL"
                f" GROUP BY tool ORDER BY count DESC LIMIT 10",
                params,
            ) as cur:
                top_tools = [
                    {"tool": r[0], "count": r[1], "denied": r[2] or 0}
                    async for r in cur
                ]

            async with db.execute(
                f"SELECT mcp_server, COUNT(*) as count,"
                f" SUM(CASE WHEN decision='denied' THEN 1 ELSE 0 END) as denied"
                f" FROM audit_log WHERE {where} AND mcp_server IS NOT NULL"
                f" GROUP BY mcp_server ORDER BY count DESC",
                params,
            ) as cur:
                by_server = [
                    {"mcp_server": r[0], "count": r[1], "denied": r[2] or 0}
                    async for r in cur
                ]

        return {
            "total": total,
            "allowed": allowed,
            "denied": denied,
            "denial_rate_pct": round(denied / total * 100, 1) if total > 0 else 0.0,
            "top_tools": top_tools,
            "by_server": by_server,
        }
