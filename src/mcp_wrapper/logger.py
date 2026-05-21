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
    approval_note       TEXT,
    params_chars        INTEGER,
    response_chars      INTEGER,
    raw_response_chars  INTEGER,
    response            TEXT,
    anomalies           TEXT,
    dlp_violations      TEXT,
    client_info         TEXT
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
            ("params_chars", "INTEGER"),
            ("response_chars", "INTEGER"),
            ("raw_response_chars", "INTEGER"),
            ("response", "TEXT"),
            ("anomalies", "TEXT"),
            ("dlp_violations", "TEXT"),
            ("client_info", "TEXT"),
        ]:
            try:
                await self._db.execute(f"ALTER TABLE audit_log ADD COLUMN {column} {definition}")
            except Exception:
                pass  # column already exists
        await self._db.commit()

    async def stop(self) -> None:
        if self._db:
            await self._db.close()

    async def log(self, event: AuditEvent) -> int | None:
        if self._db is None:
            raise RuntimeError("AuditLogger not started")

        cursor = await self._db.execute(
            """
            INSERT INTO audit_log (
                timestamp, agent_id, session_id, mcp_server, tool, params, decision,
                rule_matched, credential_accessed, response_status,
                latency_ms, denial_reason, reason, approval_id, approval_note,
                params_chars, response_chars, raw_response_chars, response, anomalies, dlp_violations, client_info
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                event.params_chars,
                event.response_chars,
                event.raw_response_chars,
                event.response,
                json.dumps(event.anomalies) if event.anomalies is not None else None,
                json.dumps(event.dlp_violations) if event.dlp_violations is not None else None,
                event.client_info,
            ),
        )
        await self._db.commit()

        if self._jsonl_path:
            with self._jsonl_path.open("a") as f:
                f.write(event.model_dump_json() + "\n")

        log.debug("audit: agent=%s decision=%s tool=%s", event.agent_id, event.decision, event.tool)
        return cursor.lastrowid

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
                f" SUM(CASE WHEN decision='denied'  THEN 1 ELSE 0 END) as denied,"
                f" COALESCE(SUM(params_chars), 0) as params_chars_total,"
                f" COALESCE(SUM(response_chars), 0) as response_chars_total"
                f" FROM audit_log WHERE {where}",
                params,
            ) as cur:
                row = await cur.fetchone()
                total = row[0] or 0
                allowed = row[1] or 0
                denied = row[2] or 0
                params_chars_total = row[3] or 0
                response_chars_total = row[4] or 0

            async with db.execute(
                f"SELECT tool, COUNT(*) as count,"
                f" SUM(CASE WHEN decision='denied' THEN 1 ELSE 0 END) as denied,"
                f" CAST(AVG(params_chars) AS INTEGER) as avg_params_chars,"
                f" CAST(AVG(response_chars) AS INTEGER) as avg_response_chars"
                f" FROM audit_log WHERE {where} AND tool IS NOT NULL"
                f" GROUP BY tool ORDER BY count DESC LIMIT 10",
                params,
            ) as cur:
                top_tools = [
                    {
                        "tool": r[0],
                        "count": r[1],
                        "denied": r[2] or 0,
                        "avg_params_chars": r[3],
                        "avg_response_chars": r[4],
                    }
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
            "token_usage": {
                "params_chars_total": params_chars_total,
                "response_chars_total": response_chars_total,
                "params_tokens_est": params_chars_total // 4,
                "response_tokens_est": response_chars_total // 4,
            },
        }

    async def update_result(
        self,
        event_id: int,
        response: str | None = None,
        anomalies: list[str] | None = None,
    ) -> None:
        """Update response content and/or anomaly list on an already-logged event."""
        if self._db is None:
            return
        await self._db.execute(
            "UPDATE audit_log SET response = ?, anomalies = ? WHERE id = ?",
            (response, json.dumps(anomalies) if anomalies is not None else None, event_id),
        )
        await self._db.commit()

    async def get_entry_by_id(self, event_id: int) -> dict | None:
        """Return a single audit event by primary key, or None if not found."""
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM audit_log WHERE id = ?", (event_id,)
            ) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None

    async def query_entries_admin(
        self,
        agent_id: str | None = None,
        limit: int = 100,
        tool: str | None = None,
        mcp_server: str | None = None,
        decision: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict]:
        """Like query_entries but agent_id is optional (None = all agents)."""
        conditions: list[str] = []
        params: list = []
        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
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
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        rows: list[dict] = []
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                f"SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ?",
                params,
            ) as cursor:
                async for row in cursor:
                    rows.append(dict(row))
        return rows

    async def fingerprint_counts(self) -> dict[str, int]:
        """Return {agent_id: number of distinct client fingerprints} from session_start rows."""
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                """
                SELECT agent_id, COUNT(DISTINCT client_info)
                FROM audit_log
                WHERE decision = 'session_start' AND client_info IS NOT NULL
                GROUP BY agent_id
                """,
            ) as cursor:
                return {row[0]: row[1] async for row in cursor}

    async def query_global_stats(
        self,
        since: str | None = None,
        until: str | None = None,
    ) -> dict:
        """Summary statistics across all agents."""
        conditions: list[str] = []
        params: list = []
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)
        if until:
            conditions.append("timestamp <= ?")
            params.append(until)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                f"SELECT COUNT(*) as total,"
                f" SUM(CASE WHEN decision='allowed' THEN 1 ELSE 0 END) as allowed,"
                f" SUM(CASE WHEN decision='denied'  THEN 1 ELSE 0 END) as denied,"
                f" COALESCE(SUM(params_chars), 0) as params_chars_total,"
                f" COALESCE(SUM(response_chars), 0) as response_chars_total,"
                f" COALESCE(SUM(raw_response_chars), 0) as raw_response_chars_total,"
                f" COALESCE(SUM(CASE WHEN raw_response_chars IS NOT NULL THEN response_chars ELSE 0 END), 0) as filtered_response_chars_total"
                f" FROM audit_log {where}",
                params,
            ) as cur:
                row = await cur.fetchone()
                total = row[0] or 0
                allowed = row[1] or 0
                denied = row[2] or 0
                params_chars_total = row[3] or 0
                response_chars_total = row[4] or 0
                raw_response_chars_total = row[5] or 0
                filtered_response_chars_total = row[6] or 0

            async with db.execute(
                f"SELECT agent_id, COUNT(*) as count,"
                f" COALESCE(SUM(response_chars), 0) as response_chars_total"
                f" FROM audit_log {where}"
                f" GROUP BY agent_id ORDER BY count DESC",
                params,
            ) as cur:
                by_agent = [
                    {
                        "agent_id": r[0],
                        "count": r[1],
                        "response_chars_total": r[2],
                        "response_tokens_est": (r[2] or 0) // 4,
                    }
                    async for r in cur
                ]

        return {
            "total": total,
            "allowed": allowed,
            "denied": denied,
            "denial_rate_pct": round(denied / total * 100, 1) if total > 0 else 0.0,
            "by_agent": by_agent,
            "token_usage": {
                "params_chars_total": params_chars_total,
                "response_chars_total": response_chars_total,
                "raw_response_chars_total": raw_response_chars_total,
                "params_tokens_est": params_chars_total // 4,
                "response_tokens_est": response_chars_total // 4,
                "raw_response_tokens_est": raw_response_chars_total // 4,
                "response_tokens_saved": max(0, (raw_response_chars_total - filtered_response_chars_total) // 4),
            },
        }
