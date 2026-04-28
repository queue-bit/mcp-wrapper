import json
import tempfile
import pytest

from mcp_wrapper.logger import AuditLogger
from mcp_wrapper.models import AuditEvent


@pytest.fixture
async def logger(tmp_path):
    db = str(tmp_path / "test.db")
    jsonl = str(tmp_path / "test.jsonl")
    al = AuditLogger(db_path=db, jsonl_path=jsonl)
    await al.start()
    yield al
    await al.stop()


async def test_log_event_to_sqlite(logger, tmp_path):
    event = AuditEvent(
        agent_id="test-agent",
        session_id="sess_001",
        tool="homeassistant.turn_on",
        params={"entity_id": "light.kitchen"},
        decision="allowed",
        latency_ms=42,
    )
    await logger.log(event)

    import aiosqlite
    async with aiosqlite.connect(str(tmp_path / "test.db")) as db:
        async with db.execute("SELECT agent_id, tool, decision, latency_ms FROM audit_log") as cur:
            row = await cur.fetchone()
    assert row == ("test-agent", "homeassistant.turn_on", "allowed", 42)


async def test_log_event_to_jsonl(logger, tmp_path):
    event = AuditEvent(
        agent_id="test-agent",
        session_id="sess_001",
        tool="homeassistant.turn_off",
        decision="denied",
        denial_reason="not in whitelist",
    )
    await logger.log(event)

    jsonl_path = tmp_path / "test.jsonl"
    lines = jsonl_path.read_text().strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["agent_id"] == "test-agent"
    assert data["decision"] == "denied"


async def test_reason_stored_and_retrieved(logger, tmp_path):
    event = AuditEvent(
        agent_id="test-agent",
        session_id="sess_001",
        tool="GetDateTime",
        decision="allowed",
        reason="user asked for the time",
    )
    await logger.log(event)

    import aiosqlite
    async with aiosqlite.connect(str(tmp_path / "test.db")) as db:
        async with db.execute("SELECT reason FROM audit_log") as cur:
            row = await cur.fetchone()
    assert row[0] == "user asked for the time"


async def test_approval_fields_stored(logger, tmp_path):
    event = AuditEvent(
        agent_id="test-agent",
        session_id="sess_001",
        tool="HassTurnOff",
        decision="allowed",
        approval_id="abc123",
        approval_note="approved by admin",
    )
    await logger.log(event)

    import aiosqlite
    async with aiosqlite.connect(str(tmp_path / "test.db")) as db:
        async with db.execute("SELECT approval_id, approval_note FROM audit_log") as cur:
            row = await cur.fetchone()
    assert row[0] == "abc123"
    assert row[1] == "approved by admin"


async def test_mcp_server_stored(logger, tmp_path):
    event = AuditEvent(
        agent_id="test-agent",
        session_id="sess_001",
        tool="GetDateTime",
        mcp_server="homeassistant",
        decision="allowed",
    )
    await logger.log(event)

    import aiosqlite
    async with aiosqlite.connect(str(tmp_path / "test.db")) as db:
        async with db.execute("SELECT mcp_server FROM audit_log") as cur:
            row = await cur.fetchone()
    assert row[0] == "homeassistant"


async def _seed(logger: AuditLogger, entries: list[dict]) -> None:
    for e in entries:
        await logger.log(AuditEvent(**e))


# ---------------------------------------------------------------------------
# query_entries
# ---------------------------------------------------------------------------

async def test_query_entries_no_filter(logger):
    await _seed(logger, [
        {"agent_id": "a", "session_id": "s", "tool": "GetDateTime", "mcp_server": "ha", "decision": "allowed"},
        {"agent_id": "a", "session_id": "s", "tool": "HassTurnOff",  "mcp_server": "ha", "decision": "denied"},
        {"agent_id": "b", "session_id": "s", "tool": "GetDateTime",  "decision": "allowed"},  # different agent
    ])
    rows = await logger.query_entries(agent_id="a")
    assert len(rows) == 2
    assert all(r["agent_id"] == "a" for r in rows)


async def test_query_entries_filter_decision(logger):
    await _seed(logger, [
        {"agent_id": "a", "session_id": "s", "tool": "GetDateTime", "decision": "allowed"},
        {"agent_id": "a", "session_id": "s", "tool": "HassTurnOff", "decision": "denied"},
    ])
    rows = await logger.query_entries(agent_id="a", decision="denied")
    assert len(rows) == 1
    assert rows[0]["tool"] == "HassTurnOff"


async def test_query_entries_filter_tool_exact(logger):
    await _seed(logger, [
        {"agent_id": "a", "session_id": "s", "tool": "GetDateTime", "decision": "allowed"},
        {"agent_id": "a", "session_id": "s", "tool": "HassTurnOff", "decision": "allowed"},
    ])
    rows = await logger.query_entries(agent_id="a", tool="GetDateTime")
    assert len(rows) == 1
    assert rows[0]["tool"] == "GetDateTime"


async def test_query_entries_filter_tool_glob(logger):
    await _seed(logger, [
        {"agent_id": "a", "session_id": "s", "tool": "HassTurnOn",  "decision": "allowed"},
        {"agent_id": "a", "session_id": "s", "tool": "HassTurnOff", "decision": "allowed"},
        {"agent_id": "a", "session_id": "s", "tool": "GetDateTime", "decision": "allowed"},
    ])
    rows = await logger.query_entries(agent_id="a", tool="Hass*")
    assert len(rows) == 2
    assert all(r["tool"].startswith("Hass") for r in rows)


async def test_query_entries_filter_mcp_server(logger):
    await _seed(logger, [
        {"agent_id": "a", "session_id": "s", "tool": "GetDateTime", "mcp_server": "ha",    "decision": "allowed"},
        {"agent_id": "a", "session_id": "s", "tool": "search",      "mcp_server": "brave", "decision": "allowed"},
    ])
    rows = await logger.query_entries(agent_id="a", mcp_server="ha")
    assert len(rows) == 1
    assert rows[0]["mcp_server"] == "ha"


async def test_query_entries_filter_since(logger):
    await _seed(logger, [
        {"agent_id": "a", "session_id": "s", "tool": "old", "decision": "allowed"},
    ])
    rows = await logger.query_entries(agent_id="a", since="2099-01-01T00:00:00")
    assert len(rows) == 0


async def test_query_entries_limit(logger):
    await _seed(logger, [
        {"agent_id": "a", "session_id": "s", "tool": "GetDateTime", "decision": "allowed"}
        for _ in range(10)
    ])
    rows = await logger.query_entries(agent_id="a", limit=3)
    assert len(rows) == 3


# ---------------------------------------------------------------------------
# query_stats
# ---------------------------------------------------------------------------

async def test_query_stats_counts(logger):
    await _seed(logger, [
        {"agent_id": "a", "session_id": "s", "tool": "GetDateTime", "mcp_server": "ha", "decision": "allowed"},
        {"agent_id": "a", "session_id": "s", "tool": "GetDateTime", "mcp_server": "ha", "decision": "allowed"},
        {"agent_id": "a", "session_id": "s", "tool": "HassTurnOff", "mcp_server": "ha", "decision": "denied"},
    ])
    stats = await logger.query_stats(agent_id="a")
    assert stats["total"] == 3
    assert stats["allowed"] == 2
    assert stats["denied"] == 1
    assert stats["denial_rate_pct"] == pytest.approx(33.3, abs=0.1)


async def test_query_stats_top_tools(logger):
    await _seed(logger, [
        {"agent_id": "a", "session_id": "s", "tool": "GetDateTime", "decision": "allowed"},
        {"agent_id": "a", "session_id": "s", "tool": "GetDateTime", "decision": "allowed"},
        {"agent_id": "a", "session_id": "s", "tool": "HassTurnOff", "decision": "denied"},
    ])
    stats = await logger.query_stats(agent_id="a")
    tools = {t["tool"]: t for t in stats["top_tools"]}
    assert tools["GetDateTime"]["count"] == 2
    assert tools["HassTurnOff"]["denied"] == 1


async def test_query_stats_by_server(logger):
    await _seed(logger, [
        {"agent_id": "a", "session_id": "s", "tool": "GetDateTime", "mcp_server": "ha",    "decision": "allowed"},
        {"agent_id": "a", "session_id": "s", "tool": "search",      "mcp_server": "brave", "decision": "allowed"},
        {"agent_id": "a", "session_id": "s", "tool": "search",      "mcp_server": "brave", "decision": "denied"},
    ])
    stats = await logger.query_stats(agent_id="a")
    servers = {s["mcp_server"]: s for s in stats["by_server"]}
    assert servers["ha"]["count"] == 1
    assert servers["brave"]["count"] == 2
    assert servers["brave"]["denied"] == 1


async def test_query_stats_empty(logger):
    stats = await logger.query_stats(agent_id="nobody")
    assert stats["total"] == 0
    assert stats["denial_rate_pct"] == 0.0


async def test_query_stats_isolates_agents(logger):
    await _seed(logger, [
        {"agent_id": "a", "session_id": "s", "tool": "GetDateTime", "decision": "allowed"},
        {"agent_id": "b", "session_id": "s", "tool": "GetDateTime", "decision": "denied"},
    ])
    stats_a = await logger.query_stats(agent_id="a")
    assert stats_a["denied"] == 0


async def test_schema_migration_adds_columns(tmp_path):
    """Existing DBs without new columns should be migrated on start."""
    import aiosqlite

    db_path = str(tmp_path / "old.db")
    # Create a DB with the original minimal schema
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                tool TEXT,
                decision TEXT NOT NULL
            )
        """)
        await db.commit()

    # Starting the logger should add missing columns without error
    al = AuditLogger(db_path=db_path)
    await al.start()
    await al.stop()

    async with aiosqlite.connect(db_path) as db:
        async with db.execute("PRAGMA table_info(audit_log)") as cur:
            columns = {row[1] async for row in cur}

    assert "mcp_server" in columns
    assert "reason" in columns
    assert "approval_id" in columns
    assert "approval_note" in columns
