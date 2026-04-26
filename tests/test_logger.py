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
