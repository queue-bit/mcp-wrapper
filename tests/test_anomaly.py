"""
Unit tests for AnomalyDetector.

Each test logs audit events directly to the logger (bypassing the proxy)
and then calls detector.check() to verify the anomaly signals.
"""

import pytest

from mcp_wrapper.anomaly import AnomalyDetector
from mcp_wrapper.logger import AuditLogger
from mcp_wrapper.models import AnomalyConfig, AuditEvent


@pytest.fixture
async def logger(tmp_path):
    al = AuditLogger(db_path=str(tmp_path / "test.db"))
    await al.start()
    yield al
    await al.stop()


def _event(**kwargs) -> AuditEvent:
    defaults = {
        "agent_id": "agent-a",
        "session_id": "sess_test",
        "tool": "GetDateTime",
        "decision": "allowed",
    }
    defaults.update(kwargs)
    return AuditEvent(**defaults)


def _detector(logger: AuditLogger, **config_kwargs) -> AnomalyDetector:
    return AnomalyDetector(logger, AnomalyConfig(**config_kwargs))


# ---------------------------------------------------------------------------
# Denial burst
# ---------------------------------------------------------------------------

async def test_denial_burst_triggered_at_threshold(logger):
    detector = _detector(logger, denial_burst_threshold=3, denial_burst_window_seconds=60)
    for _ in range(2):
        await logger.log(_event(decision="denied"))
    event = _event(decision="denied")
    await logger.log(event)
    anomalies = await detector.check(event)
    assert any("denial burst" in a for a in anomalies)


async def test_denial_burst_not_triggered_below_threshold(logger):
    detector = _detector(logger, denial_burst_threshold=3, denial_burst_window_seconds=60)
    await logger.log(_event(decision="denied"))
    event = _event(decision="denied")
    await logger.log(event)
    anomalies = await detector.check(event)
    assert not any("denial burst" in a for a in anomalies)


async def test_denial_burst_only_counts_denials(logger):
    detector = _detector(logger, denial_burst_threshold=3, denial_burst_window_seconds=60)
    for _ in range(4):
        await logger.log(_event(decision="allowed"))
    event = _event(decision="denied")
    await logger.log(event)
    anomalies = await detector.check(event)
    assert not any("denial burst" in a for a in anomalies)


async def test_denial_burst_agents_isolated(logger):
    """5 denials for agent-b must not trigger burst for agent-a."""
    detector = _detector(logger, denial_burst_threshold=3, denial_burst_window_seconds=60)
    for _ in range(3):
        await logger.log(_event(agent_id="agent-b", decision="denied"))
    event = _event(agent_id="agent-a", decision="denied")
    await logger.log(event)
    anomalies = await detector.check(event)
    assert not any("denial burst" in a for a in anomalies)


async def test_denial_burst_not_triggered_for_allowed(logger):
    """Burst check skipped entirely when decision is 'allowed'."""
    detector = _detector(logger, denial_burst_threshold=3, denial_burst_window_seconds=60)
    for _ in range(5):
        await logger.log(_event(decision="denied"))
    event = _event(decision="allowed")
    await logger.log(event)
    anomalies = await detector.check(event)
    assert not any("denial burst" in a for a in anomalies)


# ---------------------------------------------------------------------------
# New tool
# ---------------------------------------------------------------------------

async def test_new_tool_flagged_first_call(logger):
    detector = _detector(logger)
    event = _event(tool="BrandNewTool")
    await logger.log(event)
    anomalies = await detector.check(event)
    assert any("first time" in a for a in anomalies)


async def test_new_tool_not_flagged_second_call(logger):
    detector = _detector(logger)
    first = _event(tool="GetDateTime")
    await logger.log(first)
    await detector.check(first)          # count=1, anomaly raised but not added to cache
    second = _event(tool="GetDateTime")
    await logger.log(second)
    anomalies = await detector.check(second)   # count=2, added to cache
    assert not any("first time" in a for a in anomalies)


async def test_new_tool_cache_prevents_repeated_db_queries(logger):
    """Third+ calls hit in-memory cache; anomaly must not be raised."""
    detector = _detector(logger)
    for _ in range(3):
        e = _event(tool="GetDateTime")
        await logger.log(e)
        await detector.check(e)
    anomalies = await detector.check(_event(tool="GetDateTime"))
    assert not any("first time" in a for a in anomalies)


async def test_new_tool_not_flagged_for_tools_list(logger):
    detector = _detector(logger)
    event = _event(tool="tools/list")
    await logger.log(event)
    anomalies = await detector.check(event)
    assert not any("first time" in a for a in anomalies)


async def test_new_tool_agents_isolated(logger):
    """agent-b having seen a tool must not suppress the anomaly for agent-a."""
    detector = _detector(logger)
    for _ in range(2):
        await logger.log(_event(agent_id="agent-b", tool="GetDateTime"))
    event = _event(agent_id="agent-a", tool="GetDateTime")
    await logger.log(event)
    anomalies = await detector.check(event)
    assert any("first time" in a for a in anomalies)


async def test_new_tool_flagged_on_denial_too(logger):
    """Even a denied first call should produce the new-tool anomaly."""
    detector = _detector(logger)
    event = _event(tool="HassAdmin", decision="denied")
    await logger.log(event)
    anomalies = await detector.check(event)
    assert any("first time" in a for a in anomalies)


# ---------------------------------------------------------------------------
# Off-hours
# ---------------------------------------------------------------------------

async def test_off_hours_triggered_when_no_valid_days(logger):
    """business_days=[] means no day is ever valid → always off-hours."""
    detector = _detector(logger, business_hours_enabled=True, business_days=[])
    event = _event()
    await logger.log(event)
    anomalies = await detector.check(event)
    assert any("outside business hours" in a for a in anomalies)


async def test_off_hours_not_triggered_all_hours_all_days(logger):
    """Covering all days and all hours → never off-hours."""
    detector = _detector(
        logger,
        business_hours_enabled=True,
        business_days=list(range(7)),
        business_hours_start=0,
        business_hours_end=24,
    )
    event = _event()
    await logger.log(event)
    anomalies = await detector.check(event)
    assert not any("outside business hours" in a for a in anomalies)


async def test_off_hours_disabled_by_default(logger):
    """Default AnomalyConfig has business_hours_enabled=False."""
    detector = _detector(logger, business_days=[])   # no valid days but feature off
    event = _event()
    await logger.log(event)
    anomalies = await detector.check(event)
    assert not any("outside business hours" in a for a in anomalies)


# ---------------------------------------------------------------------------
# Clean baseline
# ---------------------------------------------------------------------------

async def test_no_anomalies_in_normal_usage(logger):
    detector = _detector(logger)
    for _ in range(3):
        e = _event(tool="GetDateTime")
        await logger.log(e)
        await detector.check(e)
    event = _event(tool="GetDateTime")
    await logger.log(event)
    anomalies = await detector.check(event)
    assert anomalies == []
