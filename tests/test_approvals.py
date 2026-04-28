import asyncio
import json

import pytest

from mcp_wrapper.approvals import ApprovalManager


@pytest.fixture
def mgr():
    return ApprovalManager(webhook_url=None, base_url="http://localhost:8080", timeout_seconds=5)


def _resolve_after(mgr: ApprovalManager, delay: float, approved: bool, note: str | None = None):
    async def _run():
        await asyncio.sleep(delay)
        approval_id = next(iter(mgr._pending))
        mgr.resolve(approval_id, approved=approved, note=note)
    asyncio.create_task(_run())


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

async def test_approve_unblocks_request(mgr):
    _resolve_after(mgr, delay=0.05, approved=True, note="looks good")
    approved, approval_id, note = await mgr.request(
        agent_id="test-agent", tool="HassTurnOff", params={}, reason="testing"
    )
    assert approved is True
    assert note == "looks good"
    assert approval_id


async def test_deny_unblocks_request(mgr):
    _resolve_after(mgr, delay=0.05, approved=False, note="not now")
    approved, approval_id, note = await mgr.request(
        agent_id="test-agent", tool="HassTurnOff", params={}, reason="testing"
    )
    assert approved is False
    assert note == "not now"


async def test_approval_id_unique_across_requests(mgr):
    ids = []

    async def grab_and_resolve():
        await asyncio.sleep(0.02)
        approval_id = next(iter(mgr._pending))
        ids.append(approval_id)
        mgr.resolve(approval_id, approved=True)

    for _ in range(3):
        asyncio.create_task(grab_and_resolve())
        await mgr.request(agent_id="test-agent", tool="GetDateTime", params={}, reason=None)

    assert len(set(ids)) == 3


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------

async def test_timeout_returns_denied():
    mgr = ApprovalManager(webhook_url=None, base_url="http://localhost:8080", timeout_seconds=0.05)
    approved, approval_id, note = await mgr.request(
        agent_id="test-agent", tool="HassTurnOff", params={}, reason="testing"
    )
    assert approved is False
    assert "timed out" in note


# ---------------------------------------------------------------------------
# resolve() edge cases
# ---------------------------------------------------------------------------

async def test_resolve_unknown_id_returns_false(mgr):
    assert mgr.resolve("nonexistent-id", approved=True) is False


async def test_pending_cleaned_up_after_resolution(mgr):
    _resolve_after(mgr, delay=0.05, approved=True)
    await mgr.request(agent_id="test-agent", tool="GetDateTime", params={}, reason=None)
    assert len(mgr._pending) == 0


async def test_pending_cleaned_up_after_timeout():
    mgr = ApprovalManager(webhook_url=None, base_url="http://localhost:8080", timeout_seconds=0.05)
    await mgr.request(agent_id="test-agent", tool="GetDateTime", params={}, reason=None)
    assert len(mgr._pending) == 0


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------

async def test_webhook_called_on_request(httpx_mock):
    mgr = ApprovalManager(
        webhook_url="http://hooks.example.com/notify",
        base_url="http://localhost:8080",
        timeout_seconds=5,
    )
    httpx_mock.add_response(method="POST", url="http://hooks.example.com/notify")
    _resolve_after(mgr, delay=0.05, approved=True)

    await mgr.request(agent_id="test-agent", tool="HassTurnOff", params={"x": 1}, reason="test")

    requests = httpx_mock.get_requests()
    assert len(requests) == 1
    payload = json.loads(requests[0].content)
    assert payload["tool"] == "HassTurnOff"
    assert payload["agent_id"] == "test-agent"
    assert "approve_url" in payload


async def test_webhook_failure_does_not_raise(httpx_mock):
    mgr = ApprovalManager(
        webhook_url="http://bad-host.invalid/notify",
        base_url="http://localhost:8080",
        timeout_seconds=5,
    )
    httpx_mock.add_exception(Exception("connection refused"), url="http://bad-host.invalid/notify")
    _resolve_after(mgr, delay=0.05, approved=True)

    # Should not raise despite webhook failure
    approved, _, _ = await mgr.request(
        agent_id="test-agent", tool="GetDateTime", params={}, reason=None
    )
    assert approved is True


async def test_no_webhook_does_not_raise(mgr):
    _resolve_after(mgr, delay=0.05, approved=True)
    approved, _, _ = await mgr.request(
        agent_id="test-agent", tool="GetDateTime", params={}, reason=None
    )
    assert approved is True
