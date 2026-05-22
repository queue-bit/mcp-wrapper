from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
import urllib.parse
from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_wrapper.dlp import DlpConfig, DlpScanner
from mcp_wrapper.models import SlackConfig, TelegramConfig
from mcp_wrapper.notifications import (
    CompositeNotifier,
    SlackNotifier,
    TelegramNotifier,
    build_notifiers,
)
from mcp_wrapper.credentials import SecretResolver


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolver() -> SecretResolver:
    return SecretResolver(vault=None)


def _slack(signing_secret: str = "test-secret") -> SlackNotifier:
    config = SlackConfig(
        bot_token="xoxb-test",
        channel="C12345",
        signing_secret=signing_secret,
    )
    return SlackNotifier(config, _resolver())


def _telegram(secret_token: str | None = "tg-secret") -> TelegramNotifier:
    config = TelegramConfig(
        bot_token="123:ABC",
        chat_id="-100123",
        secret_token=secret_token,
    )
    return TelegramNotifier(config, _resolver())


def _dlp() -> DlpScanner:
    return DlpScanner(DlpConfig())


def _slack_sig(body: str, secret: str, timestamp: str | None = None) -> tuple[str, str]:
    ts = timestamp or str(int(time.time()))
    base = f"v0:{ts}:{body}"
    sig = "v0=" + hmac.new(secret.encode(), base.encode(), hashlib.sha256).hexdigest()
    return ts, sig


# ---------------------------------------------------------------------------
# Slack — send
# ---------------------------------------------------------------------------

async def test_slack_send_posts_block_kit(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://slack.com/api/chat.postMessage",
        json={"ok": True, "ts": "1234.5678", "channel": "C12345"},
    )
    notifier = _slack()
    await notifier.send("aid1", "agent1", "HassTurnOff", {"entity_id": "light.desk"}, "test")

    req = httpx_mock.get_requests()[0]
    body = json.loads(req.content)
    assert body["channel"] == "C12345"
    block_types = [b["type"] for b in body["blocks"]]
    assert "header" in block_types
    assert "actions" in block_types
    assert "aid1" in json.dumps(body["blocks"])


async def test_slack_send_redacts_sensitive_params(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://slack.com/api/chat.postMessage",
        json={"ok": True, "ts": "1111.2222", "channel": "C12345"},
    )
    notifier = _slack()
    dlp = _dlp()
    safe_params = dlp.redact_for_display({"ssn": "123-45-6789", "note": "ok"})
    await notifier.send("aid2", "agent1", "SomeOp", safe_params, None)

    req = httpx_mock.get_requests()[0]
    body_str = req.content.decode()
    assert "123-45-6789" not in body_str


async def test_slack_send_stores_ts_for_update(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://slack.com/api/chat.postMessage",
        json={"ok": True, "ts": "9999.0001", "channel": "C12345"},
    )
    notifier = _slack()
    await notifier.send("aid3", "agent1", "Tool", {}, None)
    assert "aid3" in notifier._sent
    assert notifier._sent["aid3"]["ts"] == "9999.0001"


async def test_slack_send_api_error_does_not_raise(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://slack.com/api/chat.postMessage",
        json={"ok": False, "error": "channel_not_found"},
    )
    notifier = _slack()
    await notifier.send("aid4", "agent1", "Tool", {}, None)  # must not raise
    assert "aid4" not in notifier._sent


# ---------------------------------------------------------------------------
# Slack — on_resolved
# ---------------------------------------------------------------------------

async def test_slack_on_resolved_updates_message(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://slack.com/api/chat.postMessage",
        json={"ok": True, "ts": "1234.0", "channel": "C12345"},
    )
    httpx_mock.add_response(
        method="POST",
        url="https://slack.com/api/chat.update",
        json={"ok": True},
    )
    notifier = _slack()
    await notifier.send("aid5", "a", "T", {}, None)
    await notifier.on_resolved("aid5", True, "approved by admin")

    reqs = httpx_mock.get_requests()
    assert any("chat.update" in str(r.url) for r in reqs)
    update_req = next(r for r in reqs if "chat.update" in str(r.url))
    update_body = json.loads(update_req.content)
    assert update_body["ts"] == "1234.0"
    assert "Approved" in json.dumps(update_body)


async def test_slack_on_resolved_unknown_id_is_noop(httpx_mock):
    notifier = _slack()
    await notifier.on_resolved("nonexistent", True, None)  # must not raise, no HTTP calls
    assert len(httpx_mock.get_requests()) == 0


# ---------------------------------------------------------------------------
# Slack — signature verification
# ---------------------------------------------------------------------------

def test_slack_verify_signature_valid():
    notifier = _slack(signing_secret="mysecret")
    body = "payload=abc"
    ts, sig = _slack_sig(body, "mysecret")
    assert notifier.verify_signature(body.encode(), ts, sig) is True


def test_slack_verify_signature_wrong_secret():
    notifier = _slack(signing_secret="correct")
    body = "payload=abc"
    ts, sig = _slack_sig(body, "wrong")
    assert notifier.verify_signature(body.encode(), ts, sig) is False


def test_slack_verify_signature_stale_timestamp():
    notifier = _slack(signing_secret="s")
    old_ts = str(int(time.time()) - 400)
    body = "payload=abc"
    _, sig = _slack_sig(body, "s", old_ts)
    assert notifier.verify_signature(body.encode(), old_ts, sig) is False


# ---------------------------------------------------------------------------
# Slack — handle_interact
# ---------------------------------------------------------------------------

async def test_slack_handle_interact_approve():
    notifier = _slack()
    approvals = MagicMock()
    approvals.resolve.return_value = True

    payload = {
        "actions": [{"value": "approve:abc123"}],
        "user": {"name": "alice"},
    }
    await notifier.handle_interact(payload, approvals)
    approvals.resolve.assert_called_once_with("abc123", True, "approved by alice via Slack")


async def test_slack_handle_interact_deny():
    notifier = _slack()
    approvals = MagicMock()
    approvals.resolve.return_value = True

    payload = {
        "actions": [{"value": "deny:xyz789"}],
        "user": {"name": "bob"},
    }
    await notifier.handle_interact(payload, approvals)
    approvals.resolve.assert_called_once_with("xyz789", False, "denied by bob via Slack")


async def test_slack_handle_interact_already_resolved_is_safe():
    notifier = _slack()
    approvals = MagicMock()
    approvals.resolve.return_value = False  # already resolved

    payload = {
        "actions": [{"value": "approve:stale"}],
        "user": {"name": "alice"},
    }
    await notifier.handle_interact(payload, approvals)  # must not raise


async def test_slack_handle_interact_no_actions_is_noop():
    notifier = _slack()
    approvals = MagicMock()
    await notifier.handle_interact({"actions": []}, approvals)
    approvals.resolve.assert_not_called()


# ---------------------------------------------------------------------------
# Telegram — send
# ---------------------------------------------------------------------------

async def test_telegram_send_posts_with_inline_keyboard(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://api.telegram.org/bot123:ABC/sendMessage",
        json={"ok": True, "result": {"message_id": 42, "chat": {"id": -100123}}},
    )
    notifier = _telegram()
    await notifier.send("aid6", "agent1", "HassTurnOff", {"entity_id": "light.desk"}, "test")

    req = httpx_mock.get_requests()[0]
    body = json.loads(req.content)
    assert body["chat_id"] == "-100123"
    kb = body["reply_markup"]["inline_keyboard"][0]
    button_datas = [b["callback_data"] for b in kb]
    assert any("approve:aid6" in d for d in button_datas)
    assert any("deny:aid6" in d for d in button_datas)


async def test_telegram_send_redacts_sensitive_params(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://api.telegram.org/bot123:ABC/sendMessage",
        json={"ok": True, "result": {"message_id": 1, "chat": {"id": -100123}}},
    )
    notifier = _telegram()
    dlp = _dlp()
    safe_params = dlp.redact_for_display({"cc": "4111111111111111"})
    await notifier.send("aid7", "agent1", "Pay", safe_params, None)

    req = httpx_mock.get_requests()[0]
    assert "4111111111111111" not in req.content.decode()


async def test_telegram_send_stores_message_id(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://api.telegram.org/bot123:ABC/sendMessage",
        json={"ok": True, "result": {"message_id": 77, "chat": {"id": -100123}}},
    )
    notifier = _telegram()
    await notifier.send("aid8", "agent1", "T", {}, None)
    assert notifier._sent["aid8"]["message_id"] == 77


# ---------------------------------------------------------------------------
# Telegram — on_resolved
# ---------------------------------------------------------------------------

async def test_telegram_on_resolved_edits_message(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://api.telegram.org/bot123:ABC/sendMessage",
        json={"ok": True, "result": {"message_id": 10, "chat": {"id": -100123}}},
    )
    httpx_mock.add_response(
        method="POST",
        url="https://api.telegram.org/bot123:ABC/editMessageText",
        json={"ok": True},
    )
    notifier = _telegram()
    await notifier.send("aid9", "a", "T", {}, None)
    await notifier.on_resolved("aid9", True, "ok")

    reqs = httpx_mock.get_requests()
    edit_req = next(r for r in reqs if "editMessageText" in str(r.url))
    edit_body = json.loads(edit_req.content)
    assert edit_body["message_id"] == 10
    assert "Approved" in edit_body["text"]
    assert edit_body["reply_markup"] == {"inline_keyboard": []}


# ---------------------------------------------------------------------------
# Telegram — secret token verification
# ---------------------------------------------------------------------------

def test_telegram_verify_secret_token_match():
    notifier = _telegram(secret_token="correct")
    assert notifier.verify_secret_token("correct") is True


def test_telegram_verify_secret_token_mismatch():
    notifier = _telegram(secret_token="correct")
    assert notifier.verify_secret_token("wrong") is False


def test_telegram_verify_secret_token_none_configured():
    notifier = _telegram(secret_token=None)
    # When no secret is configured, all inbound calls are rejected (can't verify).
    assert notifier.verify_secret_token(None) is False
    assert notifier.verify_secret_token("anything") is False


# ---------------------------------------------------------------------------
# Telegram — handle_update
# ---------------------------------------------------------------------------

async def test_telegram_handle_update_approve(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://api.telegram.org/bot123:ABC/answerCallbackQuery",
        json={"ok": True},
    )
    notifier = _telegram()
    notifier._sent["appid"] = {"message_id": 1, "chat_id": "-100", "text": "t"}
    approvals = MagicMock()
    approvals.resolve.return_value = True

    update = {"callback_query": {"id": "cq1", "data": "approve:appid"}}
    await notifier.handle_update(update, approvals)

    approvals.resolve.assert_called_once_with("appid", True, "approved via Telegram")
    reqs = httpx_mock.get_requests()
    assert any("answerCallbackQuery" in str(r.url) for r in reqs)


async def test_telegram_handle_update_deny(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://api.telegram.org/bot123:ABC/answerCallbackQuery",
        json={"ok": True},
    )
    notifier = _telegram()
    approvals = MagicMock()
    approvals.resolve.return_value = True

    update = {"callback_query": {"id": "cq2", "data": "deny:appid2"}}
    await notifier.handle_update(update, approvals)
    approvals.resolve.assert_called_once_with("appid2", False, "denied via Telegram")


async def test_telegram_handle_update_no_callback_is_noop():
    notifier = _telegram()
    approvals = MagicMock()
    await notifier.handle_update({"message": {"text": "hello"}}, approvals)
    approvals.resolve.assert_not_called()


# ---------------------------------------------------------------------------
# Telegram — webhook registration
# ---------------------------------------------------------------------------

async def test_telegram_register_webhook(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://api.telegram.org/bot123:ABC/setWebhook",
        json={"ok": True},
    )
    notifier = _telegram()
    await notifier.register_webhook("https://myserver.example.com")

    req = httpx_mock.get_requests()[0]
    body = json.loads(req.content)
    assert body["url"] == "https://myserver.example.com/telegram/webhook"
    assert body["secret_token"] == "tg-secret"


# ---------------------------------------------------------------------------
# CompositeNotifier
# ---------------------------------------------------------------------------

async def test_composite_fans_out_send():
    n1 = AsyncMock()
    n2 = AsyncMock()
    composite = CompositeNotifier([n1, n2])
    await composite.send("aid", "agent", "Tool", {}, None)
    n1.send.assert_called_once()
    n2.send.assert_called_once()


async def test_composite_fans_out_on_resolved():
    n1 = AsyncMock()
    n2 = AsyncMock()
    composite = CompositeNotifier([n1, n2])
    await composite.on_resolved("aid", True, "note")
    n1.on_resolved.assert_called_once_with("aid", True, "note")
    n2.on_resolved.assert_called_once_with("aid", True, "note")


async def test_composite_one_failure_does_not_block_other():
    n1 = AsyncMock()
    n1.send.side_effect = RuntimeError("boom")
    n2 = AsyncMock()
    composite = CompositeNotifier([n1, n2])
    await composite.send("aid", "agent", "Tool", {}, None)  # must not raise
    n2.send.assert_called_once()


# ---------------------------------------------------------------------------
# build_notifiers
# ---------------------------------------------------------------------------

def test_build_notifiers_none_when_not_configured():
    from mcp_wrapper.models import NotificationsConfig
    slack, telegram, composite = build_notifiers(NotificationsConfig(), _resolver())
    assert slack is None
    assert telegram is None
    assert composite is None


def test_build_notifiers_slack_only():
    from mcp_wrapper.models import NotificationsConfig
    cfg = NotificationsConfig(
        slack=SlackConfig(bot_token="xoxb", channel="C1", signing_secret="s")
    )
    slack, telegram, composite = build_notifiers(cfg, _resolver())
    assert slack is not None
    assert telegram is None
    assert composite is not None


def test_build_notifiers_both():
    from mcp_wrapper.models import NotificationsConfig
    cfg = NotificationsConfig(
        slack=SlackConfig(bot_token="xoxb", channel="C1", signing_secret="s"),
        telegram=TelegramConfig(bot_token="123:ABC", chat_id="-1"),
    )
    slack, telegram, composite = build_notifiers(cfg, _resolver())
    assert slack is not None
    assert telegram is not None
    assert composite is not None


# ---------------------------------------------------------------------------
# ApprovalManager integration — notifier called with redacted params
# ---------------------------------------------------------------------------

async def test_approval_manager_calls_notifier_with_redacted_params():
    from mcp_wrapper.approvals import ApprovalManager

    notifier = AsyncMock()
    dlp = _dlp()
    mgr = ApprovalManager(
        webhook_url=None,
        base_url="http://localhost",
        timeout_seconds=5,
        notifier=notifier,
        dlp=dlp,
    )

    async def _resolve():
        await asyncio.sleep(0.05)
        approval_id = next(iter(mgr._pending))
        mgr.resolve(approval_id, approved=True)

    asyncio.create_task(_resolve())
    await mgr.request(
        agent_id="agent1",
        tool="Op",
        params={"ssn": "123-45-6789"},
        reason="test",
    )

    notifier.send.assert_called_once()
    call_params = notifier.send.call_args[0][3]  # positional: (approval_id, agent_id, tool, params, reason)
    assert "123-45-6789" not in json.dumps(call_params)
    assert "REDACTED" in json.dumps(call_params)


async def test_approval_manager_calls_on_resolved_after_resolve():
    from mcp_wrapper.approvals import ApprovalManager

    notifier = AsyncMock()
    mgr = ApprovalManager(
        webhook_url=None,
        base_url="http://localhost",
        timeout_seconds=5,
        notifier=notifier,
        dlp=None,
    )

    async def _resolve():
        await asyncio.sleep(0.05)
        approval_id = next(iter(mgr._pending))
        mgr.resolve(approval_id, approved=False, note="denied by test")

    asyncio.create_task(_resolve())
    await mgr.request(agent_id="a", tool="T", params={}, reason=None)

    # Give the create_task a tick to run
    await asyncio.sleep(0.05)
    notifier.on_resolved.assert_called_once()
    args = notifier.on_resolved.call_args[0]
    assert args[1] is False
    assert args[2] == "denied by test"
