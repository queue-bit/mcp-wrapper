from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any

import httpx

from .credentials import SecretResolver
from .models import NotificationsConfig, SlackConfig, TelegramConfig

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class NotificationProvider(ABC):
    @abstractmethod
    async def send(
        self,
        approval_id: str,
        agent_id: str,
        tool: str,
        params: dict[str, Any],
        reason: str | None,
    ) -> None: ...

    @abstractmethod
    async def on_resolved(
        self,
        approval_id: str,
        approved: bool,
        note: str | None,
    ) -> None: ...

    @abstractmethod
    async def send_alert(self, title: str, message: str) -> None: ...


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

class SlackNotifier(NotificationProvider):
    _API = "https://slack.com/api"

    def __init__(self, config: SlackConfig, resolver: SecretResolver):
        self._token = resolver.resolve(config.bot_token)
        self._channel = config.channel
        self._signing_secret = resolver.resolve(config.signing_secret)
        # approval_id -> {ts, channel, header_block, detail_block}
        self._sent: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Outbound

    async def send(
        self,
        approval_id: str,
        agent_id: str,
        tool: str,
        params: dict[str, Any],
        reason: str | None,
    ) -> None:
        params_text = json.dumps(params, indent=2)[:500]
        detail_block: dict = {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Agent:*\n{agent_id}"},
                {"type": "mrkdwn", "text": f"*Tool:*\n`{tool}`"},
                {"type": "mrkdwn", "text": f"*Reason:*\n{reason or '_not provided_'}"},
                {"type": "mrkdwn", "text": f"*Params:*\n```{params_text}```"},
            ],
        }
        header_block: dict = {
            "type": "header",
            "text": {"type": "plain_text", "text": "Approval Required"},
        }
        blocks = [
            header_block,
            detail_block,
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "style": "primary",
                        "action_id": "approve",
                        "value": f"approve:{approval_id}",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Deny"},
                        "style": "danger",
                        "action_id": "deny",
                        "value": f"deny:{approval_id}",
                    },
                ],
            },
        ]
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self._API}/chat.postMessage",
                    headers={"Authorization": f"Bearer {self._token}"},
                    json={
                        "channel": self._channel,
                        "text": f"Approval required: {tool}",
                        "blocks": blocks,
                    },
                    timeout=10.0,
                )
            data = resp.json()
            if data.get("ok"):
                self._sent[approval_id] = {
                    "ts": data["ts"],
                    "channel": data["channel"],
                    "header_block": header_block,
                    "detail_block": detail_block,
                }
            else:
                log.error("Slack chat.postMessage failed: %s", data.get("error"))
        except Exception as exc:
            log.error("Slack send failed: %s", exc)

    async def on_resolved(
        self,
        approval_id: str,
        approved: bool,
        note: str | None,
    ) -> None:
        sent = self._sent.pop(approval_id, None)
        if not sent:
            return
        outcome = ("✅ Approved" if approved else "❌ Denied") + (
            f": _{note}_" if note else ""
        )
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{self._API}/chat.update",
                    headers={"Authorization": f"Bearer {self._token}"},
                    json={
                        "channel": sent["channel"],
                        "ts": sent["ts"],
                        "text": outcome,
                        "blocks": [
                            sent["header_block"],
                            sent["detail_block"],
                            {
                                "type": "section",
                                "text": {"type": "mrkdwn", "text": f"*{outcome}*"},
                            },
                        ],
                    },
                    timeout=10.0,
                )
        except Exception as exc:
            log.error("Slack chat.update failed: %s", exc)

    async def send_alert(self, title: str, message: str) -> None:
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": title}},
            {"type": "section", "text": {"type": "mrkdwn", "text": message}},
        ]
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{self._API}/chat.postMessage",
                    headers={"Authorization": f"Bearer {self._token}"},
                    json={"channel": self._channel, "text": title, "blocks": blocks},
                    timeout=10.0,
                )
            data = resp.json()
            if not data.get("ok"):
                log.error("Slack send_alert failed: %s", data.get("error"))
        except Exception as exc:
            log.error("Slack send_alert error: %s", exc)

    # ------------------------------------------------------------------
    # Inbound

    def verify_signature(self, body: bytes, timestamp: str, signature: str) -> bool:
        try:
            if abs(time.time() - float(timestamp)) > 300:
                return False
            base = f"v0:{timestamp}:{body.decode()}"
            expected = "v0=" + hmac.new(
                self._signing_secret.encode(), base.encode(), hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(expected, signature)
        except Exception:
            return False

    async def handle_interact(self, payload: dict, approvals: Any) -> None:
        actions = payload.get("actions", [])
        if not actions:
            return
        value = actions[0].get("value", "")
        if ":" not in value:
            return
        decision, approval_id = value.split(":", 1)
        approved = decision == "approve"
        user = payload.get("user", {}).get("name", "unknown")
        note = f"{'approved' if approved else 'denied'} by {user} via Slack"
        if not approvals.resolve(approval_id, approved, note):
            log.info("Slack interact: approval %s already resolved or expired", approval_id)


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------

class TelegramNotifier(NotificationProvider):
    def __init__(self, config: TelegramConfig, resolver: SecretResolver):
        self._token = resolver.resolve(config.bot_token)
        self._chat_id = config.chat_id
        self._secret_token = (
            resolver.resolve(config.secret_token) if config.secret_token else None
        )
        # approval_id -> {message_id, chat_id, text, callback_query_id?}
        self._sent: dict[str, dict] = {}

    def _url(self, method: str) -> str:
        return f"https://api.telegram.org/bot{self._token}/{method}"

    # ------------------------------------------------------------------
    # Webhook registration

    async def register_webhook(self, base_url: str) -> None:
        webhook_url = f"{base_url.rstrip('/')}/telegram/webhook"
        payload: dict[str, Any] = {"url": webhook_url}
        if self._secret_token:
            payload["secret_token"] = self._secret_token
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    self._url("setWebhook"), json=payload, timeout=10.0
                )
            data = resp.json()
            if data.get("ok"):
                log.info("Telegram webhook registered: %s", webhook_url)
            else:
                log.warning("Telegram setWebhook failed: %s", data.get("description"))
        except Exception as exc:
            log.error("Telegram webhook registration failed: %s", exc)

    # ------------------------------------------------------------------
    # Outbound

    async def send(
        self,
        approval_id: str,
        agent_id: str,
        tool: str,
        params: dict[str, Any],
        reason: str | None,
    ) -> None:
        params_text = json.dumps(params, indent=2)[:400]
        text = (
            f"*Approval Required*\n\n"
            f"*Agent:* {agent_id}\n"
            f"*Tool:* `{tool}`\n"
            f"*Reason:* {reason or '_not provided_'}\n"
            f"*Params:*\n```{params_text}```"
        )
        keyboard = {
            "inline_keyboard": [[
                {"text": "✅ Approve", "callback_data": f"approve:{approval_id}"},
                {"text": "❌ Deny",    "callback_data": f"deny:{approval_id}"},
            ]]
        }
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    self._url("sendMessage"),
                    json={
                        "chat_id": self._chat_id,
                        "text": text,
                        "parse_mode": "Markdown",
                        "reply_markup": keyboard,
                    },
                    timeout=10.0,
                )
            data = resp.json()
            if data.get("ok"):
                msg = data["result"]
                self._sent[approval_id] = {
                    "message_id": msg["message_id"],
                    "chat_id": str(msg["chat"]["id"]),
                    "text": text,
                }
            else:
                log.error("Telegram sendMessage failed: %s", data.get("description"))
        except Exception as exc:
            log.error("Telegram send failed: %s", exc)

    async def on_resolved(
        self,
        approval_id: str,
        approved: bool,
        note: str | None,
    ) -> None:
        sent = self._sent.pop(approval_id, None)
        if not sent:
            return
        outcome = ("✅ Approved" if approved else "❌ Denied") + (
            f": {note}" if note else ""
        )
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    self._url("editMessageText"),
                    json={
                        "chat_id": sent["chat_id"],
                        "message_id": sent["message_id"],
                        "text": sent["text"] + f"\n\n*{outcome}*",
                        "parse_mode": "Markdown",
                        "reply_markup": {"inline_keyboard": []},
                    },
                    timeout=10.0,
                )
        except Exception as exc:
            log.error("Telegram editMessageText failed: %s", exc)

    async def send_alert(self, title: str, message: str) -> None:
        text = f"*{title}*\n\n{message}"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    self._url("sendMessage"),
                    json={"chat_id": self._chat_id, "text": text, "parse_mode": "Markdown"},
                    timeout=10.0,
                )
            data = resp.json()
            if not data.get("ok"):
                log.error("Telegram send_alert failed: %s", data.get("description"))
        except Exception as exc:
            log.error("Telegram send_alert error: %s", exc)

    # ------------------------------------------------------------------
    # Inbound

    def verify_secret_token(self, token: str | None) -> bool:
        if self._secret_token is None:
            # No secret configured — reject all inbound webhook calls.
            # Accepting without verification would let any caller forge approvals.
            log.warning("Telegram webhook received but no secret_token configured; rejecting.")
            return False
        return hmac.compare_digest(token or "", self._secret_token)

    async def handle_update(self, update: dict, approvals: Any) -> None:
        cb = update.get("callback_query")
        if not cb:
            return
        data_str = cb.get("data", "")
        if ":" not in data_str:
            return
        action, approval_id = data_str.split(":", 1)
        approved = action == "approve"
        note = f"{'approved' if approved else 'denied'} via Telegram"

        # Answer the callback immediately so the spinner clears on the user's phone.
        outcome_text = "✅ Approved" if approved else "❌ Denied"
        await self._answer_callback(cb["id"], outcome_text)

        # Store callback query id so on_resolved can reference it if needed.
        if approval_id in self._sent:
            self._sent[approval_id]["callback_query_id"] = cb["id"]

        if not approvals.resolve(approval_id, approved, note):
            log.info("Telegram update: approval %s already resolved or expired", approval_id)

    async def _answer_callback(self, callback_query_id: str, text: str) -> None:
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    self._url("answerCallbackQuery"),
                    json={"callback_query_id": callback_query_id, "text": text},
                    timeout=10.0,
                )
        except Exception as exc:
            log.error("Telegram answerCallbackQuery failed: %s", exc)


# ---------------------------------------------------------------------------
# Composite — fans out to all configured providers
# ---------------------------------------------------------------------------

class CompositeNotifier(NotificationProvider):
    def __init__(self, notifiers: list[NotificationProvider]):
        self._notifiers = notifiers

    async def send(self, *args: Any, **kwargs: Any) -> None:
        await asyncio.gather(
            *[n.send(*args, **kwargs) for n in self._notifiers],
            return_exceptions=True,
        )

    async def on_resolved(self, *args: Any, **kwargs: Any) -> None:
        await asyncio.gather(
            *[n.on_resolved(*args, **kwargs) for n in self._notifiers],
            return_exceptions=True,
        )

    async def send_alert(self, title: str, message: str) -> None:
        await asyncio.gather(
            *[n.send_alert(title, message) for n in self._notifiers],
            return_exceptions=True,
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_notifiers(
    config: NotificationsConfig,
    resolver: SecretResolver,
) -> tuple[SlackNotifier | None, TelegramNotifier | None, NotificationProvider | None]:
    slack = SlackNotifier(config.slack, resolver) if config.slack else None
    telegram = TelegramNotifier(config.telegram, resolver) if config.telegram else None
    active: list[NotificationProvider] = [n for n in (slack, telegram) if n is not None]
    composite: NotificationProvider | None = CompositeNotifier(active) if active else None
    return slack, telegram, composite
