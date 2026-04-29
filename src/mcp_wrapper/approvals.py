from __future__ import annotations

import asyncio
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from .dlp import DlpScanner
    from .notifications import NotificationProvider

log = logging.getLogger(__name__)


@dataclass
class PendingApproval:
    approval_id: str
    agent_id: str
    tool: str
    params: dict[str, Any]
    reason: str | None
    event: asyncio.Event = field(default_factory=asyncio.Event)
    approved: bool = False
    note: str | None = None


class ApprovalManager:
    def __init__(
        self,
        webhook_url: str | None,
        base_url: str,
        timeout_seconds: int = 300,
        notifier: NotificationProvider | None = None,
        dlp: DlpScanner | None = None,
    ):
        self._webhook_url = webhook_url
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._notifier = notifier
        self._dlp = dlp
        self._pending: dict[str, PendingApproval] = {}

    async def request(
        self,
        agent_id: str,
        tool: str,
        params: dict[str, Any],
        reason: str | None,
    ) -> tuple[bool, str, str | None]:
        """Submit an approval request. Returns (approved, approval_id, note)."""
        approval_id = uuid.uuid4().hex
        pending = PendingApproval(
            approval_id=approval_id,
            agent_id=agent_id,
            tool=tool,
            params=params,
            reason=reason,
        )
        self._pending[approval_id] = pending

        await self._notify(pending)

        try:
            await asyncio.wait_for(pending.event.wait(), timeout=float(self._timeout))
            return pending.approved, approval_id, pending.note
        except asyncio.TimeoutError:
            return False, approval_id, "approval timed out"
        finally:
            self._pending.pop(approval_id, None)

    def resolve(self, approval_id: str, approved: bool, note: str | None = None) -> bool:
        """Called by the approval endpoint. Returns False if the ID is unknown/expired."""
        pending = self._pending.get(approval_id)
        if pending is None:
            return False
        pending.approved = approved
        pending.note = note
        pending.event.set()
        if self._notifier is not None:
            asyncio.create_task(
                self._notifier.on_resolved(approval_id, approved, note)
            )
        return True

    async def _notify(self, pending: PendingApproval) -> None:
        approve_url = f"{self._base_url}/approval/{pending.approval_id}"
        log.warning(
            "APPROVAL REQUIRED: agent=%s tool=%s approval_id=%s — POST %s {'approved': true/false, 'note': '...'}",
            pending.agent_id,
            pending.tool,
            pending.approval_id,
            approve_url,
        )

        if self._notifier is not None:
            safe_params = (
                self._dlp.redact_for_display(pending.params)
                if self._dlp is not None
                else pending.params
            )
            safe_reason = _redact_reason(pending.reason, self._dlp) if pending.reason else pending.reason
            await self._notifier.send(
                pending.approval_id,
                pending.agent_id,
                pending.tool,
                safe_params,
                safe_reason,
            )

        if not self._webhook_url:
            return
        payload = {
            "approval_id": pending.approval_id,
            "agent_id": pending.agent_id,
            "tool": pending.tool,
            "params": pending.params,
            "reason": pending.reason,
            "approve_url": approve_url,
        }
        try:
            async with httpx.AsyncClient() as client:
                await client.post(self._webhook_url, json=payload, timeout=10.0)
        except Exception as e:
            log.warning("Approval webhook notification failed: %s", e)


def _redact_reason(reason: str, dlp: DlpScanner | None) -> str:
    """Run outbound DLP patterns against a plain-text reason string."""
    if dlp is None:
        return reason
    result = dlp.redact_for_display({"_r": reason})
    return result.get("_r", reason)
