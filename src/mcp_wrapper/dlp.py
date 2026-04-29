from __future__ import annotations

import copy
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, Field

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config models (also imported by models.py)
# ---------------------------------------------------------------------------

class DlpPattern(BaseModel):
    name: str
    pattern: str
    action: Literal["block", "redact", "warn", "approve"] = "warn"
    enabled: bool = True


class DlpConfig(BaseModel):
    enabled: bool = True
    # Additional patterns merged with (or overriding) built-ins by name.
    outbound: list[DlpPattern] = Field(default_factory=list)
    inbound: list[DlpPattern] = Field(default_factory=list)
    # Set False to disable the entire built-in list for that direction.
    use_builtin_outbound: bool = True
    use_builtin_inbound: bool = True


# ---------------------------------------------------------------------------
# Built-in pattern sets
# ---------------------------------------------------------------------------

#: Patterns applied to tool-call params before forwarding to MCP servers.
OUTBOUND_DEFAULTS: list[DlpPattern] = [
    DlpPattern(
        name="private_key",
        pattern=r"-----BEGIN [^-]*PRIVATE KEY-----",
        action="block",
    ),
    DlpPattern(
        name="aws_access_key",
        pattern=r"\bAKIA[0-9A-Z]{16}\b",
        action="block",
    ),
    DlpPattern(
        name="github_token",
        pattern=r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        action="block",
    ),
    # Covers OpenAI (sk-…) and Anthropic (sk-ant-…) API keys.
    DlpPattern(
        name="api_key_sk",
        pattern=r"\bsk-[A-Za-z0-9-]{20,}\b",
        action="block",
    ),
    DlpPattern(
        name="credit_card",
        pattern=r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
        action="warn",
    ),
    DlpPattern(
        name="ssn",
        pattern=r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b",
        action="warn",
    ),
]

#: Patterns applied to MCP server responses before returning to the agent.
INBOUND_DEFAULTS: list[DlpPattern] = [
    # "Ignore all previous instructions / rules / prompts"
    DlpPattern(
        name="ignore_instructions",
        pattern=r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|guidelines?|prompts?)",
        action="redact",
    ),
    # <system> / [SYSTEM] / ### System injection tags
    DlpPattern(
        name="system_tag",
        pattern=r"(?i)<\s*/?\s*system\s*>|\[SYSTEM\]|###\s*[Ss]ystem",
        action="redact",
    ),
    # Classic jailbreak phrases
    DlpPattern(
        name="jailbreak",
        pattern=r"(?i)\b(DAN\s+mode|do\s+anything\s+now|jailbreak\s+mode)\b",
        action="redact",
    ),
    # Attempts to leak the system prompt
    DlpPattern(
        name="prompt_leak",
        pattern=r"(?i)(repeat|print|reveal|output|show)\s+(your|the|all)\s+(system\s+prompt|instructions?|context|guidelines)",
        action="redact",
    ),
    # Suspicious redirection ("tell the user to visit…")
    DlpPattern(
        name="indirect_injection",
        pattern=r"(?i)tell\s+(?:the\s+)?(?:user|human|assistant)\s+to\s+",
        action="warn",
    ),
]


# ---------------------------------------------------------------------------
# Runtime types
# ---------------------------------------------------------------------------

@dataclass
class DlpViolation:
    pattern_name: str
    action: str          # block | redact | warn
    field_path: str      # e.g. "entity_id" or "content[0].text"


@dataclass
class DlpScanResult:
    violations: list[DlpViolation] = field(default_factory=list)
    blocked: bool = False
    needs_approval: bool = False
    sanitized: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

_REDACT_PLACEHOLDER = "[REDACTED:{name}]"
_CompiledPatterns = list[tuple[DlpPattern, re.Pattern]]


class DlpScanner:
    def __init__(self, config: DlpConfig):
        self._config = config
        self._outbound = self._build(
            OUTBOUND_DEFAULTS if config.use_builtin_outbound else [],
            config.outbound,
        )
        self._inbound = self._build(
            INBOUND_DEFAULTS if config.use_builtin_inbound else [],
            config.inbound,
        )

    @staticmethod
    def _build(
        defaults: list[DlpPattern],
        overrides: list[DlpPattern],
    ) -> _CompiledPatterns:
        """Merge defaults with user overrides (by name), then compile."""
        merged: dict[str, DlpPattern] = {p.name: p for p in defaults}
        for p in overrides:
            merged[p.name] = p  # override or add
        compiled: _CompiledPatterns = []
        for p in merged.values():
            if not p.enabled:
                continue
            try:
                compiled.append((p, re.compile(p.pattern)))
            except re.error as exc:
                log.warning("Invalid DLP pattern %r: %s", p.name, exc)
        return compiled

    # ------------------------------------------------------------------

    def redact_for_display(self, value: dict[str, Any]) -> dict[str, Any]:
        """Return a deep copy of *value* with all outbound matches forcibly redacted.

        Used for notification payloads (Slack, Telegram) where the configured
        action (block / warn / approve) is irrelevant — everything sensitive
        must be masked before leaving the process.
        """
        node = copy.deepcopy(value)
        forced = [
            (DlpPattern(name=p.name, pattern=p.pattern, action="redact"), regex)
            for p, regex in self._outbound
        ]
        self._walk(node, forced, DlpScanResult(), "")
        return node

    def scan_outbound(self, params: dict[str, Any]) -> DlpScanResult:
        if not self._config.enabled:
            return DlpScanResult(sanitized=params)
        return self._scan(params, self._outbound)

    def scan_inbound(self, response: dict[str, Any]) -> DlpScanResult:
        if not self._config.enabled:
            return DlpScanResult(sanitized=response)
        return self._scan(response, self._inbound)

    # ------------------------------------------------------------------

    def _scan(self, value: dict[str, Any], patterns: _CompiledPatterns) -> DlpScanResult:
        result = DlpScanResult(sanitized=copy.deepcopy(value))
        self._walk(result.sanitized, patterns, result, "")
        result.blocked = any(v.action == "block" for v in result.violations)
        result.needs_approval = any(v.action == "approve" for v in result.violations)
        return result

    def _walk(
        self,
        node: Any,
        patterns: _CompiledPatterns,
        result: DlpScanResult,
        path: str,
    ) -> Any:
        if isinstance(node, dict):
            for k, v in node.items():
                child_path = f"{path}.{k}" if path else k
                node[k] = self._walk(v, patterns, result, child_path)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                node[i] = self._walk(item, patterns, result, f"{path}[{i}]")
        elif isinstance(node, str):
            for pattern, regex in patterns:
                if regex.search(node):
                    result.violations.append(
                        DlpViolation(
                            pattern_name=pattern.name,
                            action=pattern.action,
                            field_path=path,
                        )
                    )
                    if pattern.action == "redact":
                        node = regex.sub(
                            _REDACT_PLACEHOLDER.format(name=pattern.name), node
                        )
        return node
