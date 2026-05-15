from __future__ import annotations

import json
import logging
import re
from typing import Any

log = logging.getLogger(__name__)

_MISSING = object()


def apply_jq_to_content(result: Any, jq_expr: str) -> Any:
    """Apply a jq filter to the JSON text payload of an MCP content response."""
    if not isinstance(result, dict):
        return result
    content = result.get("content")
    if not isinstance(content, list) or not content:
        return result
    first = content[0]
    if not isinstance(first, dict) or first.get("type") != "text":
        return result
    text = first.get("text", "")
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return result
    try:
        import jq as jq_lib
        items = jq_lib.compile(jq_expr).input(data).all()
        filtered = items[0] if len(items) == 1 else items
        new_text = filtered if isinstance(filtered, str) else json.dumps(filtered, ensure_ascii=False)
    except Exception as exc:
        log.warning("response_jq filter %r failed: %s — top-level keys: %s", jq_expr, exc,
                    list(data.keys()) if isinstance(data, dict) else type(data).__name__)
        return result
    return {**result, "content": [{"type": "text", "text": new_text}, *content[1:]]}


def apply_grep_to_content(result: Any, pattern: str) -> Any:
    """Keep only lines in the text payload that match a regex pattern."""
    if not isinstance(result, dict):
        return result
    content = result.get("content")
    if not isinstance(content, list) or not content:
        return result
    first = content[0]
    if not isinstance(first, dict) or first.get("type") != "text":
        return result
    text = first.get("text", "")
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        log.warning("response_grep pattern %r invalid: %s", pattern, exc)
        return result
    matched = [line for line in text.splitlines() if compiled.search(line)]
    new_text = "\n".join(matched)
    return {**result, "content": [{"type": "text", "text": new_text}, *content[1:]]}


def _get_path(data: Any, path: str) -> Any:
    node = data
    for key in path.split("."):
        try:
            node = node[int(key)] if isinstance(node, list) else node[key]
        except (KeyError, IndexError, TypeError, ValueError):
            return _MISSING
    return node


def shape_response(
    data: Any,
    response_fields: list[str] | None,
    max_response_chars: int | None,
) -> Any:
    """Filter fields and/or truncate a response before returning it to the agent."""
    if response_fields is not None and isinstance(data, dict):
        data = {path: v for path in response_fields if (v := _get_path(data, path)) is not _MISSING}

    if max_response_chars is not None:
        text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
        if len(text) > max_response_chars:
            removed = len(text) - max_response_chars
            data = text[:max_response_chars] + f" …[{removed} chars truncated]"

    return data
