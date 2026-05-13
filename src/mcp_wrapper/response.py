from __future__ import annotations

import json
from typing import Any

_MISSING = object()


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
