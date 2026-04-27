from __future__ import annotations

import fnmatch
import re
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import ServerRules, ToolConstraint, WrapperConfig


def get_effective_rules(
    config: WrapperConfig, agent_id: str, server_name: str
) -> ServerRules | None:
    """Return the rules for this agent+server pair.

    Agent override takes precedence over server defaults.
    Returns None if neither is configured.
    """
    agent_overrides = config.agent_overrides.get(agent_id, {})
    if server_name in agent_overrides:
        return agent_overrides[server_name]
    return config.server_rules.get(server_name)


def check_tool(
    rules: ServerRules, tool_name: str
) -> tuple[bool, ToolConstraint | None]:
    """Return (allowed, constraint).

    Checks constrain dict first (exact match), then allow list (fnmatch).
    Constraint is None for tools matched by the allow list.
    """
    if tool_name in rules.constrain:
        return True, rules.constrain[tool_name]
    if any(fnmatch.fnmatch(tool_name, pattern) for pattern in rules.allow):
        return True, None
    return False, None


def validate_params(params: dict[str, Any], constraint: ToolConstraint) -> str | None:
    """Return a denial reason if any param constraint is violated, else None."""
    for param_name, pc in constraint.allowed_params.items():
        value = params.get(param_name)
        if value is None:
            continue

        if pc.allowlist is not None:
            if str(value) not in pc.allowlist:
                return f"param {param_name!r}: {value!r} not in allowlist {pc.allowlist}"

        if pc.pattern is not None:
            if not re.fullmatch(pc.pattern, str(value)):
                return f"param {param_name!r}: {value!r} does not match pattern {pc.pattern!r}"

        if pc.minimum is not None or pc.maximum is not None:
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                return f"param {param_name!r}: expected numeric value, got {value!r}"
            if pc.minimum is not None and numeric < pc.minimum:
                return f"param {param_name!r}: {value} is below minimum {pc.minimum}"
            if pc.maximum is not None and numeric > pc.maximum:
                return f"param {param_name!r}: {value} is above maximum {pc.maximum}"

    return None
