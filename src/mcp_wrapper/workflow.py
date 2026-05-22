from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Awaitable, Callable

import yaml
from jinja2.sandbox import SandboxedEnvironment

from .models import WorkflowToolConfig

log = logging.getLogger(__name__)

_FALSY_RENDERS = {"", "False", "false", "None", "none", "0", "[]", "{}"}

_jinja_env = SandboxedEnvironment()
_jinja_env.filters["tojson"] = json.dumps  # type: ignore[assignment]


def _render_condition(expr: str, state: dict[str, Any]) -> bool:
    rendered = _jinja_env.from_string("{{ " + expr + " }}").render(state)
    return rendered.strip() not in _FALSY_RENDERS


def _render_template(tmpl: str, state: dict[str, Any]) -> str:
    return _jinja_env.from_string(tmpl).render(state)


def _extract_result(raw: dict[str, Any]) -> Any:
    content = raw.get("content", [])
    if isinstance(content, list) and content:
        text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
    else:
        text = str(raw)
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text


def _validate_yaml_structure(defn: dict[str, Any]) -> list[str]:
    """Return a list of validation errors (empty = valid)."""
    errors: list[str] = []
    steps = defn.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("'steps' must be a non-empty list")
        return errors
    seen_ids: set[str] = set()
    for i, step in enumerate(steps):
        step_id = step.get("id")
        if not step_id:
            errors.append(f"step {i}: missing 'id'")
            continue
        if step_id in seen_ids:
            errors.append(f"step '{step_id}': duplicate id")
        seen_ids.add(step_id)
        if "tool" in step and "params" in step and not isinstance(step["params"], dict):
            errors.append(f"step '{step_id}': 'params' must be a dict")
        for field in ("when", "return"):
            if field in step:
                try:
                    _jinja_env.parse("{{ " + str(step[field]) + " }}")
                except Exception:
                    errors.append(f"step '{step_id}': invalid Jinja2 syntax in {field!r}")
    return errors


class WorkflowRegistry:
    VIRTUAL_SERVER_NAME = "__workflows__"

    def __init__(self, configs: dict[str, WorkflowToolConfig]) -> None:
        self._configs = configs
        self._definitions: dict[str, dict[str, Any]] = {}
        self._errors: dict[str, str] = {}
        self._load_all()

    def _load_all(self) -> None:
        self._definitions.clear()
        self._errors.clear()
        for name, cfg in self._configs.items():
            self._load_one(name, cfg)

    def _load_one(self, name: str, cfg: WorkflowToolConfig) -> None:
        try:
            text = Path(cfg.path).read_text(encoding="utf-8")
            defn = yaml.safe_load(text)
            if not isinstance(defn, dict):
                raise ValueError("YAML root must be a mapping")
            errs = _validate_yaml_structure(defn)
            if errs:
                raise ValueError("; ".join(errs))
            self._definitions[name] = defn
        except Exception as exc:
            log.warning("workflow %r failed to load: %s", name, exc)
            self._errors[name] = str(exc)

    def reload(self, new_configs: dict[str, WorkflowToolConfig]) -> None:
        self._configs = new_configs
        self._load_all()

    def has_tool(self, name: str) -> bool:
        return name in self._definitions

    def get_definition(self, name: str) -> dict[str, Any] | None:
        return self._definitions.get(name)

    def list_all_definitions(self) -> list[dict[str, Any]]:
        result = []
        for name, defn in self._definitions.items():
            result.append({
                "name": name,
                "description": defn.get("description", ""),
                "inputSchema": defn.get("input_schema", {"type": "object", "properties": {}}),
            })
        return result

    def list_all_rows(self) -> list[dict[str, Any]]:
        """Admin UI helper — all workflows including errored ones."""
        rows = []
        for name in self._configs:
            defn = self._definitions.get(name)
            rows.append({
                "name": name,
                "description": (defn.get("description", "") if defn else "")[:80],
                "step_count": len(defn.get("steps", [])) if defn else 0,
                "status": "ok" if defn else "error",
                "error": self._errors.get(name, ""),
                "path": self._configs[name].path,
            })
        return rows

    async def execute(
        self,
        name: str,
        params: dict[str, Any],
        agent_id: str = "",
        tool_caller: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]] | None = None,
        trace: bool = False,
    ) -> dict[str, Any] | tuple[dict[str, Any], list[dict[str, Any]]]:
        defn = self._definitions.get(name)
        if defn is None:
            raise ValueError(f"Workflow {name!r} not found")

        state: dict[str, Any] = {"input": params, "steps": {}}
        trace_entries: list[dict[str, Any]] = []
        last_result: dict[str, Any] = {"content": [{"type": "text", "text": ""}]}

        for step in defn.get("steps", []):
            step_id: str = step["id"]
            entry: dict[str, Any] = {"step_id": step_id, "skipped": False, "when_result": None,
                                      "params": None, "result": None, "returned": None}

            when_expr = step.get("when")
            if when_expr is not None:
                try:
                    cond = _render_condition(str(when_expr), state)
                except Exception as exc:
                    log.warning("workflow %r step %r when-condition error: %s", name, step_id, exc)
                    cond = False
                entry["when_result"] = cond
                if not cond:
                    entry["skipped"] = True
                    trace_entries.append(entry)
                    continue

            tool_name = step.get("tool")
            rendered_params: dict[str, Any] = {}
            if tool_name:
                raw_params = step.get("params") or {}
                for k, v in raw_params.items():
                    if isinstance(v, str):
                        try:
                            rendered_params[k] = _render_template(v, state)
                        except Exception as exc:
                            log.warning("workflow %r step %r param %r template error: %s", name, step_id, k, exc)
                            rendered_params[k] = v
                    else:
                        rendered_params[k] = v

                entry["params"] = rendered_params
                if tool_caller is None:
                    raise RuntimeError("Workflow requires a tool_caller but none was provided")
                raw_result = await tool_caller(tool_name, rendered_params)
                parsed = _extract_result(raw_result)
                state["steps"][step_id] = parsed
                last_result = raw_result
                entry["result"] = parsed
            else:
                state["steps"][step_id] = None

            return_tmpl = step.get("return")
            if return_tmpl is not None:
                try:
                    rendered = _render_template(str(return_tmpl), state)
                except Exception as exc:
                    log.warning("workflow %r step %r return template error: %s", name, step_id, exc)
                    rendered = str(return_tmpl)
                entry["returned"] = rendered
                trace_entries.append(entry)
                final = {"content": [{"type": "text", "text": rendered}]}
                if trace:
                    return final, trace_entries
                return final

            trace_entries.append(entry)

        if trace:
            return last_result, trace_entries
        return last_result
