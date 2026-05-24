from __future__ import annotations

import json
import textwrap

import pytest

from mcp_wrapper.response import apply_grep_to_content, apply_jq_to_content
from mcp_wrapper.workflow import WorkflowRegistry
from mcp_wrapper.models import WorkflowToolConfig


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _text_result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


def _get_text(result: dict) -> str:
    return result["content"][0]["text"]


# ---------------------------------------------------------------------------
# apply_grep_to_content
# ---------------------------------------------------------------------------

def test_grep_keeps_matching_lines():
    result = _text_result("foo bar\nbaz\nfoo qux")
    out = apply_grep_to_content(result, r"foo")
    assert _get_text(out) == "foo bar\nfoo qux"


def test_grep_drops_all_non_matching():
    result = _text_result("alpha\nbeta\ngamma")
    out = apply_grep_to_content(result, r"delta")
    assert _get_text(out) == ""


def test_grep_passthrough_non_dict():
    assert apply_grep_to_content("plain string", r"x") == "plain string"


def test_grep_passthrough_missing_content():
    assert apply_grep_to_content({"other": "data"}, r"x") == {"other": "data"}


def test_grep_passthrough_non_text_content():
    result = {"content": [{"type": "image", "data": "..."}]}
    assert apply_grep_to_content(result, r"x") == result


def test_grep_invalid_regex_passthrough():
    result = _text_result("hello world")
    out = apply_grep_to_content(result, r"[invalid")
    assert out == result


def test_grep_preserves_extra_content_items():
    result = {"content": [{"type": "text", "text": "keep\ndrop"}, {"type": "image", "data": "img"}]}
    out = apply_grep_to_content(result, r"keep")
    assert _get_text(out) == "keep"
    assert out["content"][1] == {"type": "image", "data": "img"}


# ---------------------------------------------------------------------------
# apply_jq_to_content
# ---------------------------------------------------------------------------

def test_jq_extracts_field():
    data = {"name": "alice", "age": 30}
    result = _text_result(json.dumps(data))
    out = apply_jq_to_content(result, ".name")
    assert _get_text(out) == "alice"


def test_jq_filters_array():
    data = [{"v": 1}, {"v": 2}, {"v": 3}]
    result = _text_result(json.dumps(data))
    out = apply_jq_to_content(result, "[.[] | select(.v > 1)]")
    assert json.loads(_get_text(out)) == [{"v": 2}, {"v": 3}]


def test_jq_passthrough_non_dict():
    assert apply_jq_to_content("plain", ".x") == "plain"


def test_jq_passthrough_non_json_text():
    result = _text_result("not json")
    assert apply_jq_to_content(result, ".x") == result


def test_jq_passthrough_failed_expression():
    result = _text_result(json.dumps({"a": 1}))
    out = apply_jq_to_content(result, ".nonexistent_bad_expr | error")
    assert out == result


def test_jq_preserves_extra_content_items():
    result = {"content": [{"type": "text", "text": '{"x": 1}'}, {"type": "image", "data": "img"}]}
    out = apply_jq_to_content(result, ".x")
    assert _get_text(out) == "1"
    assert out["content"][1] == {"type": "image", "data": "img"}


# ---------------------------------------------------------------------------
# workflow step transforms via WorkflowRegistry.execute
# ---------------------------------------------------------------------------

def _make_registry(tmp_path, yaml_text: str) -> WorkflowRegistry:
    wf_file = tmp_path / "wf.yaml"
    wf_file.write_text(textwrap.dedent(yaml_text))
    cfg = {"mywf": WorkflowToolConfig(path=str(wf_file))}
    return WorkflowRegistry(cfg)


async def _caller(tool_name: str, params: dict) -> dict:
    if tool_name == "search":
        return _text_result("error: something\nresult: alpha\nresult: beta\nwarn: ignore")
    if tool_name == "fetch":
        return _text_result(json.dumps({"items": [{"id": 1}, {"id": 2}], "total": 2}))
    return _text_result("ok")


@pytest.mark.asyncio
async def test_workflow_response_grep_filters_step_result(tmp_path):
    registry = _make_registry(tmp_path, """
        steps:
          - id: s1
            tool: search
            params: {}
            response_grep: "^result:"
    """)
    result = await registry.execute("mywf", {}, tool_caller=_caller)
    assert _get_text(result) == "result: alpha\nresult: beta"


@pytest.mark.asyncio
async def test_workflow_response_jq_filters_step_result(tmp_path):
    registry = _make_registry(tmp_path, """
        steps:
          - id: s1
            tool: fetch
            params: {}
            response_jq: ".items"
    """)
    result = await registry.execute("mywf", {}, tool_caller=_caller)
    assert json.loads(_get_text(result)) == [{"id": 1}, {"id": 2}]


@pytest.mark.asyncio
async def test_workflow_grep_then_next_step_sees_filtered_state(tmp_path):
    """Filtered result is what gets stored in state["steps"] for downstream steps."""
    registry = _make_registry(tmp_path, """
        steps:
          - id: s1
            tool: search
            params: {}
            response_grep: "^result:"
          - id: s2
            tool: search
            params: {}
            return: "{{ steps.s1 }}"
    """)
    result = await registry.execute("mywf", {}, tool_caller=_caller)
    assert "result: alpha" in _get_text(result)
    assert "error:" not in _get_text(result)


@pytest.mark.asyncio
async def test_workflow_response_grep_and_jq_combined(tmp_path):
    """grep runs before jq; jq sees the grepped text."""
    # grep keeps only lines with "result:", leaving "result: alpha\nresult: beta"
    # that's not valid JSON so jq passes through unchanged
    registry = _make_registry(tmp_path, """
        steps:
          - id: s1
            tool: search
            params: {}
            response_grep: "^result:"
            response_jq: ".name"
    """)
    result = await registry.execute("mywf", {}, tool_caller=_caller)
    # jq fails on non-JSON, so we get the grepped text back
    assert _get_text(result) == "result: alpha\nresult: beta"


def test_validate_invalid_response_grep_regex(tmp_path):
    registry = _make_registry(tmp_path, """
        steps:
          - id: s1
            tool: search
            params: {}
            response_grep: "[invalid"
    """)
    assert "mywf" not in registry._definitions
    assert "invalid regex" in registry._errors.get("mywf", "")


def test_validate_valid_response_grep_no_error(tmp_path):
    registry = _make_registry(tmp_path, """
        steps:
          - id: s1
            tool: search
            params: {}
            response_grep: "^result:"
    """)
    assert "mywf" in registry._definitions
    assert "mywf" not in registry._errors
