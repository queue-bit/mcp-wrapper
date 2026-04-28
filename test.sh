#!/usr/bin/env bash
# Manual test commands for the MCP wrapper.
# Usage: source test.sh   (loads helpers into your shell)
#    or: bash test.sh <command>

BASE="http://localhost:8080"
TOKEN="${DEFAULT_AGENT_TOKEN}"

health() {
    curl -s "$BASE/health"
}

tools_list() {
    curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$BASE/mcp/tools/list" | python3 -m json.tool
}

audit() {
    local limit="${1:-20}"
    curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$BASE/audit/recent?limit=$limit" | python3 -m json.tool
}

# Filter audit log: audit_filter [key=value ...]
# Examples:
#   audit_filter decision=denied
#   audit_filter tool=HassLightSet
#   audit_filter mcp_server=homeassistant decision=allowed
#   audit_filter since=2025-01-01T00:00:00
audit_filter() {
    local qs=""
    for arg in "$@"; do
        qs="${qs}&${arg}"
    done
    curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$BASE/audit/recent?${qs#&}" | python3 -m json.tool
}

stats() {
    local qs=""
    for arg in "$@"; do
        qs="${qs}&${arg}"
    done
    curl -s \
        -H "Authorization: Bearer $TOKEN" \
        "$BASE/audit/stats?${qs#&}" | python3 -m json.tool
}

call_tool() {
    local tool="$1"
    local params="${2}"
    [[ -z "$params" ]] && params="{}"
    curl -s \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"tool\": \"$tool\", \"params\": $params}" \
        "$BASE/mcp/tools/call" | python3 -m json.tool
}

test_denied() {
    echo "--- should be denied (not in ruleset) ---"
    call_tool "NotARealTool" "{}"
    echo "--- check audit log for denial ---"
    audit 5
}

approve() {
    local approval_id="$1"
    local note="${2:-approved}"
    curl -s \
        -H "Content-Type: application/json" \
        -d "{\"approved\": true, \"note\": \"$note\"}" \
        "$BASE/approval/$approval_id" | python3 -m json.tool
}

deny_approval() {
    local approval_id="$1"
    local note="${2:-denied}"
    curl -s \
        -H "Content-Type: application/json" \
        -d "{\"approved\": false, \"note\": \"$note\"}" \
        "$BASE/approval/$approval_id" | python3 -m json.tool
}

# Run a named function if passed as argument, otherwise print usage
if [[ -n "$1" ]]; then
    "$@"
else
    echo "Available commands (source this file first):"
    echo "  health"
    echo "  tools_list"
    echo "  audit [limit]"
    echo "  audit_filter [key=value ...]   # e.g. decision=denied tool=Hass*"
    echo "  stats [since=ISO] [until=ISO]"
    echo "  call_tool <tool_name> [json_params]"
    echo "  test_denied"
    echo "  approve <approval_id> [note]"
    echo "  deny_approval <approval_id> [note]"
fi
