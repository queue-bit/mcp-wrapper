import pytest

from mcp_wrapper.models import (
    ParamConstraint,
    RateLimitConfig,
    ServerRules,
    ToolConstraint,
    WrapperConfig,
)
from mcp_wrapper.rules import check_tool, get_effective_rules, validate_params


# ---------------------------------------------------------------------------
# check_tool
# ---------------------------------------------------------------------------

def test_exact_allow_match():
    rules = ServerRules(allow=["GetDateTime"])
    allowed, constraint = check_tool(rules, "GetDateTime")
    assert allowed is True
    assert constraint is None


def test_glob_allow_match():
    rules = ServerRules(allow=["Hass*"])
    allowed, constraint = check_tool(rules, "HassTurnOn")
    assert allowed is True
    assert constraint is None


def test_glob_no_match():
    rules = ServerRules(allow=["Hass*"])
    allowed, _ = check_tool(rules, "GetDateTime")
    assert allowed is False


def test_constrain_returns_constraint():
    tc = ToolConstraint(rate_limit=RateLimitConfig(per_minute=5))
    rules = ServerRules(constrain={"HassLightSet": tc})
    allowed, constraint = check_tool(rules, "HassLightSet")
    assert allowed is True
    assert constraint is tc


def test_constrain_takes_precedence_over_allow():
    tc = ToolConstraint(rate_limit=RateLimitConfig(per_minute=2))
    rules = ServerRules(allow=["HassLightSet"], constrain={"HassLightSet": tc})
    allowed, constraint = check_tool(rules, "HassLightSet")
    assert allowed is True
    assert constraint is tc


def test_tool_not_in_any_list():
    rules = ServerRules(allow=["GetDateTime"])
    allowed, constraint = check_tool(rules, "DeleteEverything")
    assert allowed is False
    assert constraint is None


def test_empty_rules_denies_all():
    rules = ServerRules()
    assert check_tool(rules, "anything")[0] is False


# ---------------------------------------------------------------------------
# validate_params
# ---------------------------------------------------------------------------

def test_no_allowed_params_passes():
    assert validate_params({"foo": "bar"}, ToolConstraint()) is None


def test_allowlist_pass():
    tc = ToolConstraint(allowed_params={"entity_id": ParamConstraint(allowlist=["light.porch", "light.kitchen"])})
    assert validate_params({"entity_id": "light.porch"}, tc) is None


def test_allowlist_fail():
    tc = ToolConstraint(allowed_params={"entity_id": ParamConstraint(allowlist=["light.porch"])})
    result = validate_params({"entity_id": "light.bedroom"}, tc)
    assert result is not None
    assert "entity_id" in result


def test_pattern_pass():
    tc = ToolConstraint(allowed_params={"entity_id": ParamConstraint(pattern=r"^light\..*")})
    assert validate_params({"entity_id": "light.porch"}, tc) is None


def test_pattern_fail():
    tc = ToolConstraint(allowed_params={"entity_id": ParamConstraint(pattern=r"^light\..*")})
    result = validate_params({"entity_id": "switch.fan"}, tc)
    assert result is not None
    assert "entity_id" in result


def test_minimum_pass():
    tc = ToolConstraint(allowed_params={"brightness": ParamConstraint(minimum=0)})
    assert validate_params({"brightness": 0}, tc) is None


def test_minimum_fail():
    tc = ToolConstraint(allowed_params={"brightness": ParamConstraint(minimum=0)})
    result = validate_params({"brightness": -1}, tc)
    assert result is not None
    assert "below minimum" in result


def test_maximum_pass():
    tc = ToolConstraint(allowed_params={"brightness": ParamConstraint(maximum=80)})
    assert validate_params({"brightness": 80}, tc) is None


def test_maximum_fail():
    tc = ToolConstraint(allowed_params={"brightness": ParamConstraint(maximum=80)})
    result = validate_params({"brightness": 100}, tc)
    assert result is not None
    assert "above maximum" in result


def test_unconstrained_param_ignored():
    tc = ToolConstraint(allowed_params={"brightness": ParamConstraint(maximum=80)})
    assert validate_params({"brightness": 50, "extra": "anything"}, tc) is None


def test_missing_param_skipped():
    # Param listed in constraint but absent from call — not an error
    tc = ToolConstraint(allowed_params={"brightness": ParamConstraint(maximum=80)})
    assert validate_params({}, tc) is None


# ---------------------------------------------------------------------------
# get_effective_rules
# ---------------------------------------------------------------------------

def _cfg(server_rules=None, agent_overrides=None) -> WrapperConfig:
    cfg = WrapperConfig()
    cfg.server_rules = server_rules or {}
    cfg.agent_overrides = agent_overrides or {}
    return cfg


def test_uses_server_default():
    rules = ServerRules(allow=["GetDateTime"])
    cfg = _cfg(server_rules={"homeassistant": rules})
    assert get_effective_rules(cfg, "agent1", "homeassistant") is rules


def test_agent_override_takes_precedence():
    default = ServerRules(allow=["GetDateTime"])
    override = ServerRules(allow=["GetLiveContext"])
    cfg = _cfg(
        server_rules={"homeassistant": default},
        agent_overrides={"agent1": {"homeassistant": override}},
    )
    assert get_effective_rules(cfg, "agent1", "homeassistant") is override


def test_override_replaces_entirely():
    default = ServerRules(allow=["GetDateTime", "GetLiveContext"])
    override = ServerRules(allow=["GetDateTime"])
    cfg = _cfg(
        server_rules={"homeassistant": default},
        agent_overrides={"agent1": {"homeassistant": override}},
    )
    result = get_effective_rules(cfg, "agent1", "homeassistant")
    assert "GetLiveContext" not in result.allow


def test_other_agent_gets_default():
    default = ServerRules(allow=["GetDateTime"])
    override = ServerRules(allow=["GetLiveContext"])
    cfg = _cfg(
        server_rules={"homeassistant": default},
        agent_overrides={"agent1": {"homeassistant": override}},
    )
    assert get_effective_rules(cfg, "agent2", "homeassistant") is default


def test_unknown_server_returns_none():
    cfg = _cfg()
    assert get_effective_rules(cfg, "agent1", "nonexistent") is None
