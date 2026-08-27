"""
test_policy.py — the policy engine, with the runaway as the headline case.

WHAT THESE PROTECT
------------------
A retry action is the most dangerous thing in this release. A published
post-mortem from April 2026 describes an agent that entered a retry loop at
11pm and ran until 7am: thousands of identical failing calls, $437 in API
spend, no alert, nothing to stop it.

If FRR is below the floor and the retry also fails, FRR stays below the floor
and the rule fires again — forever. The first test below is that scenario, and
it must remain bounded no matter how the engine is changed later.
"""
import pytest

from policy import (
    PolicyEngine, Directive, normalise_policies,
    ACTION_HALT, ACTION_RETRY, ACTION_ESCALATE, DEFAULT_MAX_FIRES,
)


def run(engine, steps, metrics, action="call_api"):
    """Feed identical failing steps and collect the actions raised."""
    out = []
    for step in range(1, steps + 1):
        d = engine.evaluate(metrics, step, last_action=action, last_failed=True)
        if d:
            engine.take_directive()
            out.append(d.action)
    return out


# ── The runaway ─────────────────────────────────────────────────────────────
def test_five_hundred_failures_cannot_produce_five_hundred_retries():
    """The April 2026 scenario. This is the test that matters most."""
    eng = PolicyEngine(policies=[
        {"when": {"metric": "frr", "below": 0.7, "for_steps": 2}, "then": "retry"},
    ])
    actions = run(eng, 500, {"frr": 0.0})
    retries = actions.count(ACTION_RETRY)
    assert retries <= DEFAULT_MAX_FIRES, f"runaway: {retries} retries"
    # And it goes quiet rather than churning silently forever.
    assert len(actions) <= DEFAULT_MAX_FIRES + 1


def test_two_failed_retries_escalate_instead_of_a_third():
    """Two identical failures are evidence the retry is not working.

    Repeating it a third time is the loop itself, so the engine hands the
    problem to a human instead."""
    eng = PolicyEngine(policies=[
        {"when": {"metric": "frr", "below": 0.7, "for_steps": 1}, "then": "retry"},
    ])
    actions = run(eng, 6, {"frr": 0.0})
    assert ACTION_ESCALATE in actions
    assert actions.index(ACTION_ESCALATE) > actions.index(ACTION_RETRY)


def test_directive_is_consumed_on_read():
    """A caller checking in a loop must not act on the same signal twice."""
    eng = PolicyEngine(policies=[
        {"when": {"metric": "frr", "below": 0.7, "for_steps": 1}, "then": "retry"},
    ])
    eng.evaluate({"frr": 0.0}, 1, last_action="x")
    assert eng.take_directive() is not None
    assert eng.take_directive() is None


def test_pending_does_not_consume():
    eng = PolicyEngine(policies=[
        {"when": {"metric": "frr", "below": 0.7, "for_steps": 1}, "then": "retry"},
    ])
    eng.evaluate({"frr": 0.0}, 1, last_action="x")
    assert eng.pending is not None
    assert eng.pending is not None      # still there
    assert eng.take_directive() is not None


def test_max_fires_is_configurable():
    eng = PolicyEngine(policies=[
        {"when": {"metric": "frr", "below": 0.7, "for_steps": 1},
         "then": "escalate", "max_fires": 1},
    ])
    actions = run(eng, 10, {"frr": 0.0})
    assert actions.count(ACTION_ESCALATE) == 1


def test_halt_has_no_fire_budget():
    """Halt is terminal: firing it repeatedly is meaningless, not dangerous."""
    eng = PolicyEngine(policies=[
        {"when": {"metric": "frr", "below": 0.5, "for_steps": 1}, "then": "halt"},
    ])
    actions = run(eng, 10, {"frr": 0.0})
    assert actions.count(ACTION_HALT) == 10


# ── Sustained breach ────────────────────────────────────────────────────────
def test_a_single_dip_does_not_fire():
    """Noise immunity. A guard that fires on one bad step gets switched off."""
    eng = PolicyEngine(policies=[
        {"when": {"metric": "frr", "below": 0.5, "for_steps": 3}, "then": "halt"},
    ])
    assert eng.evaluate({"frr": 0.0}, 1) is None
    assert eng.evaluate({"frr": 0.0}, 2) is None
    assert eng.evaluate({"frr": 0.0}, 3) is not None


def test_recovery_resets_the_run():
    """A later breach must build up again from zero, not resume."""
    eng = PolicyEngine(policies=[
        {"when": {"metric": "frr", "below": 0.5, "for_steps": 3}, "then": "halt"},
    ])
    eng.evaluate({"frr": 0.0}, 1)
    eng.evaluate({"frr": 0.9}, 2)       # recovered
    eng.evaluate({"frr": 0.0}, 3)
    assert eng.evaluate({"frr": 0.0}, 4) is None, "run should have reset"


def test_undefined_metric_never_breaches():
    """An unmeasured dimension is not a failing one — the rule that governs
    every other layer of this system."""
    eng = PolicyEngine(policies=[
        {"when": {"metric": "irs", "below": 0.5, "for_steps": 1}, "then": "halt"},
    ])
    for step in range(1, 20):
        assert eng.evaluate({"irs": None}, step) is None


# ── Precedence ──────────────────────────────────────────────────────────────
def test_halt_outranks_retry():
    """Retrying a run already decided to stop is incoherent."""
    eng = PolicyEngine(policies=[
        {"when": {"metric": "frr", "below": 0.5, "for_steps": 2}, "then": "halt"},
        {"when": {"metric": "frr", "below": 0.7, "for_steps": 2}, "then": "retry"},
    ])
    eng.evaluate({"frr": 0.1}, 1, last_action="x")
    d = eng.evaluate({"frr": 0.1}, 2, last_action="x")
    assert d.action == ACTION_HALT


def test_escalate_outranks_retry():
    eng = PolicyEngine(policies=[
        {"when": {"metric": "frr", "below": 0.7, "for_steps": 1}, "then": "retry"},
        {"when": {"metric": "frr", "below": 0.7, "for_steps": 1}, "then": "escalate"},
    ])
    d = eng.evaluate({"frr": 0.0}, 1, last_action="x")
    assert d.action == ACTION_ESCALATE


# ── Circuit breaker ─────────────────────────────────────────────────────────
def test_breaker_opens_after_configured_failures():
    eng = PolicyEngine(tool_policy={"failures_before_open": 3})
    for step in range(1, 3):
        eng.record_tool_outcome("api", True, step)
        assert eng.unreliable_tools == []
    eng.record_tool_outcome("api", True, 3)
    assert eng.unreliable_tools == ["api"]


def test_breaker_full_cycle():
    """closed → open → half-open → open → closed."""
    eng = PolicyEngine(tool_policy={"failures_before_open": 2, "probe_after_steps": 5})
    for s in (1, 2):
        eng.record_tool_outcome("api", True, s)
    assert eng.tool_states["api"]["state"] == "open"

    eng.refresh_tool_states(7)
    assert eng.tool_states["api"]["state"] == "half_open"

    eng.record_tool_outcome("api", True, 8)         # probe failed
    assert eng.tool_states["api"]["state"] == "open"

    eng.refresh_tool_states(14)
    eng.record_tool_outcome("api", False, 14)       # probe succeeded
    assert eng.tool_states["api"]["state"] == "closed"
    assert eng.unreliable_tools == []


def test_breaker_is_scoped_to_one_tool():
    """A failing dependency must not take the whole agent out of service —
    that is the difference between a circuit breaker and a kill switch."""
    eng = PolicyEngine(tool_policy={"failures_before_open": 2})
    for s in (1, 2):
        eng.record_tool_outcome("bad", True, s)
    eng.record_tool_outcome("good", False, 3)
    assert eng.unreliable_tools == ["bad"]


def test_success_closes_the_breaker_immediately():
    eng = PolicyEngine(tool_policy={"failures_before_open": 2})
    for s in (1, 2):
        eng.record_tool_outcome("api", True, s)
    assert eng.unreliable_tools == ["api"]
    eng.record_tool_outcome("api", False, 3)
    assert eng.unreliable_tools == []


def test_no_tool_policy_means_no_breaker():
    eng = PolicyEngine(policies=[])
    eng.record_tool_outcome("api", True, 1)
    assert eng.unreliable_tools == []


# ── Validation ──────────────────────────────────────────────────────────────
def test_malformed_policies_are_dropped_not_raised():
    """A typo in one rule must not take down a run the others were
    protecting."""
    policies = normalise_policies([
        {"when": {"metric": "frr", "below": 0.5, "for_steps": 3}, "then": "halt"},
        {"when": {"metric": "frr", "below": 0.5}, "then": "teleport"},   # bad action
        {"when": {"metric": "", "below": 0.5}, "then": "halt"},          # no metric
        {"when": {"metric": "frr"}, "then": "halt"},                     # no floor
        {"when": {"metric": "frr", "below": "abc"}, "then": "halt"},     # not numeric
        "not a dict",
    ])
    assert len(policies) == 1
    assert policies[0]["action"] == ACTION_HALT


def test_for_steps_is_at_least_one():
    p = normalise_policies([
        {"when": {"metric": "frr", "below": 0.5, "for_steps": 0}, "then": "halt"},
    ])
    assert p[0]["for_steps"] == 1


def test_empty_policies_engine_is_inert():
    eng = PolicyEngine(policies=[])
    for step in range(1, 20):
        assert eng.evaluate({"frr": 0.0}, step) is None


# ── Evidence ────────────────────────────────────────────────────────────────
def test_directive_carries_its_whole_basis():
    """A directive that cannot be explained will not be trusted, and an
    intervention nobody trusts gets switched off."""
    eng = PolicyEngine(policies=[
        {"when": {"metric": "frr", "below": 0.5, "for_steps": 2}, "then": "halt"},
    ])
    eng.evaluate({"frr": 0.2}, 1)
    d = eng.evaluate({"frr": 0.2}, 2)
    out = d.as_dict()
    for key in ("action", "reason", "metric", "metric_value", "threshold",
                "consecutive_steps", "step_index", "policy", "occurred_at"):
        assert key in out, key
    assert out["metric"] == "frr"
    assert out["metric_value"] == 0.2
    assert out["threshold"] == 0.5
    assert out["consecutive_steps"] == 2
    # The rule verbatim, so the decision stays reproducible against what was
    # actually in force.
    assert out["policy"]["for_steps"] == 2


def test_retry_directive_names_its_target():
    eng = PolicyEngine(policies=[
        {"when": {"metric": "frr", "below": 0.7, "for_steps": 1}, "then": "retry"},
    ])
    d = eng.evaluate({"frr": 0.0}, 1, last_action="fetch_invoice")
    assert d.target == "fetch_invoice"


def test_summary_counts_actions_and_tools():
    eng = PolicyEngine(
        policies=[{"when": {"metric": "frr", "below": 0.5, "for_steps": 1},
                   "then": "halt"}],
        tool_policy={"failures_before_open": 1},
    )
    eng.evaluate({"frr": 0.0}, 1)
    eng.record_tool_outcome("api", True, 1)
    s = eng.summary()
    assert s["actions_taken"] == {"halt": 1}
    assert s["unreliable_tools"] == ["api"]
    assert len(s["directives"]) == 1