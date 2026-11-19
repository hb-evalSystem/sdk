"""
hb_eval_sdk.policy
===================
Turns a detected degradation into a decision the caller can act on.

WHERE THIS SITS
---------------
Safe Halt answered one question — should this run stop? — with one rule. That
is the right answer when an agent is collapsing and the wrong one when it is
merely struggling: stopping a run that would have recovered on the next attempt
is expensive, and stopping is the only thing Safe Halt can say.

This module generalises it. Several rules, several actions, one decision at a
time.

    policies=[
        {"when": {"metric": "frr", "below": 0.5, "for_steps": 3}, "then": "halt"},
        {"when": {"metric": "frr", "below": 0.7, "for_steps": 2}, "then": "retry"},
        {"when": {"metric": "irs", "below": 0.4, "for_steps": 5}, "then": "escalate"},
    ]

STILL COOPERATIVE, STILL ADVISORY
----------------------------------
Nothing here executes anything. A directive is raised on the session and the
caller's own loop decides what to do with it, exactly as should_halt already
works. That boundary is the reason this can be trusted in production: the
instrument stays beside the agent instead of becoming part of it, and every
failure in this module remains a monitoring failure rather than an agent
failure.

WHAT IS DELIBERATELY ABSENT
----------------------------
Rollback and model switching. Rollback cannot mean what a reader would assume:
this can discard accumulated context, and it cannot un-send an email, un-charge
a card or un-write a row. Shipping something called "rollback" that silently
only clears context would be an overclaim in a system whose entire argument is
about not overclaiming — and here it is worse, because somebody might rely on
it where the difference matters.

THE RETRY LOOP IS THE DANGER, AND IT IS DESIGNED OUT
-----------------------------------------------------
In April 2026 a published post-mortem described an agent that entered a retry
loop at 11pm and ran until 7am: thousands of identical failing calls, $437 in
API spend, no alert, nothing to stop it.

A retry action is exactly how that happens. If FRR is below the floor and the
retry also fails, FRR stays below the floor and the rule fires again — forever.
So three independent limits make it structurally impossible rather than
unlikely:

  1. max_fires per policy, defaulting to 3. A rule that has fired its budget is
     spent for the session and cannot fire again.

  2. Directives are CONSUMED on read. The caller cannot loop on a stale signal,
     because reading it clears it.

  3. A retry that is followed by another failure of the same action does not
     retry again — it escalates. Two identical failures are evidence the retry
     is not working, and repeating it a third time is the loop itself.

Halt is exempt from the fire budget. It is terminal: firing it more than once
is meaningless rather than dangerous.

TOOL CIRCUIT BREAKERS
---------------------
Separate from metric policies, because the failure is different in kind. A
metric collapse is a property of the run; a tool that times out every time is a
property of one dependency, and stopping the whole agent for it is the wrong
scope.

The classic three states apply unchanged — closed, open, half-open — and the
output is advisory. This reports a tool as unreliable; the caller decides
whether to route around it. Blocking the call outright would put this module in
the agent's execution path, which is the boundary it exists to respect.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

# Actions, in precedence order. A run that has been decided to stop is not also
# retried, and escalation outranks retry because a human being asked to look is
# a stronger response than trying again.
ACTION_HALT = "halt"
ACTION_ESCALATE = "escalate"
ACTION_RETRY = "retry"

ACTION_PRECEDENCE = {ACTION_HALT: 3, ACTION_ESCALATE: 2, ACTION_RETRY: 1}
VALID_ACTIONS = frozenset(ACTION_PRECEDENCE)

# Default fire budget for non-terminal actions. Three is enough for a transient
# fault to clear and few enough that a persistent one escalates quickly.
DEFAULT_MAX_FIRES = 3

# Circuit-breaker defaults.
DEFAULT_FAILURES_BEFORE_OPEN = 3
DEFAULT_PROBE_AFTER_STEPS = 10


@dataclass
class Directive:
    """One decision, with the evidence that produced it.

    Carries the whole basis rather than a verdict, because a directive that
    cannot be explained will not be trusted, and an intervention nobody trusts
    gets switched off.
    """
    action: str
    reason: str
    metric: Optional[str] = None
    metric_value: Optional[float] = None
    threshold: Optional[float] = None
    consecutive_steps: Optional[int] = None
    step_index: int = 0
    policy: dict = field(default_factory=dict)
    target: Optional[str] = None        # the action to retry, when applicable
    occurred_at: float = field(default_factory=time.time)

    def as_dict(self) -> dict:
        """The JSON-serialisable form: the action, why, the metric, its value, the threshold and how many consecutive steps breached it."""
        return {
            "action": self.action,
            "reason": self.reason,
            "metric": self.metric,
            "metric_value": self.metric_value,
            "threshold": self.threshold,
            "consecutive_steps": self.consecutive_steps,
            "step_index": self.step_index,
            "policy": dict(self.policy),
            "target": self.target,
            "occurred_at": self.occurred_at,
        }


KNOWN_METRICS = ("pei", "frr", "irs", "ti", "csi")


def _ineligible_reason(metric: str) -> Optional[str]:
    """Why a metric may not drive a live decision, or None. Mirrors halt_policy's rule: a policy
    that is accepted but can never fire gives a false sense of protection."""
    try:
        from .contracts import CONTRACTS
    except ImportError:                       # pragma: no cover
        return None
    contract = CONTRACTS.get(metric)
    if contract is not None and not contract.safety_eligible:
        return f"{metric} is not eligible for safety decisions in a live session"
    return None


def normalise_policies(policies: Any, dropped: Optional[list] = None) -> list[dict]:
    """Validate and normalise the policy list.

    Invalid entries are DROPPED rather than raising: a typo in one rule must not take down an agent
    run that the other rules were protecting. But a silently ignored rule is its own hazard, so every
    dropped rule is appended to `dropped` (when given) with the reason, and PolicyEngine reports them
    in its summary and log. Previously nothing was recorded, so `"then": "stop"` or a misspelt metric
    left the agent unprotected with no trace.
    """
    def drop(index: int, raw: Any, reason: str) -> None:
        if dropped is not None:
            dropped.append({"index": index, "rule": repr(raw)[:200], "reason": reason})

    if not policies:
        return []
    if not isinstance(policies, (list, tuple)):
        # `policies=True`, a dict, or a string used to be iterated (a string character by character,
        # a bool not at all: TypeError). One bad argument is one reported problem, not a crash.
        drop(0, policies, "policies must be a list of rule dicts")
        return []
    out: list[dict] = []
    for index, raw in enumerate(policies):
        if not isinstance(raw, dict):
            drop(index, raw, "a policy must be a dict like {'when': {...}, 'then': 'halt'}")
            continue
        when = raw.get("when")
        if not isinstance(when, dict):
            drop(index, raw, "'when' must be a dict with 'metric' and 'below'")
            continue
        action = str(raw.get("then", "")).strip().lower()
        metric = str(when.get("metric", "")).strip().lower()
        below = when.get("below")
        if action not in VALID_ACTIONS:
            drop(index, raw, f"'then' must be one of {sorted(VALID_ACTIONS)}, got {raw.get('then')!r}")
            continue
        if metric not in KNOWN_METRICS:
            drop(index, raw, f"metric must be one of {list(KNOWN_METRICS)}, got {when.get('metric')!r}")
            continue
        reason = _ineligible_reason(metric)
        if reason:
            drop(index, raw, reason)
            continue
        if below is None:
            drop(index, raw, "'below' is required")
            continue
        try:
            below = float(below)
            for_steps = max(1, int(when.get("for_steps", 1)))
            max_fires = None if action == ACTION_HALT else max(1, int(raw.get("max_fires", DEFAULT_MAX_FIRES)))
        except (TypeError, ValueError):
            drop(index, raw, "'below', 'for_steps' and 'max_fires' must be numbers")
            continue

        out.append({
            "metric": metric,
            "below": below,
            "for_steps": for_steps,
            "action": action,
            "max_fires": max_fires,
            "label": raw.get("label"),
        })
    return out


class PolicyEngine:
    """Evaluates policies against live metrics and raises directives.

    Stateful: sustained breach, fire budgets and retry history are all
    relationships across steps rather than properties of one.
    """

    def __init__(self, policies: Optional[Any] = None, tool_policy: Optional[dict] = None):
        self.dropped_policies: list[dict] = []
        self.policies = normalise_policies(policies, self.dropped_policies)
        if self.dropped_policies:
            import logging
            logging.getLogger("hb_eval_sdk.policy").warning(
                "HB-Eval: %d of %d policy rule(s) were rejected and will NOT protect this run: %s",
                len(self.dropped_policies), len(policies) if isinstance(policies, (list, tuple)) else 1,
                "; ".join(f"#{d['index']}: {d['reason']}" for d in self.dropped_policies))
        self._runs: dict[str, int] = {}        # policy key -> consecutive breach steps
        self._fires: dict[str, int] = {}       # policy key -> times fired
        self.directives: list[Directive] = []

        # Consumed on read, so a caller cannot act on a stale signal twice.
        self._pending: Optional[Directive] = None

        # Retry bookkeeping, for limit 3 in the module docstring.
        self._retry_targets: dict[str, int] = {}
        self._last_retry_step: Optional[int] = None
        self._last_retry_target: Optional[str] = None

        tp = tool_policy or {}
        self.tool_policy = {
            "failures_before_open": max(1, int(tp.get("failures_before_open",
                                                      DEFAULT_FAILURES_BEFORE_OPEN))),
            "probe_after_steps": max(1, int(tp.get("probe_after_steps",
                                                   DEFAULT_PROBE_AFTER_STEPS))),
        } if tool_policy else None

        # tool -> {"state", "failures", "opened_at_step"}
        self._tools: dict[str, dict] = {}

    # ── Keys ────────────────────────────────────────────────────────────────
    @staticmethod
    def _key(p: dict) -> str:
        return f"{p['metric']}<{p['below']}x{p['for_steps']}:{p['action']}"

    # ── Tool circuit breaker ────────────────────────────────────────────────
    def record_tool_outcome(self, tool: Optional[str], failed: bool,
                            step_index: int) -> None:
        """Update the breaker for one tool.

        Closed → Open after enough consecutive failures. Open → Half-open once
        enough steps have passed to be worth probing. A success in any state
        closes it, because the dependency has demonstrably recovered.
        """
        if not self.tool_policy or not tool:
            return
        st = self._tools.setdefault(
            tool, {"state": "closed", "failures": 0, "opened_at_step": None})

        if not failed:
            st.update(state="closed", failures=0, opened_at_step=None)
            return

        st["failures"] += 1
        if st["state"] == "closed" and st["failures"] >= self.tool_policy["failures_before_open"]:
            st["state"] = "open"
            st["opened_at_step"] = step_index
        elif st["state"] == "half_open":
            # The probe failed: straight back to open, with the clock reset so
            # the next probe is not immediate.
            st["state"] = "open"
            st["opened_at_step"] = step_index

    def refresh_tool_states(self, step_index: int) -> None:
        """Move breakers from open to half-open once their cooldown elapses."""
        if not self.tool_policy:
            return
        after = self.tool_policy["probe_after_steps"]
        for st in self._tools.values():
            if st["state"] == "open" and st["opened_at_step"] is not None:
                if step_index - st["opened_at_step"] >= after:
                    st["state"] = "half_open"

    @property
    def unreliable_tools(self) -> list[str]:
        """Tools whose breaker is open. Advisory — the caller decides."""
        return sorted(t for t, st in self._tools.items() if st["state"] == "open")

    @property
    def tool_states(self) -> dict:
        """A copy of every tool's circuit-breaker state, keyed by tool name."""
        return {t: dict(st) for t, st in self._tools.items()}

    # ── Policy evaluation ───────────────────────────────────────────────────
    def evaluate(self, live_metrics: dict, step_index: int,
                 last_action: Optional[str] = None,
                 last_failed: bool = False) -> Optional[Directive]:
        """Evaluate every policy against the current metrics.

        Returns the highest-precedence directive raised by THIS step, or None.
        """
        candidates: list[Directive] = []

        for p in self.policies:
            key = self._key(p)
            value = live_metrics.get(p["metric"])

            if value is None or value >= p["below"]:
                # Undefined metrics cannot breach — an unmeasured dimension is
                # not a failing one — and a recovered metric resets the run so
                # a later breach must build up again from zero.
                self._runs[key] = 0
                continue

            self._runs[key] = self._runs.get(key, 0) + 1
            if self._runs[key] < p["for_steps"]:
                continue    # breaching, but not yet sustained

            # Fire budget. Halt has none; everything else is capped so a
            # persistent fault cannot fire the same rule indefinitely.
            fired = self._fires.get(key, 0)
            if p["max_fires"] is not None and fired >= p["max_fires"]:
                continue

            action = p["action"]
            reason = (f"{p['metric'].upper()} stayed below {p['below']} for "
                      f"{self._runs[key]} consecutive steps")

            # Limit 3: a retry whose target has already failed twice is not
            # working. Escalate instead of trying a third time — this is the
            # exact point at which the April 2026 runaway became a runaway.
            if action == ACTION_RETRY and last_action:
                if self._retry_targets.get(last_action, 0) >= 2:
                    action = ACTION_ESCALATE
                    reason = (f"{last_action!r} failed repeatedly after retry; "
                              f"escalating rather than retrying again")

            candidates.append(Directive(
                action=action, reason=reason,
                metric=p["metric"], metric_value=value, threshold=p["below"],
                consecutive_steps=self._runs[key], step_index=step_index,
                policy={k: p[k] for k in ("metric", "below", "for_steps",
                                          "action", "max_fires")},
                target=(last_action if action == ACTION_RETRY else None),
            ))
            self._fires[key] = fired + 1

        if not candidates:
            return None

        # Highest precedence wins. Halting and retrying the same run would be
        # incoherent, and the stronger response is the safe one.
        chosen = max(candidates, key=lambda d: ACTION_PRECEDENCE[d.action])

        if chosen.action == ACTION_RETRY and chosen.target:
            self._retry_targets[chosen.target] = self._retry_targets.get(chosen.target, 0) + 1
            self._last_retry_step = step_index
            self._last_retry_target = chosen.target

        self.directives.append(chosen)
        self._pending = chosen
        return chosen

    # ── Consumption ─────────────────────────────────────────────────────────
    def take_directive(self) -> Optional[Directive]:
        """Read and clear the pending directive.

        Clearing on read is limit 2: a caller that checks in a loop cannot act
        on the same signal repeatedly, which is one of the ways a retry becomes
        a runaway.
        """
        d, self._pending = self._pending, None
        return d

    @property
    def pending(self) -> Optional[Directive]:
        """Look without consuming. For inspection, not for control flow."""
        return self._pending

    def summary(self) -> dict:
        """A summary for the session: how many rules are active, the rules that were dropped and why, every directive issued, and counts by action."""
        return {
            "policies": len(self.policies),
            "dropped_policies": list(self.dropped_policies),
            "directives": [d.as_dict() for d in self.directives],
            "actions_taken": {
                a: sum(1 for d in self.directives if d.action == a)
                for a in sorted({d.action for d in self.directives})
            },
            "unreliable_tools": self.unreliable_tools,
            "tool_states": self.tool_states,
        }