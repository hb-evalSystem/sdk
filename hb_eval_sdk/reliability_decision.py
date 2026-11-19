"""
hb_eval_sdk/reliability_decision.py — Phase 6
==============================================

WHERE A MEASUREMENT BECOMES A DECISION

    Evidence -> Baseline -> Comparability -> ReliabilityDiff -> DECISION

This is the first layer whose output blocks or permits something, so it is
the first layer where a wrong verdict has consequences outside the system.

WHAT THIS MODULE OWNS

    Evaluating a DECLARED SLO policy against evidence that Phase 5D has
    already established is comparable, and refusing to decide when it has not.

WHAT IT DOES NOT OWN

    Comparability          5D-C. Consumed, never re-derived.
    Deltas                 5D-D. Consumed, never recomputed.
    Threshold values       organizational. Supplied by the caller.
    Metric polarity        undeclared. DW-027.
    Attribution            DW-015.
    Change detection       Phase 8.
    Certification          Phase 7. PASS is not CERTIFIED.

FOUR STATES, AND WHY THE THIRD EXISTS

    PASS                      every applicable declared SLO met
    FAIL                      a declared SLO violated
    INCONCLUSIVE              the evidence cannot support a decision
    RECERTIFICATION_REQUIRED  a prior decision context no longer applies

    Without INCONCLUSIVE, incomparable or missing evidence is forced into
    PASS or FAIL. PASS hides the gap. FAIL reports a violation that was never
    measured, and blocks a pull request on a fiction. Both are false.

    INCONCLUSIVE never collapses into either.

FAIL MEANS AN SLO VIOLATION, NOT A REGRESSION

    An SLO is a threshold someone declared. A regression is a claim about
    causation this system cannot support (DW-015), and a REPRODUCIBLE
    regression is one it cannot support at all (DW-018).

    So no output field here says improved, regressed, fell, better or worse.

POLARITY LIVES IN THE POLICY

    `MetricContract` declares no polarity and no module declares
    `higher_is_better` (DW-027). A policy saying `frr >= 0.80` is an
    organizational statement about a threshold; checking it needs no universal
    claim about whether higher is better.

SILENCE IS NOT ELIGIBILITY

    IRS is provisional and no judge is validated (DW-012). A policy that does
    not mention a provisional metric does not thereby permit it to decide.
    The metric is excluded, and the exclusion is reported.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

__all__ = [
    "decide",
    "ReliabilityDecision",
    "MetricDecision",
    "DecisionState",
    "MetricDecisionState",
    "SLOPolicy",
    "SLOCondition",
]


class DecisionState:
    """The outcome of a reliability decision: PASS, FAIL, or INCONCLUSIVE when the evidence cannot support either.

    RECERTIFICATION_REQUIRED is defined by the model but unreachable from the decision layer: it may
    only be emitted when authoritative upstream evidence already says so.
    """
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    RECERTIFICATION_REQUIRED = "RECERTIFICATION_REQUIRED"
    """Defined by the model and UNREACHABLE in Phase 6.

    It may be emitted only when authoritative upstream evidence already
    establishes that a prior decision context no longer applies. MEASURED: no
    certification artefact exists in the SDK, so no such context exists to be
    invalidated. Phase 7 creates the context; Phase 8 detects the change.

    Inventing a trigger here would be Phase 8 work smuggled into Phase 6.
    """
    ALL = (PASS, FAIL, INCONCLUSIVE, RECERTIFICATION_REQUIRED)


class MetricDecisionState:
    """How one metric fared against its condition.

    SATISFIED or VIOLATED when the evidence supports a decision. UNDECIDABLE when it cannot.
    EXCLUDED when the metric is deliberately outside the decision (not applicable, or not declared
    decision-eligible), which is neither a failure nor a defect.
    """
    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    UNDECIDABLE = "UNDECIDABLE"
    """The evidence cannot support a decision for this metric."""
    EXCLUDED = "EXCLUDED"
    """Deliberately outside the decision: not applicable, or not declared
    decision-eligible. NOT a failure and NOT a defect."""
    ALL = (SATISFIED, VIOLATED, UNDECIDABLE, EXCLUDED)


# ═══════════════════════════════════════════════════════════════════════
#  POLICY — declared by the caller, never defaulted here
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class SLOCondition:
    """One declared threshold for one metric.

    `comparator` and `threshold` together carry the direction the SDK does not
    know: `("gte", 0.80)` says higher is acceptable for this metric, in this
    organization, under this policy. That is a policy statement, not a
    scientific constant.
    """

    metric_name: str
    comparator: str
    """gte | lte | gt | lt — applied to the metric's VALUE on side B."""
    threshold: float
    applies_to: str = "value_b"
    """value_b | delta — which quantity the threshold governs."""
    decision_eligible: bool = True
    """A provisional metric decides only when a policy says so. DW-012."""

    def evaluate(self, quantity: float) -> bool:
        """True if `quantity` satisfies the condition's comparator (gte, lte, gt or lt) against its threshold. An unknown comparator raises ValueError: a condition that cannot be evaluated must not silently pass."""
        if self.comparator == "gte":
            return quantity >= self.threshold
        if self.comparator == "lte":
            return quantity <= self.threshold
        if self.comparator == "gt":
            return quantity > self.threshold
        if self.comparator == "lt":
            return quantity < self.threshold
        raise ValueError(
            f"unknown comparator {self.comparator!r}; a condition that cannot "
            f"be evaluated must not silently pass")


@dataclass(frozen=True)
class SLOPolicy:
    """A declared, versioned set of conditions.

    VERSIONED like `scoring_version`, because a decision made under one policy
    is not comparable to a decision made under another, and a reader needs to
    know which governed.

    NO DEFAULTS. There is deliberately no default policy, no default
    threshold and no default tolerance. A missing policy yields INCONCLUSIVE,
    because absence of a threshold is not permission.
    """

    policy_version: str
    conditions: tuple = ()
    policy_id: Optional[str] = None

    def condition_for(self, metric_name: str) -> Optional[SLOCondition]:
        """The condition declared for `metric_name`, or None if the policy does not mention it."""
        for c in self.conditions:
            if c.metric_name == metric_name:
                return c
        return None

    def to_dict(self) -> dict:
        """The JSON-serialisable form: version, id and every condition."""
        return {
            "policy_version": self.policy_version,
            "policy_id": self.policy_id,
            "conditions": [
                {"metric_name": c.metric_name, "comparator": c.comparator,
                 "threshold": c.threshold, "applies_to": c.applies_to,
                 "decision_eligible": c.decision_eligible}
                for c in self.conditions],
        }


# ═══════════════════════════════════════════════════════════════════════
#  RESULTS
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class MetricDecision:
    """The decision for one metric: its state, the reasons, the condition that was applied and the quantity that was evaluated."""
    metric_name: str
    state: str
    reasons: tuple = ()
    condition: Optional[dict] = None
    evaluated_quantity: Optional[float] = None

    def to_dict(self) -> dict:
        """The JSON-serialisable form: `metric_name`, `state`, `reasons`, `condition` and `evaluated_quantity`."""
        return {"metric_name": self.metric_name, "state": self.state,
                "reasons": list(self.reasons), "condition": self.condition,
                "evaluated_quantity": self.evaluated_quantity}


@dataclass(frozen=True)
class ReliabilityDecision:
    """A verdict, carrying the conditions that produced it.

    Both baseline hashes travel with it, so a reader who did not produce the
    decision can recompute it — the same property that made ReliabilityDiff a
    derived view rather than a sealed one.
    """

    state: str
    baseline_a_id: str
    baseline_b_id: str
    baseline_a_hash: str
    baseline_b_hash: str
    comparability_state: str
    policy_version: Optional[str] = None
    reasons: tuple = ()
    per_metric: dict = field(default_factory=dict)

    @property
    def decided_metrics(self) -> tuple:
        """The names of the metrics that were actually decided (SATISFIED or VIOLATED), sorted."""
        return tuple(sorted(
            n for n, m in self.per_metric.items()
            if m.state in (MetricDecisionState.SATISFIED,
                           MetricDecisionState.VIOLATED)))

    def to_dict(self) -> dict:
        """The JSON-serialisable form: the state, both baselines by id and hash, the comparability state and every per-metric decision."""
        return {
            "state": self.state,
            "baseline_a_id": self.baseline_a_id,
            "baseline_b_id": self.baseline_b_id,
            "baseline_a_hash": self.baseline_a_hash,
            "baseline_b_hash": self.baseline_b_hash,
            "comparability_state": self.comparability_state,
            "policy_version": self.policy_version,
            "reasons": list(self.reasons),
            "per_metric": {n: m.to_dict() for n, m in self.per_metric.items()},
            "decided_metrics": list(self.decided_metrics),
        }

    def __repr__(self) -> str:
        return (f"<ReliabilityDecision {self.state} "
                f"{len(self.decided_metrics)} metric(s) decided>")


# ═══════════════════════════════════════════════════════════════════════
#  THE DECISION
# ═══════════════════════════════════════════════════════════════════════

def decide(diff, policy: Optional[SLOPolicy] = None) -> ReliabilityDecision:
    """Evaluate a declared policy against a ReliabilityDiff.

    Takes the DIFF, not two baselines: comparability was already decided by
    5D-C and carried into 5D-D. Re-deriving it here would create a second
    implementation that eventually disagrees with the first.

    `policy` is optional in signature only. Without one the verdict is
    INCONCLUSIVE, because a decision needs a declared threshold and absence of
    one is not permission.
    """
    from .comparability import ComparabilityState, MetricState

    reasons = []
    per_metric = {}

    # ── no policy, no decision ──────────────────────────────────────
    if policy is None:
        return ReliabilityDecision(
            state=DecisionState.INCONCLUSIVE,
            baseline_a_id=diff.baseline_a_id, baseline_b_id=diff.baseline_b_id,
            baseline_a_hash=diff.baseline_a_hash,
            baseline_b_hash=diff.baseline_b_hash,
            comparability_state=diff.comparability_state,
            policy_version=None,
            reasons=("no SLO policy was declared: a decision needs a declared "
                     "threshold, and the absence of one is not permission",),
            per_metric={
                n: MetricDecision(n, MetricDecisionState.UNDECIDABLE,
                                  ("no policy",))
                for n in diff.metric_deltas},
        )

    # ── the pair must be comparable before any metric is decided ────
    #
    # A metric can be individually fine while the evaluation contexts are
    # incompatible, and a verdict reached there would look valid.
    pair_ok = diff.comparability_state == ComparabilityState.COMPARABLE
    if not pair_ok:
        reasons.append(
            f"the evaluation pair is {diff.comparability_state}: the evidence "
            f"cannot support a PASS or a FAIL")
        reasons.extend(diff.blockers)
        reasons.extend(diff.unknowns)

    for name, md in diff.metric_deltas.items():
        condition = policy.condition_for(name)

        # NOT_APPLICABLE is excluded, not failed. CSI consumes no evidence in
        # a single live session; nothing is absent and nothing is wrong.
        if md.state == MetricState.NOT_APPLICABLE:
            per_metric[name] = MetricDecision(
                name, MetricDecisionState.EXCLUDED,
                ("the metric consumes no evidence in this mode; excluded from "
                 "the decision, not counted against it",))
            continue

        if condition is None:
            per_metric[name] = MetricDecision(
                name, MetricDecisionState.EXCLUDED,
                ("no declared condition governs this metric",))
            continue

        # DW-012: silence is not eligibility. A provisional metric decides
        # only when the policy declares it does.
        if not condition.decision_eligible:
            per_metric[name] = MetricDecision(
                name, MetricDecisionState.EXCLUDED,
                ("the policy declares this metric not decision-eligible",),
                condition=_cond_dict(condition))
            continue

        if not pair_ok:
            per_metric[name] = MetricDecision(
                name, MetricDecisionState.UNDECIDABLE,
                (f"the evaluation pair is {diff.comparability_state}",),
                condition=_cond_dict(condition))
            continue

        if md.state != MetricState.COMPARABLE:
            per_metric[name] = MetricDecision(
                name, MetricDecisionState.UNDECIDABLE,
                md.reasons or (f"metric state is {md.state}",),
                condition=_cond_dict(condition))
            continue

        quantity = (md.delta if condition.applies_to == "delta"
                    else md.baseline_b_value)
        if quantity is None:
            # delta is None means no comparison was made. It is NOT zero, and
            # treating it as zero would let an absent comparison satisfy a
            # threshold.
            per_metric[name] = MetricDecision(
                name, MetricDecisionState.UNDECIDABLE,
                (f"the quantity the condition governs ({condition.applies_to})"
                 f" is absent; no comparison was made",),
                condition=_cond_dict(condition))
            continue

        satisfied = condition.evaluate(quantity)
        per_metric[name] = MetricDecision(
            name,
            MetricDecisionState.SATISFIED if satisfied
            else MetricDecisionState.VIOLATED,
            () if satisfied else (
                f"{name} {condition.applies_to}={quantity} does not satisfy "
                f"{condition.comparator} {condition.threshold} under policy "
                f"{policy.policy_version}",),
            condition=_cond_dict(condition), evaluated_quantity=quantity)

    # ── STATE PRIORITY ──────────────────────────────────────────────
    #
    # 1  any UNDECIDABLE      -> INCONCLUSIVE
    # 2  any VIOLATED         -> FAIL
    # 3  at least one decided -> PASS
    # 4  nothing decided      -> INCONCLUSIVE
    #
    # UNDECIDABLE outranks VIOLATED deliberately: reporting FAIL while part of
    # the evidence could not be evaluated would present a partial verdict as a
    # complete one. INCONCLUSIVE says the evidence is not yet sufficient, and
    # the violated conditions are still reported alongside.
    states = {m.state for m in per_metric.values()}

    if MetricDecisionState.UNDECIDABLE in states:
        state = DecisionState.INCONCLUSIVE
        reasons.append(
            "at least one governed metric could not be evaluated; a FAIL here "
            "would present a partial verdict as a complete one")
    elif MetricDecisionState.VIOLATED in states:
        state = DecisionState.FAIL
    elif MetricDecisionState.SATISFIED in states:
        state = DecisionState.PASS
    else:
        state = DecisionState.INCONCLUSIVE
        reasons.append(
            "no metric was decided: every governed metric was excluded, so "
            "there is nothing for a PASS to assert")

    return ReliabilityDecision(
        state=state,
        baseline_a_id=diff.baseline_a_id, baseline_b_id=diff.baseline_b_id,
        baseline_a_hash=diff.baseline_a_hash,
        baseline_b_hash=diff.baseline_b_hash,
        comparability_state=diff.comparability_state,
        policy_version=policy.policy_version,
        reasons=tuple(reasons), per_metric=per_metric,
    )


def _cond_dict(c: SLOCondition) -> dict:
    return {"metric_name": c.metric_name, "comparator": c.comparator,
            "threshold": c.threshold, "applies_to": c.applies_to,
            "decision_eligible": c.decision_eligible}
