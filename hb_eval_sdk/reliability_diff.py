"""
hb_eval_sdk/reliability_diff.py — Phase 5D-D
=============================================

WHAT THIS COMPUTES

    Per-metric differences between TWO ReliabilityBaselines, gated by the
    comparability verdict from 5D-C.

WHAT IT IS NOT

    NOT the Reliability Gap. `delta(pi) = C_nom(pi) - R_op(pi)` compares
    nominal capability against operational reliability within one evaluation.
    Neither value exists in V2: there is no C_nom, no R_op, and `is_nominal`
    is a scenario flag marking a fault-free slot, not a capability score.
    Building it would mean inventing two aggregate measurements and opening
    battery aggregation (DW-024). It is a separate future phase.

    NOT attribution. A difference is reported, never explained. DW-015.

    NOT a regression classifier. Reporting "regressed" needs metric polarity,
    which is not declared anywhere - see DIRECTION SEMANTICS below.

    NOT an aggregate. No overall score, no roll-up across metrics.

THE CHAIN THIS SITS AT THE END OF

    RECORDED evidence -> Baseline -> Comparability -> ReliabilityDiff

    No layer may lose provenance, metric version, comparability state, or the
    distinction between an unavailable comparison and numeric equality.

THREE STATES, PRESERVED NOT NARROWED

    5D-C produces three metric states. An earlier design carried them into
    the diff as `comparable: bool`, which collapsed NOT_APPLICABLE into the
    same bucket as NOT_COMPARABLE:

        NOT_APPLICABLE   the metric consumes no evidence in this mode - CSI
                         in a single live session. Nothing is wrong.
        NOT_COMPARABLE   something blocked the comparison. Something IS wrong.

    A consumer that cannot tell them apart would read a normal CSI as a
    defect. The state is carried through unchanged.

DIRECTION SEMANTICS - what is derivable, and what is not

        unchanged   both values present and equal
        different   both values present and unequal
        undefined   no delta was computed

    NOT `improved` / `regressed`. Those need to know whether a higher value
    is better, and MEASURED: `MetricContract` declares
    name/version/definition/domain/numerator/denominator/undefined_when/
    required_evidence - and no polarity. No module declares
    `higher_is_better`.

    Producing "improved" would encode an undeclared assumption inside a diff.
    Deferred as DW-027.

ZERO IS NOT ABSENCE

    delta = 0.0    the values are equal, and that is a measurement
    delta = None   no comparison was made, for a reason carried alongside

    Conflating them would let "cannot compare" read as "no difference".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

__all__ = [
    "diff_baselines",
    "ReliabilityDiff",
    "MetricDelta",
    "Direction",
]


class Direction:
    """The observed direction of a metric between two baselines: unchanged, different, or undefined when it cannot be said. These are observations; whether a difference matters is the decision layer's judgement."""
    UNCHANGED = "unchanged"
    DIFFERENT = "different"
    UNDEFINED = "undefined"
    ALL = (UNCHANGED, DIFFERENT, UNDEFINED)


@dataclass(frozen=True)
class MetricDelta:
    """One metric's difference, carrying the conditions that produced it.

    `state` is the 5D-C verdict, unchanged. `delta` is None whenever no
    comparison was made, and the reason travels with it so a consumer never
    has to infer why.
    """

    metric_name: str
    state: str
    """COMPARABLE | NOT_COMPARABLE | NOT_APPLICABLE - as produced by 5D-C."""

    baseline_a_value: Optional[float] = None
    baseline_b_value: Optional[float] = None
    delta: Optional[float] = None
    """b - a. None whenever no comparison was made. 0.0 means EQUAL."""

    direction: str = Direction.UNDEFINED
    metric_version_a: Optional[str] = None
    metric_version_b: Optional[str] = None
    provenance_a: Optional[str] = None
    provenance_b: Optional[str] = None
    reasons: tuple = ()

    def to_dict(self) -> dict:
        """The JSON-serialisable form: the metric, its state, both values, the delta and the direction."""
        return {
            "metric_name": self.metric_name,
            "state": self.state,
            "baseline_a_value": self.baseline_a_value,
            "baseline_b_value": self.baseline_b_value,
            "delta": self.delta,
            "direction": self.direction,
            "metric_version_a": self.metric_version_a,
            "metric_version_b": self.metric_version_b,
            "provenance_a": self.provenance_a,
            "provenance_b": self.provenance_b,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class ReliabilityDiff:
    """A derived view over two sealed baselines. Recomputable, not sealed.

    Both baseline hashes travel with it, so any reader can reproduce it
    without trusting whoever produced it. Sealing a derivation would add a
    hash proving nothing its inputs do not.
    """

    baseline_a_id: str
    baseline_b_id: str
    baseline_a_hash: str
    baseline_b_hash: str

    comparability_state: str
    blockers: tuple = ()
    unknowns: tuple = ()
    metric_deltas: dict = field(default_factory=dict)

    state_transition_diff = None    # DW-002
    constraint_diff = None          # DW-013

    @property
    def compared_metrics(self) -> tuple:
        """The names of the metrics for which a delta was actually computed, sorted."""
        return tuple(sorted(n for n, m in self.metric_deltas.items()
                            if m.delta is not None))

    def to_dict(self) -> dict:
        """The JSON-serialisable form: both baselines by id and hash, the comparability state, the blockers and every metric delta."""
        return {
            "baseline_a_id": self.baseline_a_id,
            "baseline_b_id": self.baseline_b_id,
            "baseline_a_hash": self.baseline_a_hash,
            "baseline_b_hash": self.baseline_b_hash,
            "comparability_state": self.comparability_state,
            "blockers": list(self.blockers),
            "unknowns": list(self.unknowns),
            "metric_deltas": {n: m.to_dict()
                              for n, m in self.metric_deltas.items()},
            "compared_metrics": list(self.compared_metrics),
            "state_transition_diff": None,
            "constraint_diff": None,
        }

    def __repr__(self) -> str:
        return (f"<ReliabilityDiff {self.comparability_state} "
                f"{len(self.compared_metrics)}/{len(self.metric_deltas)} "
                f"metrics compared>")


def diff_baselines(baseline_a, baseline_b,
                   evaluation_a=None, evaluation_b=None) -> ReliabilityDiff:
    """Difference two baselines, computing a number only where 5D-C allows.

    Comparability is decided FIRST and is not re-derived here. This module
    owns no comparability logic; duplicating it would let the two drift.

    `evaluation_a` / `evaluation_b` are optional and pass straight through to
    5D-C, which yields UNKNOWN when they are needed and absent.
    """
    from .comparability import compare, ComparabilityState, MetricState

    verdict = compare(baseline_a, baseline_b, evaluation_a, evaluation_b)

    ma = {m[0]: m for m in baseline_a.metrics}
    mb = {m[0]: m for m in baseline_b.metrics}

    deltas = {}
    for name, mc in verdict.per_metric.items():
        _, val_a, ver_a, prov_a = ma.get(name, (name, None, None, None))
        _, val_b, ver_b, prov_b = mb.get(name, (name, None, None, None))

        # A NUMBER ONLY WHERE THE PAIR AND THE METRIC BOTH ALLOW IT.
        #
        # The pair-level gate matters as much as the metric-level one: a
        # metric can be individually fine while the evaluation contexts are
        # incompatible, and a delta computed there would look valid.
        pair_ok = verdict.state == ComparabilityState.COMPARABLE
        metric_ok = mc.state == MetricState.COMPARABLE
        have_values = val_a is not None and val_b is not None

        if pair_ok and metric_ok and have_values:
            delta = val_b - val_a
            direction = (Direction.UNCHANGED if delta == 0
                         else Direction.DIFFERENT)
            reasons: tuple = ()
        else:
            # delta stays None. It is NOT 0.0: zero means the values are
            # equal, which is a measurement, and using it for "no comparison"
            # would let an absent comparison read as no difference.
            delta = None
            direction = Direction.UNDEFINED
            if not pair_ok:
                reasons = (f"the evaluation pair is "
                           f"{verdict.state}; no metric delta is computed",)
            elif not metric_ok:
                reasons = mc.reasons
            else:
                reasons = ("a value is absent on at least one side",)

        deltas[name] = MetricDelta(
            metric_name=name,
            state=mc.state,          # three states, carried through unchanged
            baseline_a_value=val_a, baseline_b_value=val_b,
            delta=delta, direction=direction,
            metric_version_a=ver_a, metric_version_b=ver_b,
            provenance_a=prov_a, provenance_b=prov_b,
            reasons=tuple(reasons),
        )

    return ReliabilityDiff(
        baseline_a_id=baseline_a.baseline_id,
        baseline_b_id=baseline_b.baseline_id,
        baseline_a_hash=baseline_a.baseline_hash,
        baseline_b_hash=baseline_b.baseline_hash,
        comparability_state=verdict.state,
        blockers=verdict.blockers,
        unknowns=verdict.unknowns,
        metric_deltas=deltas,
    )
