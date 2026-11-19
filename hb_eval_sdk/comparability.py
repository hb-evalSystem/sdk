"""
hb_eval_sdk/comparability.py — Phase 5D-C
==========================================

THE ONLY QUESTION THIS MODULE ANSWERS

    May these two baselines be meaningfully compared?

Not what the difference is. Not what caused it. Not whether it is a
regression. Those are 5D-D, and the last is constrained by DW-015.

    5D-C decides whether a question may be asked.
    5D-D asks it.

IDENTITY IS NOT COMPARABILITY

    baseline_id     which exact baseline is this?
    comparability   may these two be compared?

Same `baseline_id` means the SAME baseline, not "comparable" - and comparing a
baseline with itself is the degenerate case, not the interesting one.
Different `baseline_id` does not mean incomparable; every useful comparison is
between two different baselines.

`baseline_id` is never consulted here. INV-5DC-3 asserts that by reading this
module's source.

THREE STATES, AND THE DIFFERENCE IS THE REMEDY

    COMPARABLE       both valid, contexts known and compatible
    NOT_COMPARABLE   we already know the comparison is not meaningful
    UNKNOWN          we cannot tell from the inputs given

    NOT_COMPARABLE   -> supply different baselines, or accept these two
    UNKNOWN          -> supply the missing context; may resolve either way

Neither produces a delta. UNKNOWN is not a permissive middle: it withholds the
comparison exactly as NOT_COMPARABLE does, and differs only in what it tells
the caller to do next. Collapsing them would make a fixable situation look
permanent.

WHY UNKNOWN EXISTS AT ALL - a structural constraint, not caution

    ReliabilityBaseline stores `evaluation_fingerprint` as an OPAQUE HASH.

    A baseline alone cannot answer: scoring_version, protocol version,
    environment, seeds. A protocol change, a scoring change, an environment
    change and a seed change all produce the same signal - a different hash.

    So when the fingerprints differ and the EvaluationIdentity objects were
    not supplied, the reason is unavailable and the honest answer is UNKNOWN.

TWO SOURCES OF METRIC-VERSION TRUTH, AND WHICH ONE GOVERNS

    DECLARED   EvaluationIdentity.metric_versions
               caller-supplied; nothing in the SDK produces it
    RECORDED   ReliabilityBaseline.metrics
               derived from the envelope, i.e. from the actual measurement

    RECORDED GOVERNS. `_metric_conditions` adjudicates from it, because it is
    what the metrics were actually computed at. DECLARED is an assertion
    about context, and is used only to EXPLAIN a fingerprint difference.

WHY THE CONSISTENCY CHECK SITS BEHIND THE FINGERPRINT GATE

    The declared-versus-recorded check runs only when the baselines' STORED
    evaluation fingerprints differ. That is deliberate, and the reachability
    was analysed rather than assumed:

        fingerprints equal
            -> there is no difference to explain
            -> the EvaluationIdentity objects are never consulted
            -> a wrong declaration cannot influence the verdict
            -> and the per-metric layer still catches any real version
               difference, from the RECORDED versions

    Measured: two baselines sharing a stored fingerprint while recording
    different pei versions yield pei=NOT_COMPARABLE, frr=COMPARABLE,
    pair=COMPARABLE - the correct verdict, reached without the declaration.

    So validating the declaration there would add a check that changes no
    verdict. It is not a gap; it is validation the system does not need.
"""
from __future__ import annotations

from dataclasses import dataclass, field


def _pair(x, y) -> str:
    """Render two values order-independently.

    Blocker reasons must not change when the caller swaps its arguments, or
    INV-5DC-2 cannot hold as set equality. An earlier test weakened itself to
    `set(...) == set(...) or len(...) == len(...)` to accommodate reversible
    messages - which let two genuinely different reason sets pass merely by
    having the same count. The message is fixed here so the test can be
    strict.
    """
    a, b = sorted((repr(x), repr(y)))
    return f"{a} / {b}"

__all__ = [
    "compare",
    "EvaluationComparability",
    "MetricComparability",
    "ComparabilityState",
    "MetricState",
]


class ComparabilityState:
    """Whether two evaluations may be compared: COMPARABLE, NOT_COMPARABLE, or UNKNOWN when the evidence needed to decide is missing. UNKNOWN is not COMPARABLE."""
    COMPARABLE = "COMPARABLE"
    NOT_COMPARABLE = "NOT_COMPARABLE"
    UNKNOWN = "UNKNOWN"
    ALL = (COMPARABLE, NOT_COMPARABLE, UNKNOWN)


class MetricState:
    """Whether one metric may be compared between two evaluations.

    NOT_APPLICABLE means both sides declare that the metric consumes no evidence in this mode (CSI in
    a single live session). It is neither a defect nor comparable, and is distinct from a metric that
    was blocked.
    """
    COMPARABLE = "COMPARABLE"
    NOT_COMPARABLE = "NOT_COMPARABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    """Both sides declare the metric consumes no evidence in this mode - CSI in
    a single live session. Not a defect and not comparable; distinct from a
    metric that was blocked."""
    ALL = (COMPARABLE, NOT_COMPARABLE, NOT_APPLICABLE)


@dataclass(frozen=True)
class MetricComparability:
    """The comparability verdict for a single metric: its name, a MetricState, and the reasons behind it."""
    metric_name: str
    state: str
    reasons: tuple = ()

    def to_dict(self) -> dict:
        """The JSON-serialisable form: `metric_name`, `state` and `reasons`."""
        return {"metric_name": self.metric_name, "state": self.state,
                "reasons": list(self.reasons)}


@dataclass(frozen=True)
class EvaluationComparability:
    """The verdict, with its reasons kept separate by kind.

    `blockers` and `unknowns` are distinct lists because they call for
    different actions, and a caller seeing them merged cannot tell which
    action to take.

    `unknowns` is populated even when the state is NOT_COMPARABLE: a decisive
    blocker does not erase the fact that other context was missing, and hiding
    it would leave a caller unable to fix the second problem after the first.
    """

    state: str
    baseline_a_id: str
    baseline_b_id: str
    blockers: tuple = ()
    unknowns: tuple = ()
    per_metric: dict = field(default_factory=dict)

    @property
    def comparable(self) -> bool:
        """True only when the overall state is COMPARABLE."""
        return self.state == ComparabilityState.COMPARABLE

    @property
    def comparable_metrics(self) -> tuple:
        """The names of the metrics whose state is COMPARABLE, sorted."""
        return tuple(sorted(
            n for n, m in self.per_metric.items()
            if m.state == MetricState.COMPARABLE))

    def to_dict(self) -> dict:
        """The JSON-serialisable form: overall state, both baseline ids, blockers, unknowns and the per-metric verdicts."""
        return {
            "state": self.state,
            "baseline_a_id": self.baseline_a_id,
            "baseline_b_id": self.baseline_b_id,
            "blockers": list(self.blockers),
            "unknowns": list(self.unknowns),
            "per_metric": {n: m.to_dict() for n, m in self.per_metric.items()},
            "comparable_metrics": list(self.comparable_metrics),
        }


# ═══════════════════════════════════════════════════════════════════════
#  PAIR-LEVEL CONDITIONS
# ═══════════════════════════════════════════════════════════════════════

# EVERY field EvaluationIdentity.fingerprint() hashes, verified against its
# source. The comparator must account for all of them: returning COMPARABLE
# because an inspected SUBSET matches while an uninspected fingerprint-bearing
# field differs is the failure INV-5DC-8 exists to prevent.
#
#   fingerprint() hashes:
#       protocol · battery · scoring · metrics · environment · seeds · judge
#
# `metrics` is deliberately absent from this tuple: metric_versions are
# adjudicated PER METRIC from the baselines themselves, where a difference
# blocks one metric rather than the whole pair. It is accounted for, not
# ignored - see _metric_conditions and the residual guard below.
_CONTEXT_FIELDS = (
    "scoring_version",
    "evaluation_protocol_version",
    "fault_battery_fingerprint",
    "seeds",
)

# The judge is compared as ONE unit, not two fields. A change of judge is a
# single conceptual change - method and version move together - and reporting
# it twice would inflate the blocker count for one cause.

# SEEDS - an explicit decision, not an inference from "it is in the hash"
#
# Identity != Comparability, so a field being fingerprint-bearing does not by
# itself make it a blocker. Seeds are a blocker here for a specific reason:
#
#   Seeds drive scenario generation and fault timing. Two evaluations under
#   different seeds were subjected to different injected conditions, so a
#   PAIRWISE difference between them may be the seed rather than the agent.
#
# WHAT THIS DELIBERATELY DOES NOT DECIDE
#
#   Repeated runs across seeds are a legitimate methodology - CSI measures
#   stability across them, and treating that as "incomparable" would be
#   wrong. But population or repeated-run comparability is a DIFFERENT
#   question with different statistics, and 5D-C answers only the pairwise
#   one. Deferred as DW-026.


def _pair_conditions(a, b, eval_a, eval_b):
    """Return (blockers, unknowns) for the pair as a whole.

    Both lists are always returned in full. Nothing short-circuits: a caller
    who fixes one problem and rediscovers the next on the following attempt
    learns the state of their inputs one failure at a time.
    """
    blockers, unknowns = [], []

    # ── determinable from the baselines alone ───────────────────────
    for label, base in (("A", a), ("B", b)):
        v = base.verify()
        if not v["valid"]:
            blockers.append(
                f"baseline {label} does not verify: {v['problems'][:2]}")

    # PAIRWISE ONLY. Two slots are two scenarios, so comparing them PAIRWISE
    # would report a scenario difference as a reliability difference.
    #
    # This is NOT a claim that different slots are universally incomparable.
    # A reliability profile ACROSS scenarios is a legitimate future question -
    # it is battery aggregation, which the 5D-C scope lock excludes and DW-024
    # holds.
    if a.battery_slot_id != b.battery_slot_id:
        blockers.append(
            f"battery_slot_id differs "
            f"({_pair(a.battery_slot_id, b.battery_slot_id)}): two different "
            f"scenarios, not "
            f"two runs of one. Pairwise comparison would report a scenario "
            f"difference as a reliability difference. Comparing ACROSS "
            f"scenarios is battery aggregation (DW-024), not this")

    if a.battery_spec_fingerprint != b.battery_spec_fingerprint:
        blockers.append(
            f"battery_spec_fingerprint differs "
            f"({_pair(a.battery_spec_fingerprint, b.battery_spec_fingerprint)}): "
            f"a different specification is a different question, not a "
            f"different answer to the same one")

    # ── requires EvaluationIdentity ─────────────────────────────────
    #
    # Equal fingerprints already establish context equivalence, so no object
    # is needed. Differing fingerprints without the objects leave the REASON
    # unavailable, and the reason decides the verdict - a protocol change
    # blocks, an irrelevant field does not.
    if a.evaluation_fingerprint != b.evaluation_fingerprint:
        if eval_a is None or eval_b is None:
            missing = [n for n, o in (("evaluation_a", eval_a),
                                      ("evaluation_b", eval_b)) if o is None]
            unknowns.append(
                f"evaluation_fingerprint differs and {', '.join(missing)} "
                f"{'was' if len(missing) == 1 else 'were'} not supplied: the "
                f"fingerprint is opaque, so which field moved - scoring, "
                f"protocol, environment or seeds - cannot be determined")
        else:
            # Named for what it means: a cause OTHER THAN metric_versions
            # that is known to have moved the fingerprint. `context_explained`
            # was misleading - the judge is not context in the narrow sense,
            # and environment has its own comparison. In a design that rests
            # on invariants, the name is part of the proof.
            known_non_metric_fingerprint_cause = False

            for name in _CONTEXT_FIELDS:
                va = getattr(eval_a, name, None)
                vb = getattr(eval_b, name, None)
                if va != vb:
                    blockers.append(f"{name} differs ({_pair(va, vb)})")
                    known_non_metric_fingerprint_cause = True

            # JUDGE CONFIGURATION - a formal unit of comparison.
            #
            # NOT the claim that method and version always move together;
            # either can move alone. The claim is narrower and provable: what
            # matters for comparability is whether the JUDGE CONFIGURATION
            # differs, because a change to either field means the measurement
            # process changed. That matters most for IRS, already provisional
            # under DW-012.
            #
            # Compared as a unit so one configuration change reports one
            # blocker instead of two.
            judge_config_a = (eval_a.judge_method, eval_a.judge_version)
            judge_config_b = (eval_b.judge_method, eval_b.judge_version)
            if judge_config_a != judge_config_b:
                blockers.append(
                    f"judge configuration differs "
                    f"({_pair(judge_config_a, judge_config_b)})")
                known_non_metric_fingerprint_cause = True

            env_a = (eval_a.environment or {}).get("fingerprint")
            env_b = (eval_b.environment or {}).get("fingerprint")
            if env_a != env_b:
                blockers.append(
                    f"environment differs ({_pair(env_a, env_b)}): the runs "
                    f"were measured under different conditions")
                known_non_metric_fingerprint_cause = True

            # ── RESIDUAL GUARD (INV-5DC-8) ──────────────────────
            #
            # The fingerprints differ. If nothing inspected above explains
            # that, and no metric_version differs either, then a
            # fingerprint-bearing field this comparator does not know about
            # has moved.
            #
            # THE FAILURE THIS PREVENTS
            # Returning COMPARABLE because an inspected SUBSET matched while
            # something uninspected changed the evaluation context. The
            # verdict would then rest on the fields that happened to be
            # checked rather than on the full context.
            #
            # UNKNOWN rather than NOT_COMPARABLE, because we do not know the
            # unexplained field is decisive - only that we cannot account for
            # it. The remedy is to extend _CONTEXT_FIELDS, which is fixable,
            # and UNKNOWN is the state that says so.
            # `metric_versions` is fingerprint-bearing AND adjudicated per
            # metric. If it differs, the fingerprint difference IS explained -
            # by a difference that blocks individual metrics rather than the
            # pair. Suppressing the residual guard here is therefore correct,
            # and it is stated rather than left implicit: the guard fires only
            # when NOTHING known explains the difference.
            # ── metric_versions: EXPLAINS the fingerprint only if the
            #    per-metric layer will actually adjudicate it ───────────
            #
            # THE GAP THIS CLOSES
            #
            # `metric_versions` lives on EvaluationIdentity and is
            # fingerprint-bearing. But `_metric_conditions` adjudicates
            # versions from the BASELINE's own metrics tuple and never reads
            # EvaluationIdentity at all.
            #
            # So a difference in eval.metric_versions was accepted as
            # "explained, handled per metric" while the per-metric layer
            # compared something else entirely. If the baselines carried
            # matching versions, every metric came back COMPARABLE and the
            # residual guard stayed silent - a verdict of COMPARABLE resting
            # on an explanation nothing verified.
            #
            # The two must agree before the explanation is accepted. Where
            # they disagree the inputs are inconsistent: a baseline produced
            # under an evaluation whose declared metric versions do not match
            # the versions recorded in its own metrics.
            # THE FULL SET, not only the shared names.
            #
            # An earlier version compared versions only where
            # `name in recorded`, which missed two cases that are not version
            # differences at all but DIFFERENT METRIC SETS:
            #
            #   declared and not recorded - the identity names a metric the
            #       baseline never carried, so the per-metric layer will never
            #       adjudicate it and it cannot explain anything
            #   recorded and not declared - the baseline carries a metric the
            #       identity never declared, so the declaration is incomplete
            #
            # Both mean the declaration does not describe this baseline.
            #
            # CONTROL FLOW ON A BOOLEAN, NOT ON MESSAGE TEXT. The earlier
            # version decided by searching blockers for the substring
            # "internally inconsistent", tying a logical decision to the
            # presentation layer: rewording the message would silently change
            # behaviour.
            metric_declaration_is_consistent = True

            for label, ev_obj, base in (("A", eval_a, a), ("B", eval_b, b)):
                declared = dict(ev_obj.metric_versions or {})
                recorded = {name: ver for name, _, ver, _ in base.metrics}

                only_declared = sorted(set(declared) - set(recorded))
                version_mismatch = sorted(
                    n for n in set(declared) & set(recorded)
                    if declared[n] != recorded[n])

                # RECORDED-BUT-NOT-DECLARED IS NOT A DEFECT, and this was
                # checked rather than assumed: no production code populates
                # `metric_versions`, and configuration.py documents no
                # completeness requirement. A partial declaration is
                # legitimate, and the per-metric layer adjudicates the
                # RECORDED versions regardless.
                #
                # Treating it as a defect would invent a constraint the system
                # does not have and reject every partial declaration.
                problems = []
                if only_declared:
                    problems.append(
                        f"declares {only_declared} which the baseline does "
                        f"not record, so the per-metric layer can never "
                        f"adjudicate it")
                if version_mismatch:
                    problems.append(
                        f"disagrees on versions for "
                        f"{[(n, declared[n], recorded[n]) for n in version_mismatch]}")

                if problems:
                    metric_declaration_is_consistent = False
                    blockers.append(
                        f"baseline {label} and its EvaluationIdentity "
                        f"describe different metric sets: "
                        f"{'; '.join(problems)}. The per-metric layer "
                        f"adjudicates the RECORDED metrics, so the "
                        f"declaration cannot be trusted to explain the "
                        f"fingerprint difference")

            # Accepted as an explanation ONLY when the declarations differ AND
            # each side's declaration actually describes its own baseline -
            # i.e. the per-metric layer really is adjudicating this difference.
            metric_versions_explain_it = (
                eval_a.metric_versions != eval_b.metric_versions
                and metric_declaration_is_consistent)

            if (not known_non_metric_fingerprint_cause
                    and not metric_versions_explain_it):
                unknowns.append(
                    "evaluation_fingerprint differs but no inspected field "
                    "accounts for it: a fingerprint-bearing field outside "
                    "this comparator's knowledge has changed. Reporting "
                    "COMPARABLE would rest the verdict on the fields that "
                    "happened to be checked")

    return blockers, unknowns


# ═══════════════════════════════════════════════════════════════════════
#  PER-METRIC CONDITIONS
# ═══════════════════════════════════════════════════════════════════════

def _metric_conditions(a, b):
    """One verdict per metric, independent of the pair-level result.

    If IRS changed version and FRR did not, FRR is comparable and IRS is not -
    rather than blocking everything or comparing everything regardless.
    """
    ma = {m[0]: m for m in a.metrics}
    mb = {m[0]: m for m in b.metrics}
    out = {}

    for name in sorted(set(ma) | set(mb)):
        if name not in ma or name not in mb:
            out[name] = MetricComparability(
                name, MetricState.NOT_COMPARABLE,
                (f"present on only one side "
                 f"({'A' if name in ma else 'B'} only)",))
            continue

        _, val_a, ver_a, prov_a = ma[name]
        _, val_b, ver_b, prov_b = mb[name]

        # NOT_APPLICABLE on both sides is not a defect. CSI consumes no
        # evidence in a single live session; nothing is absent.
        if prov_a == "not_applicable" and prov_b == "not_applicable":
            out[name] = MetricComparability(
                name, MetricState.NOT_APPLICABLE,
                ("both sides declare the metric consumes no evidence in this "
                 "mode",))
            continue

        reasons = []
        if ver_a != ver_b:
            reasons.append(
                f"metric_version differs ({ver_a} vs {ver_b}): the two values "
                f"were produced by different definitions, so a delta would be "
                f"arithmetic rather than information")
        if val_a is None or val_b is None:
            reasons.append(
                f"no value on side {'A' if val_a is None else 'B'}")
        for label, prov in (("A", prov_a), ("B", prov_b)):
            if prov == "missing":
                reasons.append(
                    f"provenance_status is MISSING on side {label}: evidence "
                    f"was expected and not found")
            elif prov != "applicable":
                reasons.append(
                    f"provenance_status is {prov!r} on side {label}")

        out[name] = MetricComparability(
            name,
            MetricState.NOT_COMPARABLE if reasons else MetricState.COMPARABLE,
            tuple(reasons))

    return out


# ═══════════════════════════════════════════════════════════════════════
#  THE VERDICT
# ═══════════════════════════════════════════════════════════════════════

def compare(baseline_a, baseline_b,
            evaluation_a=None, evaluation_b=None) -> EvaluationComparability:
    """Decide whether two baselines may be meaningfully compared.

    `evaluation_a` and `evaluation_b` are OPTIONAL. Equal evaluation
    fingerprints already establish context equivalence; supplying the objects
    then adds nothing. They are needed only when the fingerprints differ, and
    their absence yields UNKNOWN rather than a guess.

    `EvidenceEnvelope` is deliberately NOT an input. Requiring it would couple
    comparison to evidence retention, which DW-010 has not solved, and would
    make comparison impossible once evidence is discarded.

    Returns a verdict. Computes no delta, attributes nothing, ranks nothing.
    """
    blockers, unknowns = _pair_conditions(
        baseline_a, baseline_b, evaluation_a, evaluation_b)
    per_metric = _metric_conditions(baseline_a, baseline_b)

    # STATE PRIORITY
    #
    #   1  a known pair-level blocker        -> NOT_COMPARABLE
    #   2  otherwise, an undeterminable one  -> UNKNOWN
    #   3  otherwise, no comparable metric   -> NOT_COMPARABLE
    #   4  otherwise                         -> COMPARABLE
    #
    # A KNOWN DECISIVE BLOCKER OUTRANKS UNKNOWN CONTEXT. If the battery
    # specification differs, the comparison is invalid regardless of what else
    # is unavailable, and answering UNKNOWN would send the caller looking for
    # context that cannot change the answer.
    #
    # `unknowns` is still reported in that case: a decisive blocker does not
    # erase the fact that other context was missing, and hiding it would leave
    # the caller unable to fix the second problem after fixing the first.
    if blockers:
        state = ComparabilityState.NOT_COMPARABLE
    elif unknowns:
        state = ComparabilityState.UNKNOWN
    elif not any(m.state == MetricState.COMPARABLE
                 for m in per_metric.values()):
        # Nothing to compare. Reporting COMPARABLE here would invite a delta
        # that cannot be computed for any metric.
        state = ComparabilityState.NOT_COMPARABLE
        blockers = ("no metric is individually comparable",)
    else:
        state = ComparabilityState.COMPARABLE

    return EvaluationComparability(
        state=state,
        baseline_a_id=baseline_a.baseline_id,
        baseline_b_id=baseline_b.baseline_id,
        blockers=tuple(blockers),
        unknowns=tuple(unknowns),
        per_metric=per_metric,
    )
