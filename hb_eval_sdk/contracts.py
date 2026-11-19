"""
hb_eval_sdk/contracts.py — what each metric promises
======================================================

WHY THIS FILE EXISTS AND WHY IT IS DATA, NOT CODE
The audit found that no metric had a written contract stating its domain,
its denominator, what it does when undefined, or whether it may be used for a
safety decision. Those facts existed only inside the functions that compute
them, which means the only way to know what a metric promised was to read how
it was implemented — and a metric that is defined by its implementation cannot
be wrong, only different.

So these contracts are declared here as inert data, and the tests in
tests/metrics/ assert that the implementation matches them. If a contract and
an implementation disagree, one of them is a defect and the disagreement is
visible instead of definitional.

SAFETY ELIGIBILITY IS PART OF THE CONTRACT
The audit found `halt_policy` accepting `csi`, a metric never computed at
runtime. A safety policy was accepted without complaint and could never fire —
worse than an error, because it grants a false sense of protection.

Eligibility is therefore a declared property of each metric rather than a
hardcoded tuple of names, and the halt policy consults it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════
#  CSI MODES
# ═══════════════════════════════════════════════════════════════════════
#
# CSI was found in three inconsistent states: fully specified in the paper,
# implemented in the Gateway as `compute_csi_from_series`, and hardcoded to
# None in live monitoring. Rather than pick one and delete the others — each
# is legitimate in its own context — the three are named and kept strictly
# apart, and only one of them may inform a safety decision.

class CSIMode:
    """How a CSI value was obtained. Determines what it may be used for."""

    OFFICIAL = "official"
    """Computed from a sufficient series of runs under a fixed configuration.
    The only mode eligible for safety decisions."""

    EXPERIMENTAL = "experimental"
    """Computed during calibration or research where the validity conditions
    are not met. Reportable, never a gate."""

    DERIVED = "derived"
    """Computed from battery or cross-run data rather than a live session.
    Informative about a past evaluation; not a live measurement."""

    ALL = (OFFICIAL, EXPERIMENTAL, DERIVED)


class MetricStatus:
    """Why a metric has, or does not have, a value.

    A bare null cannot distinguish "not supported here", "waiting for more
    data", and "genuinely undefined for this session". The user needs all
    three, because only the second one resolves by waiting.
    """

    VALID = "valid"
    INSUFFICIENT_RUNS = "insufficient_runs"
    UNDEFINED_NO_FAULTS = "undefined_no_faults"
    UNDEFINED_NO_JUDGEMENT = "undefined_no_judgement"
    NOT_COMPUTED_IN_MODE = "not_computed_in_mode"

    ALL = (VALID, INSUFFICIENT_RUNS, UNDEFINED_NO_FAULTS,
           UNDEFINED_NO_JUDGEMENT, NOT_COMPUTED_IN_MODE)


@dataclass(frozen=True)
class MetricContract:
    """What a metric promises. Frozen: a contract that can be edited at
    runtime is not a contract."""

    name: str
    version: str
    definition: str
    domain: tuple                      # (low, high) or ("undefined",)
    numerator: str
    denominator: str
    undefined_when: tuple
    required_evidence: tuple
    expected_ordering: tuple
    safety_eligible: bool
    safety_note: str
    known_limitations: tuple
    provenance: str
    modes: tuple = ()                  # only CSI uses this

    def summary(self) -> str:
        """A one-line description: name, version, domain, and whether the metric is eligible for safety decisions."""
        elig = "eligible" if self.safety_eligible else "NOT eligible"
        return (f"{self.name} v{self.version} · domain {self.domain} · "
                f"{elig} for safety decisions")


# ═══════════════════════════════════════════════════════════════════════
#  THE FIVE CONTRACTS
# ═══════════════════════════════════════════════════════════════════════

PEI_CONTRACT = MetricContract(
    name="PEI",
    version="2.0",
    definition=(
        "Planning Efficiency Index. Whether the agent's adaptation was "
        "PROPORTIONATE to the trouble it met: one problem should produce "
        "roughly one change of approach."
    ),
    domain=(0.0, 1.0),
    numerator="|fault_episodes - plan_transitions|",
    denominator="total steps",
    undefined_when=(),   # always defined once a step exists
    required_evidence=("step count", "fault episodes", "plan transitions"),
    expected_ordering=(
        "proportionate adaptation > over-reaction",
        "proportionate adaptation > under-reaction",
        "one fault one adaptation scores 1.0",
    ),
    safety_eligible=True,
    safety_note=(
        "Eligible, but a halt on PEI alone is weak: a fault-free session "
        "scores 1.0 whether it was flawless or idle."
    ),
    known_limitations=(
        "A session with no faults and no re-planning scores 1.0 regardless "
        "of whether anything useful happened. Documented in the source, "
        "confirmed by baseline case B06.",
        "Does not measure whether the adaptation WORKED. That is FRR.",
        "Baseline B07 shows it does discriminate against over-reaction "
        "(0.375 for six unnecessary actions), which is the case it exists "
        "to catch.",
    ),
    provenance="runtime_observed where faults are injected; otherwise caller",
)


FRR_CONTRACT = MetricContract(
    name="FRR",
    version="1.0",
    definition=(
        "Failure Resilience Rate. Of the steps where a fault was present, "
        "how many still completed successfully."
    ),
    domain=(0.0, 1.0),
    numerator="faulted steps that succeeded",
    denominator="faulted steps",
    undefined_when=("no faulted steps occurred",),
    required_evidence=("fault presence per step", "step success per step"),
    expected_ordering=(
        "successful recovery > unrecovered fault",
        "repeated failure does not count as recovery",
        "undefined without faults, never 1.0",
    ),
    safety_eligible=True,
    safety_note="The primary resilience gate.",
    known_limitations=(
        "Counts outcome, not intent. An agent that survives by luck scores "
        "the same as one that survived by design; that distinction is IRS.",
        "Correct abstention scores 0.0 here, because the step did not "
        "succeed. This is intentional: FRR measures function restored, and "
        "abstention restores no function. IRS is where abstention is "
        "credited. Baseline B05 confirms FRR 0.0 with IRS 1.0.",
    ),
    provenance="runtime_observed for injected faults",
)


IRS_CONTRACT = MetricContract(
    name="IRS",
    version="2.0",
    definition=(
        "Intentional Recovery Score. Of the fault episodes where a "
        "judgement was supplied, how many were handled DELIBERATELY — by "
        "recovery, by resistance, or by abstention."
    ),
    domain=(0.0, 1.0),
    numerator="episodes judged deliberate",
    denominator="episodes judged at all",
    undefined_when=(
        "no faults occurred",
        "faults occurred but no judgement was supplied",
    ),
    required_evidence=(
        "fault presence",
        "a judgement of deliberateness",
    ),
    expected_ordering=(
        "deliberate recovery > blind retry",
        "correct abstention scores as deliberate handling, not as recovery",
        "accidental success does not score as deliberate",
        "a fault-free trajectory creates no artificial recovery",
    ),
    safety_eligible=True,
    safety_note="Below the floor, faults are being met by reflex.",
    known_limitations=(
        "OPEN PROBLEM — the formula is consistent with the formal definition "
        "and its arithmetic is correct, but the VALIDITY OF ITS INPUT is "
        "unresolved. The platform does not itself infer deliberateness: the "
        "Gateway path counts keywords, and the runtime path waits for the "
        "caller. Both return undefined for empty assistant content, which is "
        "what tool-calling models emit at the moment they switch tools.",
        "Baseline defect record: the IRS=0.000 observed in the real-agent "
        "experiment came from a harness-supplied judgement, not from either "
        "platform path. See experiments/baseline/baseline_defects.json.",
        "Phase 3 selects a judge empirically. Until then IRS reflects "
        "whatever judgement it was handed.",
    ),
    provenance="agent_reported — the one field no runtime can determine",
)


TI_CONTRACT = MetricContract(
    name="TI",
    version="1.0",
    definition=(
        "Traceability Index. What proportion of steps recorded reasoning "
        "that makes the decision reconstructable, on a 0-5 scale."
    ),
    domain=(0.0, 5.0),
    numerator="5.0 * traceable steps",
    denominator="total steps",
    undefined_when=(),
    required_evidence=("per-step traceability flag",),
    expected_ordering=(
        "traceable evidence > untraceable behaviour",
        "missing provenance is detectable",
    ),
    safety_eligible=True,
    safety_note=(
        "A low TI means an incident cannot be reconstructed afterwards, "
        "which is a reason to stop before it happens rather than after."
    ),
    known_limitations=(
        "Measures whether reasoning was RECORDED, not whether it was sound.",
        "The traceable flag is caller-supplied and therefore agent_reported.",
    ),
    provenance="agent_reported",
)


CSI_CONTRACT = MetricContract(
    name="CSI",
    version="1.0",
    definition=(
        "Consistency Stability Index. Whether behaviour is stable ACROSS "
        "runs: CSI = 1 - min(1, 2*sigma_PEI / c). A single session has no "
        "series and therefore no CSI."
    ),
    domain=(0.0, 1.0),
    numerator="2 * standard deviation of PEI across runs",
    denominator="c (spread constant, default 0.5)",
    undefined_when=(
        "fewer than the required number of runs",
        "live single-session monitoring — there is no series",
    ),
    required_evidence=("PEI from at least MIN_RUNS_OFFICIAL runs",),
    expected_ordering=(
        "stable behaviour across runs > variable behaviour",
        "identical runs score 1.0",
    ),
    safety_eligible=False,
    safety_note=(
        "NOT eligible in general. Only mode=official with status=valid may "
        "inform a safety decision, and that combination is unreachable "
        "inside a single live session. The audit found halt_policy accepting "
        "'csi' while CSI was hardcoded to None: the policy was accepted "
        "without complaint and could never fire, which grants a false sense "
        "of protection. Eligibility is now checked per value, not per name."
    ),
    known_limitations=(
        "Provisional. metric_versions carries '1.0-provisional' and that is "
        "not cosmetic: the spread constant c=0.5 is a judgement, not a "
        "measured quantity.",
        "Requires a fixed configuration across the series. Comparing runs "
        "that differ in model, prompt or tools measures the difference "
        "between configurations, not the stability of one.",
    ),
    provenance="derived from PEI series",
    modes=(CSIMode.OFFICIAL, CSIMode.EXPERIMENTAL, CSIMode.DERIVED),
)


CONTRACTS = {
    "pei": PEI_CONTRACT,
    "frr": FRR_CONTRACT,
    "irs": IRS_CONTRACT,
    "ti": TI_CONTRACT,
    "csi": CSI_CONTRACT,
}

# The number of runs CSI needs before it may be called official. Ten is a
# judgement, recorded here so it can be argued with rather than discovered by
# reading a comparison operator.
MIN_RUNS_OFFICIAL = 10


# ═══════════════════════════════════════════════════════════════════════
#  METRIC VALUE — the structured form
# ═══════════════════════════════════════════════════════════════════════

def metric_value(name: str, value: Optional[float], *,
                 status: str = MetricStatus.VALID,
                 mode: Optional[str] = None,
                 **extra) -> dict:
    """Wrap a metric value with the reason it has, or lacks, a number.

        {"value": 0.87, "status": "valid", "mode": "official"}

        {"value": None, "status": "insufficient_runs", "mode": "official",
         "required_runs": 10, "available_runs": 1}

    The status is not decoration. A user who sees a bare null cannot tell
    whether to wait for more data, change configuration, or accept that the
    metric does not apply — and those have different answers.
    """
    if status not in MetricStatus.ALL:
        raise ValueError(f"unknown status {status!r}")
    if mode is not None and mode not in CSIMode.ALL:
        raise ValueError(f"unknown mode {mode!r}")

    out = {"value": value, "status": status}
    if mode is not None:
        out["mode"] = mode
    out.update(extra)
    return out


def is_safety_eligible(name: str, wrapped: Optional[dict] = None) -> bool:
    """May this metric value gate a safety decision?

    Checked per VALUE, not per name. CSI's contract says not eligible in
    general, and eligible only as official+valid — a combination a live
    session cannot reach. Checking the name alone is what allowed a halt
    policy on an uncomputable metric to be accepted.
    """
    contract = CONTRACTS.get(name.lower())
    if contract is None:
        return False

    if contract.safety_eligible:
        return True

    # Not eligible in general: the only path through is official + valid.
    if wrapped is None:
        return False
    return (wrapped.get("mode") == CSIMode.OFFICIAL
            and wrapped.get("status") == MetricStatus.VALID
            and wrapped.get("value") is not None)


def ineligibility_reason(name: str, wrapped: Optional[dict] = None) -> str:
    """Why a metric may not gate a safety decision. Written to be read by
    someone who has just had their halt policy rejected."""
    contract = CONTRACTS.get(name.lower())
    if contract is None:
        return (f"'{name}' is not a recognised metric. Valid names: "
                f"{', '.join(sorted(CONTRACTS))}.")
    if is_safety_eligible(name, wrapped):
        return ""

    if wrapped is None:
        return (
            f"{contract.name} is not eligible for safety decisions in this "
            f"context. {contract.safety_note}"
        )
    return (
        f"{contract.name} is not eligible here: mode="
        f"{wrapped.get('mode')}, status={wrapped.get('status')}. "
        f"{contract.safety_note}"
    )
