"""
hb_eval_sdk/evidence_package.py — what was tested, how, and what happened
==========================================================================

THE FOUR-WAY SEPARATION THIS FILE PRESERVES

    Fingerprint     what configuration was this?
    Envelope        what was tested, how, under which conditions, and what
                    happened?                                    <- HERE
    Judgment        was the observed behaviour deliberate?
    Certification   what may legitimately be concluded?

They are kept apart because each can be wrong independently, and merging any
two makes one of them unfalsifiable. An envelope with impeccable integrity can
contain evidence of an agent that behaved badly; a certificate is a claim
about what the envelope permits, not a property of the envelope.

WHAT PHASE 4 MAY NOT DO
No certificate. No signature. The envelope is the input to Phases 5-7, and
signing an artefact whose schema is still moving produces signatures that
verify a shape nobody will keep.

SEAL BEFORE HASH, AND THE ORDER IS THE POINT
A hash computed over a mutable object certifies nothing: whatever it certified
can be changed afterwards, and the hash still verifies against the version
that was hashed rather than the version being read. So `seal()` freezes the
contents first and computes the hash second, and `add_*` raises after sealing.
This is failure case 10.

A HASH IS NOT PROVENANCE
Failure case 8 is a valid hash over insufficient evidence. A hash proves that
what is present is unchanged; it says nothing about whether what is present is
enough to know what was tested. `verify()` therefore checks integrity AND
completeness, and reports them separately, because they fail for different
reasons and have different remedies.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

try:
    from .configuration import ConfigurationFingerprint, EvaluationIdentity
except ImportError:                      # direct execution from tests/
    from configuration import ConfigurationFingerprint, EvaluationIdentity  # type: ignore[no-redef]


__all__ = [
    "EvidenceEnvelope", "MetricProvenance", "EnvelopeError",
    "MetricRef", "RefType", "ProvenanceStatus", "ExecutionBinding",
    "EnvelopeState",
    "VerificationResult",
]


class EnvelopeError(Exception):
    """Raised when an envelope cannot be built or has been misused."""


# ═══════════════════════════════════════════════════════════════════════
#  METRIC PROVENANCE — the missing link in I -> P -> A -> O -> M
# ═══════════════════════════════════════════════════════════════════════

class RefType:
    """What kind of thing a provenance reference points at.

    The metrics do not all consume one kind of entity, and an untyped list of
    ids would force a later phase to discover that. Measured from the
    computation:

        PEI   numerator: fault EPISODES + plan TRANSITIONS
              denominator: all STEPS
        FRR   faulted STEPS that succeeded / faulted STEPS
        IRS   judged EPISODES deliberate / judged EPISODES
        TI    traceable STEPS / all STEPS

    An episode is not a step: it opens on the first faulted step and spans
    several, so the counts differ. A plan transition is a property of a step
    rather than a step itself.
    """

    STEP = "step"
    FAULT_EVENT = "fault_event"
    EPISODE = "episode"
    PLAN_TRANSITION = "plan_transition"
    ALL = (STEP, FAULT_EVENT, EPISODE, PLAN_TRANSITION)


class ProvenanceStatus:
    """Whether a metric consumed evidence, and if not, why not.

    An empty ref list conflates three different facts:

        APPLICABLE      consumed evidence; the refs list it
        NOT_APPLICABLE  does not consume evidence in this mode
        MISSING         should have consumed evidence and none was found

    Only the second is a non-problem, and an empty list cannot tell them
    apart. CSI is NOT_APPLICABLE in live single-session mode: it needs a
    series across runs and one session has none.
    """

    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    MISSING = "missing"
    ALL = (APPLICABLE, NOT_APPLICABLE, MISSING)


@dataclass(frozen=True)
class MetricRef:
    """One typed, resolvable reference into the evidence model.

    `ref_id` must resolve to something present in the envelope. A reference
    resolving to nothing is worse than no reference, because it implies
    evidence that does not exist - so `dangling_refs()` reports any that do
    not.

        step             ST-<session>-<index>
        fault_event      FE-<hex>
        episode          EP-<session>-<n>
        plan_transition  PT-<session>-<index>
    """

    ref_type: str
    ref_id: str

    def __post_init__(self):
        if self.ref_type not in RefType.ALL:
            raise EnvelopeError(
                f"unknown ref_type {self.ref_type!r}. A reference nothing has "
                f"reasoned about lets provenance depend on anything.")

    def to_dict(self) -> dict:
        """`{"ref_type": ..., "ref_id": ...}`: a pointer from a metric to one piece of evidence it was computed from."""
        return {"ref_type": self.ref_type, "ref_id": self.ref_id}


@dataclass(frozen=True)
class ExecutionBinding:
    """Which execution a session's evidence belongs to.

    SESSION-LEVEL and immutable. Duplicating identity onto every event would
    make it mutable in more places, which Phase 4 avoided; and re-binding a
    session after events exist would retroactively attribute those events to
    an execution that did not exist when they occurred.

    ENTERS THE ENVELOPE'S CANONICAL FORM, so the existing integrity hash
    covers it. Attached outside it, the traceability chain would rest on a
    field nothing verifies.
    """

    execution_id: str
    battery_spec_fingerprint: str
    battery_instance_id: str
    battery_slot_id: str
    base_task_hash: str
    configuration_fingerprint: str
    execution_semantics_hash: str
    identity_status: str = "COMPLETE"
    identity_missing: tuple = ()

    def __post_init__(self):
        if self.identity_status not in ("COMPLETE", "PARTIAL", "UNAVAILABLE"):
            raise EnvelopeError(
                f"unknown identity_status {self.identity_status!r}")
        if self.identity_status == "PARTIAL" and not self.identity_missing:
            raise EnvelopeError(
                "a PARTIAL identity must name what is missing. A bare PARTIAL "
                "flag repeats the silence about undeclared inputs that the "
                "declaration states exist to prevent.")

    @property
    def comparison_eligible(self) -> bool:
        """Only COMPLETE. A PARTIAL identity carries an execution_id and is
        not thereby comparable - the same rule as a PARTIAL envelope, which
        exists and cannot anchor a baseline."""
        return self.identity_status == "COMPLETE"

    def to_dict(self) -> dict:
        """The JSON-serialisable form, with the list of identity fields that are missing and whether the execution is eligible for comparison."""
        d = asdict(self)
        d["identity_missing"] = list(self.identity_missing)
        d["comparison_eligible"] = self.comparison_eligible
        return d


@dataclass(frozen=True)
class MetricProvenance:
    """A metric value bound to the events that produced it.

    Today a metric is a number with no record of where it came from. Asking
    "why is FRR 0.79" requires re-deriving it, which answers a different
    question: it tells you what the formula would produce now, not what
    produced the recorded value then.

    Binding the value to event ids makes the question answerable by lookup,
    and makes a value whose events are missing detectable rather than merely
    unexplained.
    """

    metric_name: str
    value: Optional[float]
    metric_version: str

    contributing_event_ids: tuple
    """DEPRECATED - a lossy compatibility PROJECTION, not provenance.

    Contains ONLY the fault_event refs that genuinely exist. Empty when a
    metric consumed no fault events, which is most of the time: PEI and TI
    always consume steps and episodes, FRR and IRS usually do.

    An earlier design proposed the union of all typed refs. Withdrawn: that
    union contains step and episode ids, and a field named
    contributing_event_ids holding non-event ids would degrade correct typed
    provenance to keep a legacy field looking full.

    Removal tracked as DW-021. Use numerator_refs / denominator_refs.
    """

    numerator: Optional[float] = None
    denominator: Optional[float] = None

    numerator_refs: tuple = ()
    """Exactly the typed refs that entered the numerator - none that did not,
    none omitted that did."""

    denominator_refs: tuple = ()
    """Exactly the typed refs that entered the denominator."""

    supporting_refs: tuple = ()
    """Linked context, such as fault events associated with a step.

    SEPARATE from numerator and denominator deliberately. Merging them would
    break the `Actual Inputs == Recorded Provenance` equality, because
    supporting refs are context rather than inputs.
    """

    provenance_status: str = "applicable"

    status: str = "valid"
    undefined_reason: Optional[str] = None

    def __post_init__(self):
        if self.value is None and not self.undefined_reason:
            raise EnvelopeError(
                f"{self.metric_name} is None with no undefined_reason. A bare "
                f"null cannot tell a reader whether the metric was "
                f"inapplicable, awaiting data, or never computed - and those "
                f"have different remedies.")
        if self.provenance_status not in ProvenanceStatus.ALL:
            raise EnvelopeError(
                f"unknown provenance_status {self.provenance_status!r}")

        # A value with no refs is legitimate only when the metric does not
        # consume evidence in this mode. CSI is that case: it needs a series
        # across runs and a single session has none.
        # DEPRECATION WINDOW (DW-021). A legacy construction supplying only
        # contributing_event_ids counts as evidence for this check. The field
        # is deprecated, not removed, and rejecting it here would break the
        # Phase 4 tests - which are part of the integrity oracle for I1 and
        # I3, and must not change in the same phase that changes the metric
        # path.
        _has_refs = bool(self.numerator_refs or self.denominator_refs
                         or self.contributing_event_ids)

        if (self.value is not None and not _has_refs
                and self.provenance_status == ProvenanceStatus.APPLICABLE):
            raise EnvelopeError(
                f"{self.metric_name} has a value, no refs, and claims to be "
                f"APPLICABLE. A number with no evidence behind it is what "
                f"this class exists to make impossible. Use NOT_APPLICABLE if "
                f"the metric genuinely does not consume evidence here.")

    @property
    def all_refs(self) -> tuple:
        """Numerator and denominator only. Supporting refs are context, and
        including them would make the actual-inputs equality pass on refs that
        were never inputs."""
        return tuple(self.numerator_refs) + tuple(self.denominator_refs)

    def to_dict(self) -> dict:
        """The JSON-serialisable form: the metric's name, value and version, and the numerator, denominator and supporting evidence it was computed from."""
        return {
            "metric_name": self.metric_name,
            "value": self.value,
            "metric_version": self.metric_version,
            "numerator_refs": [r.to_dict() for r in self.numerator_refs],
            "denominator_refs": [r.to_dict() for r in self.denominator_refs],
            "supporting_refs": [r.to_dict() for r in self.supporting_refs],
            "provenance_status": self.provenance_status,
            "contributing_event_ids": list(self.contributing_event_ids),
            "_contributing_event_ids_note":
                "DEPRECATED projection of fault_event refs only; see DW-021",
            "numerator": self.numerator,
            "denominator": self.denominator,
            "status": self.status,
            "undefined_reason": self.undefined_reason,
        }


class EnvelopeState:
    """What an envelope IS, derived from verification rather than asserted.

    Four states, and the distinction between two of them is the reason this
    class exists rather than a boolean.

        COMPLETE     sealed, intact, provenance sufficient
        PARTIAL      sealed and intact, but provenance insufficient
        INVALID      sealed, and something was altered after sealing
        UNVERIFIED   not sealed; contents can still change

    PARTIAL is NOT a cosmetic flag. An envelope whose metrics cannot be traced
    to the events that produced them is valid evidence of something and
    insufficient evidence for a comparison: any difference found against it
    may be an artefact of what was never captured rather than a change in the
    agent. `baseline_eligible` therefore refuses it, and refuses it here, in
    the envelope, rather than in whatever code later decides to build a
    baseline.

    Putting the refusal in the consumer would mean every future consumer has
    to remember, and the first one that forgets creates a baseline from
    partial evidence that then looks exactly like a good one.

    PARTIAL must also stay distinguishable from a FAILURE TO PRODUCE an
    envelope at all, which is represented by `envelope is None` and a
    populated `envelope_error`. "We recorded a run but could not trace its
    metrics" and "we could not record the run" are different facts with
    different remedies, and collapsing them loses the one that is actionable.
    """

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    INVALID = "INVALID"
    UNVERIFIED = "UNVERIFIED"

    ALL = (COMPLETE, PARTIAL, INVALID, UNVERIFIED)

    BASELINE_ELIGIBLE = (COMPLETE,)
    """Only COMPLETE. Stated as data so a test can assert the set rather than
    trusting a conditional somewhere."""


@dataclass
class VerificationResult:
    """Integrity and completeness, reported separately.

    Separately because they fail for different reasons: integrity fails when
    something was altered, completeness when something was never captured. A
    single boolean would collapse "this was tampered with" and "this was never
    finished" into one verdict, and they call for different responses.
    """

    integrity_ok: bool
    completeness_ok: bool
    integrity_problems: list = field(default_factory=list)
    completeness_problems: list = field(default_factory=list)

    sealed: bool = True
    """Needed to distinguish UNVERIFIED from INVALID: an unsealed envelope has
    not been tampered with, it simply has not been closed."""

    @property
    def verified(self) -> bool:
        """True only if both the integrity check and the completeness check passed."""
        return self.integrity_ok and self.completeness_ok

    @property
    def state(self) -> str:
        """The envelope's state, derived from what was checked."""
        if not self.sealed:
            return EnvelopeState.UNVERIFIED
        if not self.integrity_ok:
            return EnvelopeState.INVALID
        if not self.completeness_ok:
            return EnvelopeState.PARTIAL
        return EnvelopeState.COMPLETE

    @property
    def baseline_eligible(self) -> bool:
        """May this envelope anchor a reliability baseline?

        Only COMPLETE. A baseline anchored to partial evidence produces
        differences that may be artefacts of what was never captured, and a
        comparison whose differences might not be about the agent is worse
        than no comparison, because it will be acted on.
        """
        return self.state in EnvelopeState.BASELINE_ELIGIBLE

    def summary(self) -> str:
        """A one-line, human-readable result that names how many integrity problems and completeness gaps were found, if any."""
        if self.verified:
            return "verified: integrity intact, provenance complete"
        parts = []
        if not self.integrity_ok:
            parts.append(f"integrity FAILED ({len(self.integrity_problems)})")
        if not self.completeness_ok:
            parts.append(
                f"provenance INCOMPLETE ({len(self.completeness_problems)})")
        return " · ".join(parts)


# ═══════════════════════════════════════════════════════════════════════
#  THE ENVELOPE
# ═══════════════════════════════════════════════════════════════════════

REQUIRED_FOR_COMPLETENESS = (
    "configuration", "evaluation", "run_id", "started_at", "completed_at",
)


class EvidenceEnvelope:
    """One evaluation run: its identity, its evidence, and its metrics.

    Mutable while open, immutable once sealed. The lifecycle is the mechanism:

        open   -> add_fault_event, add_enforcement_record, add_metric
        seal   -> contents frozen, THEN hashed
        verify -> integrity and completeness, checked separately

    An envelope that could be hashed while still open would produce a hash of
    a moment rather than of a document.
    """

    def __init__(self, *,
                 configuration: ConfigurationFingerprint,
                 evaluation: EvaluationIdentity,
                 run_id: Optional[str] = None):
        if not isinstance(configuration, ConfigurationFingerprint):
            raise EnvelopeError(
                "configuration must be a ConfigurationFingerprint. Evidence "
                "not bound to an identified configuration cannot be compared "
                "to any other evidence.")
        if not isinstance(evaluation, EvaluationIdentity):
            raise EnvelopeError("evaluation must be an EvaluationIdentity")

        self.configuration = configuration
        self.evaluation = evaluation
        self.run_id = run_id or f"RUN-{uuid.uuid4().hex[:12]}"
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.completed_at: Optional[str] = None

        self._execution_binding = None
        self._step_refs: set = set()
        self._fault_events: list = []
        self._enforcement_records: list = []
        self._metrics: dict = {}
        self._sealed = False
        self._envelope_hash: Optional[str] = None

    # ── while open ──────────────────────────────────────────────────

    def _require_open(self, what: str):
        if self._sealed:
            raise EnvelopeError(
                f"cannot {what}: this envelope is sealed. Its hash was "
                f"computed over the contents as they stood at sealing, and "
                f"admitting anything afterwards would leave a hash that "
                f"verifies a document nobody is reading.")

    def add_fault_event(self, event) -> None:
        """Add a fault event to the envelope. Raises EnvelopeError once the envelope is sealed."""
        self._require_open("add a fault event")
        self._fault_events.append(event)

    def add_enforcement_record(self, record) -> None:
        """Add an enforcement record to the envelope. Raises EnvelopeError once the envelope is sealed."""
        self._require_open("add an enforcement record")
        self._enforcement_records.append(record)

    def bind_execution(self, binding) -> None:
        """Attach the execution this envelope's evidence belongs to.

        Once only, and before sealing. A second binding would let evidence be
        re-attributed to a different execution after the fact, which makes
        every downstream attribution unfalsifiable.
        """
        self._require_open("bind an execution")
        if self._execution_binding is not None:
            raise EnvelopeError(
                "already bound to an execution. Re-binding would re-attribute "
                "evidence to an execution that did not produce it.")
        self._execution_binding = binding

    @property
    def execution_binding(self):
        """The execution binding attached to the envelope, or None if none was set."""
        return self._execution_binding

    def register_step_refs(self, refs) -> None:
        """Declare which refs exist in this run, so a dangling reference is
        detected rather than believed.

        Stores (ref_type, ref_id) PAIRS, not bare ids. Ids alone would let
        MetricRef("episode", "ST-abc-1") resolve because a STEP with that id
        exists - the reference would be typed and the resolver would not check
        the type, making "typed, resolvable" only half true.
        """
        self._require_open("register step refs")
        for r in refs:
            if isinstance(r, MetricRef):
                self._step_refs.add((r.ref_type, r.ref_id))
            elif isinstance(r, tuple) and len(r) == 2:
                self._step_refs.add(r)
            else:
                raise EnvelopeError(
                    f"expects MetricRef or (type, id) pairs, got "
                    f"{type(r).__name__}. A bare id cannot be type-checked "
                    f"at resolution.")

    def add_metric(self, provenance: MetricProvenance) -> None:
        """Add a metric with its provenance. A bare number is refused: a metric that cannot be traced to the events that produced it is exactly what the envelope exists to prevent. Raises EnvelopeError once sealed."""
        self._require_open("add a metric")
        if not isinstance(provenance, MetricProvenance):
            raise EnvelopeError(
                "metrics must be added as MetricProvenance. A bare number "
                "cannot be traced to the events that produced it, which is "
                "the whole reason this envelope exists.")
        self._metrics[provenance.metric_name] = provenance

    # ── sealing ─────────────────────────────────────────────────────

    def seal(self) -> str:
        """Freeze the contents, then hash them. Returns the envelope hash.

        The order is the point. Hashing a mutable object certifies a moment;
        sealing first certifies a document.
        """
        if self._sealed:
            raise EnvelopeError("already sealed")

        self.completed_at = datetime.now(timezone.utc).isoformat()
        self._fault_events = tuple(self._fault_events)  # type: ignore[assignment]
        self._enforcement_records = tuple(self._enforcement_records)  # type: ignore[assignment]
        self._metrics = dict(self._metrics)
        self._sealed = True
        self._envelope_hash = self._compute_hash()
        return self._envelope_hash

    @property
    def sealed(self) -> bool:
        """True once `seal()` has been called; a sealed envelope accepts no further additions."""
        return self._sealed

    @property
    def envelope_hash(self) -> Optional[str]:
        """The envelope's content hash, or None until it is sealed."""
        return self._envelope_hash

    @property
    def state(self) -> str:
        """COMPLETE / PARTIAL / INVALID / UNVERIFIED.

        Exposed on the envelope so a consumer does not have to know that the
        answer comes from verify(). A consumer that has to remember an extra
        call is a consumer that will eventually not.
        """
        return self.verify().state

    @property
    def baseline_eligible(self) -> bool:
        """May this envelope anchor a baseline? Only when COMPLETE."""
        return self.verify().baseline_eligible

    @property
    def agent_exception(self) -> Optional[dict]:
        """Set when the agent raised inside the monitored block.

        A run that crashed is evidence, and often the most interesting kind.
        Discarding it would lose exactly the runs a reliability framework
        should keep, so the envelope is still produced and records that the
        run ended abnormally.
        """
        return getattr(self, "_agent_exception", None)

    def record_agent_exception(self, exc_type: str, at_step: int,
                               message: str = "") -> None:
        """Record that the monitored block raised. Callable only while open."""
        self._require_open("record an agent exception")
        self._agent_exception = {
            "type": exc_type,
            "at_step": at_step,
            "message": message[:200],
        }

    def _canonical(self) -> dict:
        """The canonical form the hash is taken over.

        Excludes the hash itself: a document cannot contain its own hash and
        still hash to the value it contains.
        """
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "configuration": self.configuration.to_dict(),
            "evaluation": self.evaluation.to_dict(),
            "fault_events": [
                e.to_dict() if hasattr(e, "to_dict") else str(e)
                for e in self._fault_events],
            "enforcement_records": [
                r.to_dict() if hasattr(r, "to_dict") else str(r)
                for r in self._enforcement_records],
            "metrics": {k: v.to_dict() for k, v in self._metrics.items()},
            "agent_exception": getattr(self, "_agent_exception", None),
            # Inside the canonical form deliberately: the existing hash then
            # covers it, so mutating a binding field after sealing fails
            # verify(). Attached outside it, the traceability chain would rest
            # on a field nothing verifies.
            "execution_binding": (self._execution_binding.to_dict()
                                  if self._execution_binding else None),
        }

    def _compute_hash(self) -> str:
        raw = json.dumps(self._canonical(), sort_keys=True,
                         separators=(",", ":"), default=str,
                         ensure_ascii=False)
        return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()

    # ── verification ────────────────────────────────────────────────

    def verify(self) -> VerificationResult:
        """Integrity and completeness, checked separately.

        A hash proves that what is present is unchanged. It says nothing about
        whether what is present suffices to know what was tested, and treating
        a passing hash as a passing verification is failure case 8.
        """
        integrity, completeness = [], []

        # ── integrity ───────────────────────────────────────────────
        if not self._sealed:
            integrity.append(
                "envelope is not sealed; its contents can still change")
        else:
            recomputed = self._compute_hash()
            if recomputed != self._envelope_hash:
                integrity.append(
                    f"hash mismatch: recorded {self._envelope_hash[:24]}..., "  # type: ignore[index]
                    f"recomputed {recomputed[:24]}... — the contents changed "
                    f"after sealing")

        for e in self._fault_events:
            if hasattr(e, "fault_present") and hasattr(e, "injection_status"):
                declared = getattr(e, "injection_status", None)
                observed = getattr(e, "observed_outcome", None)
                if declared == "applied" and observed == "normal" \
                        and getattr(e, "fault_present", False):
                    integrity.append(
                        f"{getattr(e, 'fault_event_id', '?')}: reports a "
                        f"fault while the observed outcome was normal")

        # ── completeness ────────────────────────────────────────────
        for name in REQUIRED_FOR_COMPLETENESS:
            if getattr(self, name, None) in (None, ""):
                completeness.append(f"missing required field: {name}")

        # ── metric provenance completeness ──────────────────────────
        #
        # CORRECTIVE PATCH (DW-025). This rule previously read
        # `contributing_event_ids`, which Phase 5C redefined as a LOSSY
        # fault-event-only projection. PEI and TI consume steps and episodes
        # and never fault events, so their projection is always empty - which
        # made every envelope PARTIAL and every baseline impossible.
        #
        # The canonical evidence of metric provenance is now the TYPED refs.
        # The projection remains deprecated (DW-021) and is no longer
        # completeness evidence.
        #
        # WHAT THIS DELIBERATELY DOES NOT DO
        # It does not say "any typed refs means complete". An APPLICABLE
        # metric with a value still needs provenance; MISSING is still
        # incomplete; NOT_APPLICABLE is still not a defect.
        # ── COMPATIBILITY BOUNDARY (documented invariant) ───────────
        #
        # `is_modern` uses the presence of an ExecutionBinding as a TEMPORAL
        # and STRUCTURAL discriminator for the provenance generation. It is
        # NOT a general definition of "modern", and the distinction matters
        # because the two are different concepts that happen to coincide.
        #
        # WHY THE COINCIDENCE HOLDS TODAY
        # `MonitorSession._produce_envelope()` is the ONLY place that calls
        # `bind_execution()`, and the same method call also invokes
        # `_metric_provenance()`, which always emits typed refs. Binding and
        # typed provenance are produced together, by construction, in the only
        # path that produces either.
        #
        # WHAT WOULD BREAK THE COINCIDENCE
        # A migrated legacy artifact given a binding; an external import
        # carrying a binding without typed provenance; a future path that
        # binds separately from metric production.
        #
        # WHAT HAPPENS THEN - the failure direction is SAFE
        # Such an artifact is treated as MODERN, its typed provenance is
        # missing, and it is REFUSED as incomplete. It is not silently
        # accepted. A wrong classification costs a false refusal, never a
        # false acceptance - and a false refusal is visible while a false
        # acceptance is not.
        #
        # Asserted by test_compatibility_boundary_is_not_a_guess.
        is_modern = self._execution_binding is not None

        for name, prov in self._metrics.items():
            status = getattr(prov, "provenance_status", "applicable")

            if status == "missing":
                # Evidence was expected and not found. Distinct from
                # NOT_APPLICABLE, where none was expected.
                completeness.append(
                    f"metric {name} has provenance_status=MISSING: evidence "
                    f"was expected and not found")

            elif status == "applicable" and prov.value is not None:
                has_typed = bool(getattr(prov, "numerator_refs", ())
                                 or getattr(prov, "denominator_refs", ()))
                has_legacy = bool(prov.contributing_event_ids)

                if is_modern:
                    # MODERN ARTIFACT: typed provenance is the ONLY canonical
                    # evidence of completeness.
                    #
                    # The first patch accepted `has_typed or has_legacy`
                    # everywhere, which left the deprecated projection as a
                    # PARALLEL ASSURANCE PATH: a modern artifact with zero
                    # typed refs and a populated projection reached COMPLETE
                    # and became baseline-eligible. Demonstrated, then closed
                    # here.
                    if not has_typed:
                        completeness.append(
                            f"metric {name} has a value and no typed "
                            f"provenance. The deprecated "
                            f"contributing_event_ids projection is not "
                            f"completeness evidence for an artifact produced "
                            f"under the typed provenance model (DW-021)")
                else:
                    # LEGACY ARTIFACT: produced before execution binding and
                    # typed refs existed. The projection is all it can have,
                    # and refusing it would make Phase 4 evidence unreadable.
                    #
                    # Not a loophole: a legacy envelope has no execution
                    # binding, so it is not traceable and can never become
                    # baseline-eligible regardless of completeness.
                    if not (has_typed or has_legacy):
                        completeness.append(
                            f"metric {name} has a value and no provenance of "
                            f"any kind")

            # status == "not_applicable": the metric does not consume evidence
            # in this mode. CSI in a single live session is the case. Nothing
            # is absent, so nothing is incomplete.

            missing = [eid for eid in prov.contributing_event_ids
                       if eid not in self._event_ids()]
            if missing:
                completeness.append(
                    f"metric {name} cites {len(missing)} event(s) not present "
                    f"in this envelope")

        if self._metrics and not self._fault_events:
            completeness.append(
                "metrics were recorded with no fault events; the envelope "
                "cannot show what was tested")

        return VerificationResult(
            integrity_ok=not integrity,
            completeness_ok=not completeness,
            integrity_problems=integrity,
            completeness_problems=completeness,
            sealed=self._sealed,
        )

    def all_refs_including_support(self) -> tuple:
        """Every ref in the envelope, INCLUDING supporting refs.

        `all_refs` deliberately excludes supporting refs: including them would
        let the Actual-Inputs equality pass on refs that were never inputs.
        But a supporting ref pointing at nothing is still a dangling reference
        - it implies evidence that does not exist - so the dangling check uses
        this instead.
        """
        out = []
        for prov in self._metrics.values():
            out.extend(prov.numerator_refs)
            out.extend(prov.denominator_refs)
            out.extend(prov.supporting_refs)
        return tuple(out)

    def dangling_refs(self) -> list:
        """Refs resolving to nothing present in this envelope.

        A reference resolving to nothing is worse than no reference: it
        implies evidence that does not exist, and a reader following it finds
        a gap rather than a contradiction.
        """
        # TYPE-CORRECT resolution. Fault events resolve as (fault_event, id);
        # everything else as the pair it was registered with. A ref whose id
        # exists under a DIFFERENT type is dangling: it points at something
        # that is not what it claims to point at.
        known = {(RefType.FAULT_EVENT, e) for e in self._event_ids()}
        known |= self._step_refs
        out = []
        for name, prov in self._metrics.items():
            # Supporting refs are checked too. They are not INPUTS, but a
            # supporting ref pointing at nothing still implies evidence that
            # does not exist, and a reader following it finds a gap.
            for kind, refs in (("numerator", prov.numerator_refs),
                               ("denominator", prov.denominator_refs),
                               ("supporting", prov.supporting_refs)):
                for ref in refs:
                    if (ref.ref_type, ref.ref_id) not in known:
                        exists = any(rid == ref.ref_id for _, rid in known)
                        out.append(
                            f"{name}.{kind}: {ref.ref_type}:{ref.ref_id} "
                            f"({'wrong type' if exists else 'unknown id'})")
        return out

    def resolve_chain(self) -> dict:
        """Which execution produced this evidence, and from what?

        Every link returns a value or an explicit unresolved - never a
        plausible default. A wrong attribution is worse than a missing one,
        because it will be believed.
        """
        b = self._execution_binding
        if b is None:
            # SAME SCHEMA as the bound path. Two return paths with different
            # keys make a consumer's KeyError depend on the data, which is how
            # an unbound envelope comes to be handled differently by accident.
            return {
                "traceability_resolved": False,
                "comparison_eligible": False,
                "resolved": False,
                "reason": "no execution binding",
                "unresolved_links": ["execution", "battery", "slot", "task",
                                     "configuration"],
                "dangling_refs": self.dangling_refs(),
            }
        # TWO DIFFERENT QUESTIONS, KEPT APART.
        #
        # An earlier version returned resolved=True for a PARTIAL identity,
        # conflating "every link resolves" with "this evidence may be
        # compared". They differ: a PARTIAL identity resolves to a real
        # execution and is still not comparable, because something affecting
        # the result was never declared.
        #
        #   traceability_resolved  can this evidence be traced to its source?
        #   comparison_eligible    may it anchor or enter a comparison?
        chain = {
            "traceability_resolved": True,
            "resolved": b.comparison_eligible,
            "execution_id": b.execution_id,
            "identity_status": b.identity_status,
            "identity_missing": list(b.identity_missing),
            "comparison_eligible": b.comparison_eligible,
            "battery_spec_fingerprint": b.battery_spec_fingerprint,
            "battery_instance_id": b.battery_instance_id,
            "battery_slot_id": b.battery_slot_id,
            "base_task_hash": b.base_task_hash,
            "configuration_fingerprint": b.configuration_fingerprint,
            "execution_semantics_hash": b.execution_semantics_hash,
            "metrics": {n: {"value": p.value,
                            "provenance_status": p.provenance_status,
                            "numerator_refs": [r.to_dict() for r in p.numerator_refs],
                            "denominator_refs": [r.to_dict() for r in p.denominator_refs]}
                        for n, p in self._metrics.items()},
            "dangling_refs": self.dangling_refs(),
        }
        unresolved = [k for k in ("battery_spec_fingerprint",
                                  "battery_instance_id", "battery_slot_id",
                                  "base_task_hash", "configuration_fingerprint")
                      if not chain.get(k)]
        if unresolved:
            chain["traceability_resolved"] = False
            chain["resolved"] = False
            chain["unresolved_links"] = unresolved

        if chain["traceability_resolved"] and not chain["comparison_eligible"]:
            chain["not_comparable_because"] = (
                f"identity_status={b.identity_status}"
                + (f", missing {list(b.identity_missing)}"
                   if b.identity_missing else ""))
        return chain

    def _event_ids(self) -> set:
        return {getattr(e, "fault_event_id", None) for e in self._fault_events}

    # ── the graph query ─────────────────────────────────────────────

    def why(self, metric_name: str) -> dict:
        """Why is this metric this value?

        Resolves a value to the events that produced it and the configuration
        they were produced under. A view over the envelope rather than a
        second store: two stores disagree, and the one that is not
        authoritative is the one people read.
        """
        prov = self._metrics.get(metric_name)
        if prov is None:
            return {"metric": metric_name, "answer": "not recorded"}

        events = [e for e in self._fault_events
                  if getattr(e, "fault_event_id", None)
                  in prov.contributing_event_ids]

        return {
            "metric": metric_name,
            "value": prov.value,
            "status": prov.status,
            "undefined_reason": prov.undefined_reason,
            "metric_version": prov.metric_version,
            "computed_from": {
                "numerator": prov.numerator,
                "denominator": prov.denominator,
                "event_count": len(events),
            },
            "events": [
                {"id": getattr(e, "fault_event_id", None),
                 "target": getattr(e, "target", None),
                 "intended": getattr(e, "intended_type", None),
                 "observed": getattr(e, "observed_outcome", None),
                 "fault_present": getattr(e, "fault_present", None)}
                for e in events],
            "configuration": self.configuration.fingerprint(),
            "evaluation": self.evaluation.fingerprint(),
            "envelope_hash": self._envelope_hash,
        }

    # ── serialisation ───────────────────────────────────────────────

    def to_dict(self) -> dict:
        """The JSON-serialisable form: the canonical content, the envelope hash and sealed flag, plus reconstruction data that is deliberately kept outside the hashed content."""
        d = self._canonical()
        d["envelope_hash"] = self._envelope_hash
        d["sealed"] = self._sealed

        # PHASE 5D-A: reconstruction data, OUTSIDE the canonical form.
        #
        # `_step_refs` is a verification aid, not evidence: it records which
        # refs exist so a dangling one can be detected. It is deliberately NOT
        # hashed - adding it would change every existing envelope hash - but a
        # reloaded envelope without it would report every ref as dangling,
        # which is the opposite of the truth.
        d["_reconstruction"] = {
            "step_refs": sorted(list(r) for r in self._step_refs),
            "schema": "5D-A",
        }
        d["state"] = self.state
        d["baseline_eligible"] = self.baseline_eligible
        verification = self.verify()
        d["verification"] = {
            "integrity_ok": verification.integrity_ok,
            "completeness_ok": verification.completeness_ok,
            "summary": verification.summary(),
        }
        # Stated on every envelope so a reader cannot mistake it for more than
        # it is. Phase 4 produces evidence; conclusions come later.
        d["scope"] = {
            "contains": "identity, observations, and metric provenance",
            "does_not_contain": (
                "any certification decision or signature. This envelope is "
                "input to certification, not an assertion of reliability."),
        }
        return d

    # ── Reconstruction (Phase 5D-A) ─────────────────────────────────────

    @classmethod
    def from_dict(cls, data: dict) -> "EvidenceEnvelope":
        """Rebuild a sealed envelope from its serialised form.

        WHAT THIS IS
        A serialization round-trip, so a baseline written out can be read back
        and VERIFIED. It is not durable storage: no database, no retention, no
        migration, no access control, no external anchoring. DW-010 stays OPEN
        and this is a contribution to it, not a closure.

        THE REQUIREMENT
        The reconstructed envelope must produce the SAME hash. That constrains
        the design: `_canonical()` serialises events via their `to_dict()`, so
        reconstructed events must return byte-identical dicts. They are
        therefore rebuilt as `_ReconstructedRecord` wrappers holding the
        stored dict verbatim, not as live FaultEvent objects.

        THE LIMITATION, STATED RATHER THAN DISCOVERED
        A reconstructed envelope is NOT the original object. Its events are
        records, not live `FaultEvent` instances: same data, none of the
        behaviour. It can be verified and compared; it cannot be added to.

        `reconstructed` is True on the result, so a consumer can tell.
        """
        if not isinstance(data, dict):
            raise EnvelopeError("from_dict expects a dict")

        for req in ("run_id", "configuration", "evaluation", "envelope_hash"):
            if req not in data:
                raise EnvelopeError(
                    f"cannot reconstruct: {req!r} is missing. A partial "
                    f"reconstruction that verified would be worse than a "
                    f"refusal, because it would look complete.")

        if not data.get("sealed"):
            raise EnvelopeError(
                "cannot reconstruct an unsealed envelope. Its contents could "
                "still have changed when it was written, so there is nothing "
                "for the hash to attest.")

        from .configuration import ConfigurationFingerprint, EvaluationIdentity

        cfg_d = dict(data["configuration"])
        cfg_d.pop("fingerprint", None)
        cfg_d["declared_absent"] = tuple(cfg_d.get("declared_absent", ()))
        configuration = ConfigurationFingerprint(**cfg_d)

        eval_d = dict(data["evaluation"])
        eval_d.pop("fingerprint", None)
        eval_d["seeds"] = tuple(eval_d.get("seeds", ()))
        evaluation = EvaluationIdentity(**eval_d)

        env = cls(configuration=configuration, evaluation=evaluation,
                  run_id=data["run_id"])
        env.started_at = data.get("started_at")  # type: ignore[assignment]
        env.completed_at = data.get("completed_at")

        bd = data.get("execution_binding")
        if bd:
            b = dict(bd)
            b.pop("comparison_eligible", None)
            b["identity_missing"] = tuple(b.get("identity_missing", ()))
            env._execution_binding = ExecutionBinding(**b)  # type: ignore[assignment]

        env._fault_events = tuple(  # type: ignore[assignment]
            _ReconstructedRecord(d) for d in data.get("fault_events", []))
        env._enforcement_records = tuple(  # type: ignore[assignment]
            _ReconstructedRecord(d)
            for d in data.get("enforcement_records", []))
        env._metrics = {n: _provenance_from_dict(d)
                        for n, d in data.get("metrics", {}).items()}

        recon = data.get("_reconstruction", {})
        env._step_refs = {tuple(r) for r in recon.get("step_refs", [])}

        if data.get("agent_exception"):
            env._agent_exception = data["agent_exception"]

        env._sealed = True
        env._envelope_hash = env._compute_hash()
        env.reconstructed = True  # type: ignore[attr-defined]

        stored = data["envelope_hash"]
        if env._envelope_hash != stored:
            raise EnvelopeError(
                f"reconstruction produced a different hash. stored={stored} "
                f"recomputed={env._envelope_hash}. The serialised form does "
                f"not round-trip: either it was altered between writing and "
                f"reading, or the schema changed since it was written. Either "
                f"way the envelope cannot be trusted, and returning it would "
                f"present altered evidence as intact.")

        return env

    def __repr__(self) -> str:
        state = "sealed" if self._sealed else "open"
        return (f"<EvidenceEnvelope {self.run_id} {state} "
                f"config={self.configuration.fingerprint()} "
                f"events={len(self._fault_events)} "
                f"metrics={len(self._metrics)}>")


class _ReconstructedRecord:
    """A serialised record rebuilt from its dict.

    Holds the stored dict verbatim and returns it from `to_dict()`, so
    `_canonical()` produces byte-identical output and the hash round-trips.

    Deliberately NOT a FaultEvent. It carries the data and none of the
    behaviour, and pretending otherwise would let a consumer call a method
    that silently is not there.
    """

    __slots__ = ("_data",)

    def __init__(self, data: dict):
        object.__setattr__(self, "_data", dict(data))

    def to_dict(self) -> dict:
        return dict(self._data)

    def __getattr__(self, name):
        data = object.__getattribute__(self, "_data")
        if name in data:
            return data[name]
        raise AttributeError(
            f"{name!r} is not present on a reconstructed record. This is a "
            f"serialised record, not a live FaultEvent.")

    def __repr__(self):
        d = object.__getattribute__(self, "_data")
        return f"<_ReconstructedRecord {d.get('fault_event_id', '?')}>"


def _provenance_from_dict(d: dict) -> "MetricProvenance":
    """Rebuild MetricProvenance, including its typed refs."""
    def refs(key):
        return tuple(MetricRef(r["ref_type"], r["ref_id"])
                     for r in d.get(key, []))

    return MetricProvenance(
        metric_name=d["metric_name"], value=d.get("value"),
        metric_version=d.get("metric_version", "unknown"),
        contributing_event_ids=tuple(d.get("contributing_event_ids", ())),
        numerator=d.get("numerator"), denominator=d.get("denominator"),
        numerator_refs=refs("numerator_refs"),
        denominator_refs=refs("denominator_refs"),
        supporting_refs=refs("supporting_refs"),
        provenance_status=d.get("provenance_status", "applicable"),
        status=d.get("status", "valid"),
        undefined_reason=d.get("undefined_reason"),
    )
