"""
hb_eval_sdk/context_assessment.py — Phase 8
============================================

THE SENTENCE THIS MODULE IS BUILT AROUND

    Phase 8 does not determine whether the agent is reliable. It determines
    whether the DECLARED, COMPARABLE context under which a previous PASS
    attestation was issued remains applicable under the defined context
    policy.

Every overclaim this module refuses is a way of losing that distinction.

WHY THERE IS NO `STILL_VALID`

    An earlier draft proposed it. It cannot be said, for two measured
    reasons:

        DW-005   the current context is DECLARED by the caller, not observed
                 at runtime
        DW-016   sampling parameters sit outside ConfigurationFingerprint, so
                 a temperature change does not move it

    Finding no difference therefore establishes only that no change was
    detected in the context that was supplied and compared. That is not the
    same claim as the attestation still being valid, and the difference is not
    pedantry: one is a statement about what was checked, the other about the
    world.

    CONTEXT_UNCHANGED            what this module can honestly say
    RECERTIFICATION_REQUIRED     a declared invalidating field differs
    UNDETERMINED                 the comparison could not be made

    UNDETERMINED never collapses into the other two. With the evidence
    absent, one answer hides a gap and the other invents a finding.

NOT EVERY DIFFERENCE INVALIDATES

    The question is not "did something change" - that is a hash comparison.
    It is "does the change make the prior decision inapplicable".

    INVALIDATING
        configuration_fingerprint   the subject itself changed
        evaluation_fingerprint      the measurement changed
        battery_slot_id             a different scenario entirely
        battery_spec_fingerprint    a different specification, per 5D-C
        policy_version              the standard changed

    NOT INVALIDATING
        envelope_hash · baseline_hash · reference_baseline_hash
        battery_instance_id

    NEW EVIDENCE DOES NOT MAKE OLD EVIDENCE FALSE. The attestation says the
    prior decision was reached ON THIS EVIDENCE, and that stays true when
    newer evidence appears. Treating fresh evidence as invalidating would let
    this module rewrite history, and would demand recertification after every
    re-run - recertification firing on noise.

    A freshness rule ("re-evaluate every N days") is a TEMPORAL VALIDITY
    POLICY, not an equality comparison. It is not invented here: expiry needs
    durable state, and DW-010 is open.

WHAT THIS MODULE DOES NOT DO

    re-run an evaluation             Phase 6
    produce a reliability decision   Phase 6
    issue or re-issue an attestation Phase 7
    persist anything                 DW-010
    expire or revoke                 needs durable state
    fix DW-016                       a deferred item is not solved sideways
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

__all__ = [
    "assess_context",
    "ContextAssessment",
    "ContextState",
    "FieldDifference",
    "INVALIDATING_FIELDS",
    "NON_INVALIDATING_FIELDS",
    "CONTEXT_LIMITATIONS",
]


class ContextState:
    """The result of comparing the context an attestation was made in with the context now: CONTEXT_UNCHANGED, RECERTIFICATION_REQUIRED, or UNDETERMINED when it cannot be told."""
    CONTEXT_UNCHANGED = "CONTEXT_UNCHANGED"
    """No change was detected in the context that was supplied and compared.

    NOT a statement that the agent did not change, and NOT a statement that
    the attestation is still valid. See DW-005 and DW-016.
    """
    RECERTIFICATION_REQUIRED = "RECERTIFICATION_REQUIRED"
    UNDETERMINED = "UNDETERMINED"
    ALL = (CONTEXT_UNCHANGED, RECERTIFICATION_REQUIRED, UNDETERMINED)


INVALIDATING_FIELDS = (
    "configuration_fingerprint",
    "evaluation_fingerprint",
    "battery_slot_id",
    "battery_spec_fingerprint",
    "policy_version",
)

NON_INVALIDATING_FIELDS = (
    "envelope_hash",
    "baseline_hash",
    "reference_baseline_hash",
    "battery_instance_id",
)

CONTEXT_LIMITATIONS = (
    "the current context is DECLARED by the caller, not observed at runtime "
    "(DW-005): two contexts may declare identically and have differed",
    "CONTEXT_UNCHANGED means unchanged under the REPRESENTED configuration "
    "identity, not proof that every provider or runtime parameter remained "
    "unchanged (DW-016: sampling parameters are outside "
    "ConfigurationFingerprint)",
    "the assessment covers one battery slot, matching the attestation's scope "
    "(DW-024)",
    "no expiry and no revocation: both need durable state (DW-010)",
    "environment enters only through EvaluationIdentity; there is no "
    "environment snapshot (DW-014)",
)
"""Carried IN the result, following the Phase 7 precedent.

A limitation a reader has to go and look up is one most readers will not find.
"""


@dataclass(frozen=True)
class FieldDifference:
    """One field that differs between the attested context and the current one: its name, both values, whether the difference invalidates the attestation, and a note."""
    field_name: str
    attested: Optional[str]
    current: Optional[str]
    invalidating: bool
    note: str = ""

    def to_dict(self) -> dict:
        """The JSON-serialisable form: `field_name`, `attested`, `current`, `invalidating` and `note`."""
        return {"field_name": self.field_name, "attested": self.attested,
                "current": self.current, "invalidating": self.invalidating,
                "note": self.note}


@dataclass(frozen=True)
class ContextAssessment:
    """The verdict, with every difference visible.

    `non_invalidating` is REPORTED, not hidden. A reader should see that
    evidence changed even where it does not invalidate, because silence about
    a real difference is its own kind of misleading.
    """

    state: str
    attestation_id: str
    attestation_hash: str
    invalidating: tuple = ()
    non_invalidating: tuple = ()
    undetermined: tuple = ()
    reasons: tuple = ()
    limitations: tuple = CONTEXT_LIMITATIONS

    @property
    def requires_recertification(self) -> bool:
        """True when the state is RECERTIFICATION_REQUIRED."""
        return self.state == ContextState.RECERTIFICATION_REQUIRED

    def to_dict(self) -> dict:
        """The JSON-serialisable form: the state, the attestation it concerns, and the invalidating, non-invalidating and undetermined differences."""
        return {
            "state": self.state,
            "attestation_id": self.attestation_id,
            "attestation_hash": self.attestation_hash,
            "invalidating": [d.to_dict() for d in self.invalidating],
            "non_invalidating": [d.to_dict() for d in self.non_invalidating],
            "undetermined": list(self.undetermined),
            "reasons": list(self.reasons),
            "limitations": list(self.limitations),
        }

    def __repr__(self) -> str:
        return (f"<ContextAssessment {self.state} "
                f"{len(self.invalidating)} invalidating, "
                f"{len(self.non_invalidating)} other differences>")


def assess_context(attestation, current_context: dict) -> ContextAssessment:
    """Compare a declared current context against an attested one.

    `current_context` is a dict the CALLER declares. This module does not
    observe runtime truth and does not pretend to (DW-005).

    Any required field absent yields UNDETERMINED for that field, and an
    UNDETERMINED verdict overall. Never a default, and never an assumption
    that absence means unchanged: both would be claims without evidence.
    """
    if not isinstance(current_context, dict):
        raise TypeError("current_context must be a dict declared by the caller")

    invalidating: list = []
    non_invalidating: list = []
    undetermined: list = []
    reasons: list = []

    def _compare(field_name, is_invalidating):
        attested = getattr(attestation, field_name, None)
        if field_name not in current_context:
            undetermined.append(
                f"{field_name}: not declared in the current context, so "
                f"neither a match nor a difference can be established")
            return
        current = current_context[field_name]
        if current == attested:
            return
        note = ("this field is declared invalidating: the prior decision was "
                "reached under a different one"
                if is_invalidating else
                "a difference that does not invalidate: new evidence does not "
                "make the evidence the decision rested on false")
        diff = FieldDifference(field_name, attested, current,
                               is_invalidating, note)
        (invalidating if is_invalidating else non_invalidating).append(diff)

    for name in INVALIDATING_FIELDS:
        _compare(name, True)
    for name in NON_INVALIDATING_FIELDS:
        _compare(name, False)

    # ── STATE PRIORITY ──────────────────────────────────────────────
    #
    # 1  any invalidating field differs   -> RECERTIFICATION_REQUIRED
    # 2  otherwise, anything undetermined -> UNDETERMINED
    # 3  otherwise                        -> CONTEXT_UNCHANGED
    #
    # A KNOWN INVALIDATING DIFFERENCE OUTRANKS MISSING CONTEXT, for the same
    # reason a known blocker outranked unknown context in 5D-C: if the
    # configuration demonstrably changed, the prior decision does not apply
    # regardless of what else was not declared, and answering UNDETERMINED
    # would send a caller looking for context that cannot change the answer.
    #
    # The undetermined fields are still reported, so nothing is hidden.
    if invalidating:
        state = ContextState.RECERTIFICATION_REQUIRED
        reasons.append(
            f"{len(invalidating)} field(s) declared invalidating differ from "
            f"the attested context")
    elif undetermined:
        state = ContextState.UNDETERMINED
        reasons.append(
            "the current context does not declare every field the comparison "
            "needs; asserting either a match or a change would be a claim "
            "without evidence")
    else:
        state = ContextState.CONTEXT_UNCHANGED
        reasons.append(
            "no change was detected in the context that was supplied and "
            "compared. This is not a statement that the agent did not change, "
            "nor that the attestation remains valid")

    if non_invalidating:
        reasons.append(
            f"{len(non_invalidating)} field(s) differ without invalidating: "
            f"reported so the difference is visible, not hidden")

    return ContextAssessment(
        state=state,
        attestation_id=attestation.attestation_id,
        attestation_hash=attestation.attestation_hash,
        invalidating=tuple(invalidating),
        non_invalidating=tuple(non_invalidating),
        undetermined=tuple(undetermined),
        reasons=tuple(reasons),
    )
