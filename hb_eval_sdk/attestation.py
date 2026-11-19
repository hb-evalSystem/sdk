"""
hb_eval_sdk/attestation.py — Phase 7
=====================================

A BOUNDED ATTESTATION. NOT A CERTIFICATION.

    Evidence -> Baseline -> Comparability -> Diff -> Decision -> ATTESTATION

WHAT AN ATTESTATION SAYS

    A specific identity was evaluated against specific evidence and baselines,
    under a specific versioned policy, and produced a PASS ReliabilityDecision
    within an explicitly declared scope.

WHAT IT DOES NOT SAY

    certified · reliable · proven · safe · production-approved · guaranteed ·
    universally verified

    Those need an issuing authority, a signature over a frozen schema, an
    external anchor and durable revocation. The SDK has none of the four:
    DW-008's unlock is unmet, DW-009 depends on DW-010, and DW-010 is Phase 9.

    An artefact claiming to be a certification while lacking all of them would
    assert exactly what it cannot support. So the word does not appear here -
    not in a field, not in a message, not in the serialised output.

WHAT PHASE 7 IS FOR

    It creates the authoritative CONTEXT against which Phase 8 can later
    detect invalidating change.

    It does NOT trigger RECERTIFICATION_REQUIRED. That state stays unreachable
    until Phase 8 exists, and conflating "makes possible later" with "makes
    reachable now" is how Phase 8 would leak into Phase 7. The identifier is
    deliberately absent from this module.

PASS ONLY

    FAIL and INCONCLUSIVE produce no attestation, and INCONCLUSIVE is the
    important refusal: attesting it would issue a statement about evidence
    that could not support a decision - the failure Phase 6 was built to end.

SCOPE IS A FIELD, NOT A FOOTNOTE

    A ReliabilityDecision covers one battery slot, because a
    ReliabilityBaseline covers one envelope. The attestation states that in
    its own content, so a reader never has to know DW-024 exists to understand
    what was not covered.

NO FALSE ISSUER

    `produced_by` names the system that generated the statement. There is no
    issuer, no authority, no signer, no certifier - a system-generated
    statement is honest, and a credential implying an authority that does not
    exist is not.

THE GATEWAY FLAG IS NOT AN INPUT

    `EvaluationResult.certified` is a transport field mirroring a remote
    response. It is never read here. Three distinct things stay distinct:

        Gateway certified flag   what a remote service reported
        HB-Eval Attestation      what this system states from its own evidence
        Certification credential does not exist
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

__all__ = [
    "attest",
    "ReliabilityAttestation",
    "AttestationError",
    "ATTESTATION_LIMITATIONS",
]


class AttestationError(Exception):
    """Raised when an attestation cannot be issued honestly."""


ATTESTATION_LIMITATIONS = (
    "tamper-evident within the producing process only; not independently "
    "verifiable",
    "not cryptographically signed (DW-008: the evidence schema is frozen "
    "since Phase 9A, but no issuing authority or signature exists yet)",
    "not externally anchored (DW-009, which depends on DW-010)",
    "not persisted and therefore not revocable (DW-010)",
    "no issuing authority: this is a system-generated statement, not a "
    "credential",
    "scope is one battery slot; it says nothing about the agent as a whole "
    "(DW-024)",
    "rests on declared execution conditions, not observed ones (DW-005)",
)
"""Carried IN the artefact, not only in documentation.

A limitation a reader has to go and look up is a limitation most readers will
not find. These travel with the statement so the claim and its boundaries
arrive together.
"""


@dataclass(frozen=True)
class ReliabilityAttestation:
    """A sealed, content-addressed statement. Frozen after construction.

    Identity is DERIVED, following 5D-B: two attestations over identical
    content are the same attestation, and an assigned id would let one
    statement be issued twice under different names.

    Registry metadata is deliberately absent from the canonical content, as
    `BaselineRegistryEntry` established - `produced_at` and `produced_by`
    describe the act of producing, not what is being stated.
    """

    # ── subject: what was evaluated ─────────────────────────────────
    configuration_fingerprint: str
    evaluation_fingerprint: str

    # ── evidence: on what basis ─────────────────────────────────────
    baseline_id: str
    baseline_hash: str
    reference_baseline_id: str
    reference_baseline_hash: str
    envelope_hash: str

    # ── decision: by what judgement ─────────────────────────────────
    decision_state: str
    policy_version: str
    decided_metrics: tuple
    comparability_state: str

    # ── scope: over what ────────────────────────────────────────────
    battery_spec_fingerprint: str
    battery_instance_id: str
    battery_slot_id: str
    scope: str = "single_battery_slot"

    # ── production metadata: outside the canonical content ──────────
    produced_at: float = field(default_factory=time.time)
    produced_by: str = "hb-eval-sdk"

    limitations: tuple = ATTESTATION_LIMITATIONS

    attestation_id: str = ""
    attestation_hash: str = ""

    # ── construction ────────────────────────────────────────────────

    @classmethod
    def from_decision(cls, decision, subject_baseline,
                      produced_by: str = "hb-eval-sdk"
                      ) -> "ReliabilityAttestation":
        """Issue an attestation, or refuse with a reason.

        TWO INPUTS, because one is not enough. A ReliabilityDecision carries
        baseline ids and hashes but not `configuration_fingerprint`,
        `evaluation_fingerprint` or `battery_slot_id` - those live on the
        baseline. The subject baseline is therefore required, and its id must
        match the decision's candidate side.

        That match is checked rather than assumed: an attestation naming one
        subject while resting on another's decision would be worse than no
        attestation at all.
        """
        from .reliability_decision import DecisionState

        if decision.state != DecisionState.PASS:
            raise AttestationError(
                f"the decision state is {decision.state}, not PASS. "
                + _refusal_reason(decision.state))

        if subject_baseline.baseline_id != decision.baseline_b_id:
            raise AttestationError(
                f"the subject baseline {subject_baseline.baseline_id} is not "
                f"the one the decision was made about "
                f"({decision.baseline_b_id}). An attestation naming one "
                f"subject while resting on another's decision would be worse "
                f"than none")

        verification = subject_baseline.verify()
        if not verification["valid"]:
            raise AttestationError(
                f"the subject baseline does not verify: "
                f"{verification['problems'][:2]}")

        if not decision.decided_metrics:
            raise AttestationError(
                "the decision decided no metric: a PASS with nothing decided "
                "asserts nothing, and an attestation over it would assert "
                "nothing either")

        if not decision.policy_version:
            raise AttestationError(
                "the decision carries no policy version: an attestation must "
                "name the policy it was issued under")

        att = cls(
            configuration_fingerprint=subject_baseline.configuration_fingerprint,
            evaluation_fingerprint=subject_baseline.evaluation_fingerprint,
            baseline_id=subject_baseline.baseline_id,
            baseline_hash=subject_baseline.baseline_hash,
            reference_baseline_id=decision.baseline_a_id,
            reference_baseline_hash=decision.baseline_a_hash,
            envelope_hash=subject_baseline.envelope_hash,
            decision_state=decision.state,
            policy_version=decision.policy_version,
            decided_metrics=tuple(decision.decided_metrics),
            comparability_state=decision.comparability_state,
            battery_spec_fingerprint=subject_baseline.battery_spec_fingerprint,
            battery_instance_id=subject_baseline.battery_instance_id,
            battery_slot_id=subject_baseline.battery_slot_id,
            produced_by=produced_by,
        )
        object.__setattr__(att, "attestation_id", att._derive_id())
        object.__setattr__(att, "attestation_hash", att._compute_hash())
        return att

    # ── identity and integrity ──────────────────────────────────────

    def _identity_content(self) -> dict:
        """What this is an attestation OF.

        `produced_at` and `produced_by` are absent deliberately: two
        attestations of the same fact, produced a minute apart, are the same
        attestation.
        """
        return {
            "configuration_fingerprint": self.configuration_fingerprint,
            "evaluation_fingerprint": self.evaluation_fingerprint,
            "baseline_id": self.baseline_id,
            "reference_baseline_id": self.reference_baseline_id,
            "decision_state": self.decision_state,
            "policy_version": self.policy_version,
            "battery_slot_id": self.battery_slot_id,
        }

    def _derive_id(self) -> str:
        blob = json.dumps(self._identity_content(), sort_keys=True,
                          separators=(",", ":"))
        return "ATT-" + hashlib.sha256(blob.encode()).hexdigest()[:16]

    def _canonical(self) -> dict:
        return {
            **self._identity_content(),
            "baseline_hash": self.baseline_hash,
            "reference_baseline_hash": self.reference_baseline_hash,
            "envelope_hash": self.envelope_hash,
            "decided_metrics": list(self.decided_metrics),
            "comparability_state": self.comparability_state,
            "battery_spec_fingerprint": self.battery_spec_fingerprint,
            "battery_instance_id": self.battery_instance_id,
            "scope": self.scope,
        }

    def _compute_hash(self) -> str:
        blob = json.dumps(self._canonical(), sort_keys=True,
                          separators=(",", ":"), default=str)
        return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()

    def verify(self, subject_baseline=None) -> dict:
        """Recompute identity and hash; optionally re-check the subject.

        Read-only. Verifying must not change the attestation or the baseline.

        The limit is inherited from the envelope: tamper-EVIDENT within this
        process, not independently verifiable. DW-008 and DW-009 stay open.
        """
        result: dict[str, Any] = {
            "id_ok": self.attestation_id == self._derive_id(),
            "hash_ok": self.attestation_hash == self._compute_hash(),
            "subject_checked": False,
            "subject_ok": None,
            "problems": [],
        }
        if not result["id_ok"]:
            result["problems"].append(
                "attestation_id does not match its content: it was assigned "
                "or altered rather than derived")
        if not result["hash_ok"]:
            result["problems"].append("attestation content was altered")

        if subject_baseline is not None:
            result["subject_checked"] = True
            if subject_baseline.baseline_hash != self.baseline_hash:
                result["subject_ok"] = False
                result["problems"].append(
                    "the supplied baseline is not the attested subject")
            else:
                result["subject_ok"] = subject_baseline.verify()["valid"]
                if not result["subject_ok"]:
                    result["problems"].append(
                        "the attested subject no longer verifies")

        result["valid"] = (result["id_ok"] and result["hash_ok"]
                           and result["subject_ok"] is not False)
        return result

    # ── what it states, in words ────────────────────────────────────

    def statement(self) -> str:
        """The claim in one sentence, bounded exactly as the artefact is.

        Deliberately says "reached a PASS decision", not "is reliable" or "is
        certified". The difference is the whole point of Phase 7.
        """
        return (
            f"Configuration {self.configuration_fingerprint} was evaluated "
            f"under evaluation identity {self.evaluation_fingerprint} on "
            f"battery slot {self.battery_slot_id}, and reached a PASS "
            f"reliability decision under policy {self.policy_version} on "
            f"evidence {self.baseline_hash[:24]}. This statement covers one "
            f"battery slot and nothing beyond it.")

    def to_dict(self) -> dict:
        """The JSON-serialisable form: the attested content plus its id and hash, when and by what it was produced, its limitations, and the plain-language statement."""
        d = self._canonical()
        d["attestation_id"] = self.attestation_id
        d["attestation_hash"] = self.attestation_hash
        d["produced_at"] = self.produced_at
        d["produced_by"] = self.produced_by
        d["limitations"] = list(self.limitations)
        d["statement"] = self.statement()
        return d

    # ── Reconstruction (Phase 8, DW-029) ────────────────────────────

    @classmethod
    def from_dict(cls, data: dict) -> "ReliabilityAttestation":
        """Rebuild an attestation from its serialised form and verify it.

        WHY PHASE 8 NEEDS THIS

        Change detection compares a CURRENT context against an ATTESTED one.
        Without reconstruction an attestation dies with the process that
        produced it, so there is nothing to compare against and the phase
        cannot answer the question it exists for.

        WHAT THIS IS, AND IS NOT

            to_dict() -> persisted representation -> from_dict() -> verify()

        A verified round-trip. NOT durable storage: no database, retention,
        object storage, backup, revocation state or external anchor.

        DW-029 closes on this. DW-010 does NOT - the same distinction 5D-A
        drew for the envelope, and the same one that had to be corrected once
        when a round-trip was mistaken for persistence.

        The stored hash is never trusted on its word: the content is
        recomputed and compared, so an attestation altered between writing and
        reading is refused rather than returned looking intact.
        """
        if not isinstance(data, dict):
            raise AttestationError("from_dict expects a dict")

        required = ("attestation_id", "attestation_hash",
                    "configuration_fingerprint", "evaluation_fingerprint",
                    "baseline_id", "decision_state", "policy_version",
                    "battery_slot_id")
        missing = [k for k in required if k not in data]
        if missing:
            raise AttestationError(
                f"cannot reconstruct: {missing} absent. A partial "
                f"reconstruction that verified would be worse than a refusal, "
                f"because it would look complete")

        att = cls(
            configuration_fingerprint=data["configuration_fingerprint"],
            evaluation_fingerprint=data["evaluation_fingerprint"],
            baseline_id=data["baseline_id"],
            baseline_hash=data["baseline_hash"],
            reference_baseline_id=data["reference_baseline_id"],
            reference_baseline_hash=data["reference_baseline_hash"],
            envelope_hash=data["envelope_hash"],
            decision_state=data["decision_state"],
            policy_version=data["policy_version"],
            decided_metrics=tuple(data.get("decided_metrics", ())),
            comparability_state=data["comparability_state"],
            battery_spec_fingerprint=data["battery_spec_fingerprint"],
            battery_instance_id=data["battery_instance_id"],
            battery_slot_id=data["battery_slot_id"],
            scope=data.get("scope", "single_battery_slot"),
            produced_at=data.get("produced_at", 0.0),
            produced_by=data.get("produced_by", "unknown"),
        )
        object.__setattr__(att, "attestation_id", att._derive_id())
        object.__setattr__(att, "attestation_hash", att._compute_hash())

        if att.attestation_id != data["attestation_id"]:
            raise AttestationError(
                f"attestation_id does not match the content: stored "
                f"{data['attestation_id']}, derived {att.attestation_id}. "
                f"Either the content was altered or the id was forged")
        if att.attestation_hash != data["attestation_hash"]:
            raise AttestationError(
                f"the attestation does not round-trip: stored "
                f"{data['attestation_hash'][:24]}, recomputed "
                f"{att.attestation_hash[:24]}. Returning it would present "
                f"altered evidence as intact")

        return att

    def __repr__(self) -> str:
        return (f"<ReliabilityAttestation {self.attestation_id} "
                f"slot={self.battery_slot_id} scope={self.scope}>")


def _refusal_reason(state: str) -> str:
    from .reliability_decision import DecisionState

    if state == DecisionState.INCONCLUSIVE:
        return ("An INCONCLUSIVE decision means the evidence could not "
                "support a decision at all; attesting it would issue a "
                "statement about evidence that says nothing.")
    if state == DecisionState.FAIL:
        return ("A FAIL is already fully described by the decision that "
                "produced it; no negative attestation is issued.")
    return ("Only a PASS decision is eligible for attestation.")


def attest(decision, subject_baseline, produced_by: str = "hb-eval-sdk"):
    """Issue a bounded attestation from a PASS decision.

    Consumes a ReliabilityDecision; never re-derives one. Re-deriving would
    create a second judgement that eventually disagrees with the first.
    """
    return ReliabilityAttestation.from_decision(
        decision, subject_baseline, produced_by=produced_by)
