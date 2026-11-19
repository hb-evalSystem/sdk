"""
hb_eval_sdk/baseline.py — Phase 5D-B
=====================================

THE RELIABILITY BASELINE

    An immutable, identity-bearing reference representation of an evaluated
    reliability state under a declared configuration, evaluation protocol,
    evidence set and operational scope.

Not `FRR = 0.91`. A number without the conditions that produced it cannot be a
reference for anything.

What makes it a BASELINE rather than a record is a role: it is the thing a
later evaluation is measured against. That role imposes requirements a record
does not have - immutability, derived identity, and independent verifiability
against the integrity mechanisms available in this system.

THREE DISTINCT IDENTITIES

    SUBJECT IDENTITY      what was evaluated
        The evaluated execution/evaluation scope, carried by the existing
        mechanisms: ConfigurationFingerprint, EvaluationIdentity, and the
        ExecutionBinding chain. This module creates none of them.

    EVIDENCE IDENTITY     which artifact supports the claim
        EvidenceEnvelope -> envelope_hash

    BASELINE IDENTITY     which immutable assertion this is
        A specific reference assertion ABOUT a subject, under a declared
        configuration and evaluation context, SUPPORTED BY a specific
        evidence artifact.

    Therefore:
        Subject   != Evidence
        Baseline  != Subject
        Baseline  REFERENCES a subject
        Baseline  IS SUPPORTED BY evidence

WHY envelope_hash BELONGS IN baseline_id

    It looks like a collapse of Subject into Evidence. It is not, and the
    reason is what a baseline asserts.

    A baseline is not "the reliability of this subject". It is "THIS
    reliability reference state, for this subject, supported by THIS
    evidence". Two runs of the same execution identity produce different
    evidence - models are non-deterministic - and they are two different
    reference states, not one state observed twice.

    Excluding envelope_hash would make them collide: two different measured
    outcomes sharing one baseline_id, with no way to say which a later
    comparison was made against.

    Asserted by test_same_subject_different_evidence_is_a_different_baseline.

IDENTITY versus INTEGRITY

    baseline_id     "which baseline assertion is this?"
                    derived from the four identity-bearing fields

    baseline_hash   "has the canonical content been altered?"
                    integrity over the COMPLETE canonical representation,
                    identity-bearing and non-identity-bearing alike

    The two are deliberately different scopes. A change to canonical
    non-identity content leaves baseline_id unchanged and moves
    baseline_hash - which is exactly how tampering with a metric value is
    detected while the assertion it belongs to stays identifiable.

    Asserted by test_identity_unchanged_integrity_changed.

IMMUTABLE SNAPSHOT SEMANTICS

    A ReliabilityBaseline is an immutable SNAPSHOT, not a mutable container
    whose metrics can be updated.

        same conceptual subject
        + same configuration context
        + different evaluated reliability outcome
        = A DIFFERENT baseline snapshot

    The earlier snapshot remains valid as historical evidence and is not
    retroactively modified. A comparison already made against it stays
    reproducible, which it would not if snapshots could be edited in place.

    Preparation for 5D-C and 5D-D only: the semantic boundary is established
    here, and comparability itself is NOT implemented.

SCOPE - ONE ENVELOPE, ONE SLOT
    ExecutionBinding.battery_slot_id is singular, an envelope carries one
    binding (INV-5C-1), and nothing aggregates envelopes. A battery of 18
    slots produces 18 baselines. More objects, and honest: each carries its
    own evidence, hash and verifiability. The aggregate is DW-024.

NOT IN THIS MODULE
    comparability between baselines    5D-C
    deltas, diffs, associations        5D-D
    storage, registry service          DW-010
    certification, expiry, revocation  Phase 7
    any new identity system            Phases 4, 5B, 5C own that
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

__all__ = [
    "ReliabilityBaseline",
    "BaselineEligibility",
    "BaselineRegistryEntry",
    "BaselineError",
    "is_baseline_eligible",
]


class BaselineError(Exception):
    """Raised when a baseline cannot be constructed or verified honestly."""


# ═══════════════════════════════════════════════════════════════════════
#  ELIGIBILITY - a contract, not scattered checks
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class BaselineEligibility:
    """Whether an envelope is fit to become a baseline, and why not.

    A CONTRACT rather than `if` statements inside a constructor. 5D-C has to
    depend on this decision, and a decision buried in a constructor cannot be
    depended on - only re-implemented, and the second implementation drifts.

    ALL conditions are evaluated; nothing short-circuits. A caller who fixes
    one problem and rediscovers the next on the following attempt learns the
    state of their evidence one failure at a time.

    INTRINSIC ONLY. This asks whether an envelope is fit to be a reference. It
    says nothing about whether two baselines may be compared - that is 5D-C,
    and letting it leak in here would put pairwise logic inside a
    single-object question.
    """

    eligible: bool
    refusals: tuple = ()

    def __bool__(self) -> bool:
        return self.eligible

    def to_dict(self) -> dict:
        """`{"eligible": bool, "refusals": [...]}`: whether the evidence may become a baseline, and each reason it may not."""
        return {"eligible": self.eligible, "refusals": list(self.refusals)}


def is_baseline_eligible(envelope) -> BaselineEligibility:
    """Evaluate every intrinsic validity condition. Nothing short-circuits."""
    refusals = []

    if not getattr(envelope, "sealed", False):
        refusals.append(
            "envelope is not sealed: its contents could still change, so "
            "there is nothing for a reference to be a reference to")

    try:
        v = envelope.verify()
    except Exception as exc:                       # pragma: no cover
        return BaselineEligibility(False, tuple(
            refusals + [f"verification raised: {type(exc).__name__}: {exc}"]))

    if not v.integrity_ok:
        refusals.append(
            f"envelope integrity failed: {list(v.integrity_problems)[:3]}")
    if not v.completeness_ok:
        refusals.append(
            f"envelope completeness failed: "
            f"{list(v.completeness_problems)[:3]}")

    state = getattr(envelope, "state", None)
    if state != "COMPLETE":
        refusals.append(
            f"envelope state is {state}, not COMPLETE. A baseline anchored to "
            f"partial evidence produces differences that may be artefacts of "
            f"what was never captured")

    binding = getattr(envelope, "execution_binding", None)
    if binding is None:
        refusals.append(
            "no execution binding: this evidence cannot be attributed to an "
            "execution, so it cannot be a reference for one")
    else:
        if binding.identity_status != "COMPLETE":
            missing = list(getattr(binding, "identity_missing", ()))
            refusals.append(
                f"identity_status is {binding.identity_status}"
                + (f", missing {missing}" if missing else "")
                + "; something affecting the result was never declared")
        for name in ("configuration_fingerprint", "execution_semantics_hash",
                     "battery_spec_fingerprint", "battery_instance_id",
                     "battery_slot_id", "execution_id"):
            if not getattr(binding, name, None):
                refusals.append(f"binding.{name} is empty")

    try:
        chain = envelope.resolve_chain()
        if not chain.get("traceability_resolved"):
            refusals.append(
                f"traceability unresolved: "
                f"{chain.get('unresolved_links', chain.get('reason'))}")
    except Exception as exc:                       # pragma: no cover
        refusals.append(f"chain resolution raised: {exc}")

    try:
        dangling = envelope.dangling_refs()
        if dangling:
            refusals.append(
                f"{len(dangling)} dangling reference(s): {dangling[:2]}; a "
                f"ref resolving to nothing implies evidence that does not "
                f"exist")
    except Exception as exc:                       # pragma: no cover
        refusals.append(f"dangling check raised: {exc}")

    # NOT_APPLICABLE is fine; MISSING is not. CSI is NOT_APPLICABLE in live
    # mode - it consumes no evidence, so none is absent. MISSING means
    # evidence was expected and not found, and a later comparison could not
    # tell whether a difference was real or was that gap.
    metrics = getattr(envelope, "_metrics", {})
    if not metrics:
        refusals.append("envelope carries no metrics")
    for name, prov in metrics.items():
        status = getattr(prov, "provenance_status", None)
        if status == "missing":
            refusals.append(
                f"metric {name!r} has provenance_status=MISSING: evidence was "
                f"expected and not found")
        elif status not in ("applicable", "not_applicable"):
            refusals.append(
                f"metric {name!r} has unknown provenance_status {status!r}")

    for attr in ("configuration", "evaluation"):
        obj = getattr(envelope, attr, None)
        if obj is None or not getattr(obj, "fingerprint", None):
            refusals.append(f"envelope.{attr} has no fingerprint")

    return BaselineEligibility(not refusals, tuple(refusals))


# ═══════════════════════════════════════════════════════════════════════
#  THE BASELINE
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ReliabilityBaseline:
    """An immutable reference point for a later evaluation.

    FULLY IMMUTABLE. Nothing is writable after construction - not even
    registry metadata, which lives on BaselineRegistryEntry instead. A
    half-immutable object is one nobody can reason about: sealed for some
    fields and writable for others, with the distinction visible only in the
    hash function.

    IDENTITY IS DERIVED, NEVER ASSIGNED. Two baselines over identical content
    ARE the same baseline. An assigned id would let the same evidence be
    registered twice under different names, and supersession would then be
    ambiguous about which is which.

    Construct via `from_envelope()`. The constructor is not the gate; the
    eligibility contract is.
    """

    configuration_fingerprint: str
    evaluation_fingerprint: str
    execution_id: str
    envelope_hash: str

    battery_spec_fingerprint: str
    battery_instance_id: str
    battery_slot_id: str
    base_task_hash: str
    execution_semantics_hash: str

    metrics: tuple = ()
    """((name, value, metric_version, provenance_status), ...) - sorted."""

    baseline_id: str = ""
    baseline_hash: str = ""

    # ── construction ────────────────────────────────────────────────

    @classmethod
    def from_envelope(cls, envelope) -> "ReliabilityBaseline":
        """Build from an eligible envelope, or refuse listing EVERY reason."""
        eligibility = is_baseline_eligible(envelope)
        if not eligibility.eligible:
            raise BaselineError(
                "envelope is not eligible to be a baseline:\n  - "
                + "\n  - ".join(eligibility.refusals))

        b = envelope.execution_binding

        metrics = tuple(sorted(
            (name,
             getattr(p, "value", None),
             getattr(p, "metric_version", "unknown"),
             getattr(p, "provenance_status", "applicable"))
            for name, p in envelope._metrics.items()))

        base = cls(
            # `evaluation_fingerprint` is a FIELD NAME whose value comes from
            # EvaluationIdentity.fingerprint(). No new identity is created and
            # no EvaluationIdentity is constructed here.
            configuration_fingerprint=envelope.configuration.fingerprint(),
            evaluation_fingerprint=envelope.evaluation.fingerprint(),
            execution_id=b.execution_id,
            envelope_hash=envelope.envelope_hash,
            battery_spec_fingerprint=b.battery_spec_fingerprint,
            battery_instance_id=b.battery_instance_id,
            battery_slot_id=b.battery_slot_id,
            base_task_hash=b.base_task_hash,
            execution_semantics_hash=b.execution_semantics_hash,
            metrics=metrics,
        )
        object.__setattr__(base, "baseline_id", base._derive_id())
        object.__setattr__(base, "baseline_hash", base._compute_hash())
        return base

    # ── identity ────────────────────────────────────────────────────

    def _identity_content(self) -> dict:
        """The four identities that determine what this is a baseline OF.

        `envelope_hash` is included deliberately. Two runs of the same
        execution identity produce different evidence - models are
        non-deterministic - and they are different baselines. Excluding it
        would make them collide.

        Registry metadata is absent by construction: it lives on
        BaselineRegistryEntry, so there is nothing here to accidentally hash.
        """
        return {
            "configuration_fingerprint": self.configuration_fingerprint,
            "evaluation_fingerprint": self.evaluation_fingerprint,
            "execution_id": self.execution_id,
            "envelope_hash": self.envelope_hash,
        }

    def _derive_id(self) -> str:
        blob = json.dumps(self._identity_content(), sort_keys=True,
                          separators=(",", ":"))
        return "BL-" + hashlib.sha256(blob.encode()).hexdigest()[:16]

    def _canonical(self) -> dict:
        return {
            **self._identity_content(),
            "battery_spec_fingerprint": self.battery_spec_fingerprint,
            "battery_instance_id": self.battery_instance_id,
            "battery_slot_id": self.battery_slot_id,
            "base_task_hash": self.base_task_hash,
            "execution_semantics_hash": self.execution_semantics_hash,
            "metrics": [list(m) for m in self.metrics],
        }

    def _compute_hash(self) -> str:
        blob = json.dumps(self._canonical(), sort_keys=True,
                          separators=(",", ":"), default=str)
        return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()

    # ── verification ────────────────────────────────────────────────

    def verify(self, envelope=None) -> dict:
        """Recompute identity and hash; optionally re-verify the envelope.

        Read-only. Verifying must not change the baseline or the envelope.
        """
        result: dict[str, Any] = {
            "id_ok": self.baseline_id == self._derive_id(),
            "hash_ok": self.baseline_hash == self._compute_hash(),
            "envelope_checked": False,
            "envelope_ok": None,
            "problems": [],
        }
        if not result["id_ok"]:
            result["problems"].append(
                "baseline_id does not match its content: it was assigned or "
                "altered rather than derived")
        if not result["hash_ok"]:
            result["problems"].append("baseline content was altered")

        if envelope is not None:
            result["envelope_checked"] = True
            if envelope.envelope_hash != self.envelope_hash:
                result["envelope_ok"] = False
                result["problems"].append(
                    f"envelope reference mismatch: baseline points at "
                    f"{self.envelope_hash[:24]}, this envelope is "
                    f"{envelope.envelope_hash[:24]}")
            else:
                v = envelope.verify()
                result["envelope_ok"] = v.integrity_ok and v.completeness_ok
                if not result["envelope_ok"]:
                    result["problems"].append(
                        "referenced envelope no longer verifies")

        result["valid"] = (result["id_ok"] and result["hash_ok"]
                           and result["envelope_ok"] is not False)
        return result

    def resolve_subject(self) -> dict:
        """What this is a baseline OF.

        The complete battery reference is spec_fingerprint +
        battery_instance_id - the paired contract from 5B. Neither alone is
        sufficient: the spec cannot see a changed seed or size, and the
        instance cannot see a spec change that leaves generation unchanged.
        """
        return {
            "configuration_fingerprint": self.configuration_fingerprint,
            "evaluation_fingerprint": self.evaluation_fingerprint,
            "execution_id": self.execution_id,
            "battery_spec_fingerprint": self.battery_spec_fingerprint,
            "battery_instance_id": self.battery_instance_id,
            "battery_slot_id": self.battery_slot_id,
            "base_task_hash": self.base_task_hash,
        }

    # ── serialisation ───────────────────────────────────────────────

    def to_dict(self) -> dict:
        """The JSON-serialisable form: the baseline's content plus its `baseline_id` and `baseline_hash`."""
        d = self._canonical()
        d["baseline_id"] = self.baseline_id
        d["baseline_hash"] = self.baseline_hash
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "ReliabilityBaseline":
        """Rebuild and verify. A stored hash is never trusted on its word."""
        if not isinstance(data, dict):
            raise BaselineError("from_dict expects a dict")
        for req in ("baseline_id", "baseline_hash", "envelope_hash",
                    "execution_id"):
            if req not in data:
                raise BaselineError(
                    f"cannot reconstruct: {req!r} missing. A partial "
                    f"reconstruction that verified would look complete")

        base = cls(
            configuration_fingerprint=data["configuration_fingerprint"],
            evaluation_fingerprint=data["evaluation_fingerprint"],
            execution_id=data["execution_id"],
            envelope_hash=data["envelope_hash"],
            battery_spec_fingerprint=data["battery_spec_fingerprint"],
            battery_instance_id=data["battery_instance_id"],
            battery_slot_id=data["battery_slot_id"],
            base_task_hash=data["base_task_hash"],
            execution_semantics_hash=data["execution_semantics_hash"],
            metrics=tuple(tuple(m) for m in data.get("metrics", [])),
        )
        object.__setattr__(base, "baseline_id", base._derive_id())
        object.__setattr__(base, "baseline_hash", base._compute_hash())

        if base.baseline_id != data["baseline_id"]:
            raise BaselineError(
                f"baseline_id does not match the content: stored "
                f"{data['baseline_id']}, derived {base.baseline_id}. Either "
                f"the content was altered or the id was forged")
        if base.baseline_hash != data["baseline_hash"]:
            raise BaselineError(
                f"baseline content does not round-trip: stored "
                f"{data['baseline_hash'][:24]}, recomputed "
                f"{base.baseline_hash[:24]}")
        return base

    def __repr__(self) -> str:
        return (f"<ReliabilityBaseline {self.baseline_id} "
                f"slot={self.battery_slot_id}>")


# ═══════════════════════════════════════════════════════════════════════
#  REGISTRY ENTRY - mutable, separate, deliberately outside the baseline
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class BaselineRegistryEntry:
    """Mutable relationship metadata ABOUT a baseline.

    Separate so the baseline itself stays fully immutable. Supersession is
    recorded here, never on the baseline, so the baseline's hash is untouched
    by it - the property that was wanted, obtained without making the baseline
    partly writable.

    A SUPERSEDED BASELINE IS NOT INVALIDATED. It remains verifiable and
    remains the correct reference for any comparison already made against it.
    Rewriting history to say a past comparison used a superseded baseline
    would make prior conclusions unreproducible.

    SCOPE BOUNDARY - RELATIONSHIP RECORDING IS NOT LIFECYCLE GOVERNANCE

    The presence of `supersedes` and `superseded_by` must not quietly become
    a baseline lifecycle system. This class RECORDS a relationship a caller
    asserts. It decides nothing.

    IN SCOPE (5D-B)          recording that one baseline supersedes another
                             recording who created one, when, under what label

    OUT OF SCOPE             automatic supersession
                             preferred-baseline selection
                             baseline ranking
                             automatic validity decisions
                             expiration          -> Phase 7
                             revocation          -> Phase 7
                             registry topology   -> DW-010 / Phase 9
                             persistent registry service
                             storage policy

    A STRUCTURE, NOT A REGISTRY SERVICE. Storage and retention are DW-010, and
    the topology of a persistent registry - set, chain, graph, versioned - is
    deliberately NOT fixed here.

    Asserted by test_registry_entry_governs_nothing.
    """

    baseline_id: str
    created_at: float = field(default_factory=time.time)
    created_by: str = "unknown"
    label: Optional[str] = None
    supersedes: Optional[str] = None
    superseded_by: Optional[str] = None

    def supersede(self, earlier: "BaselineRegistryEntry") -> None:
        """Record that this entry supersedes an earlier one.

        One-directional and additive. Nothing is deleted.
        """
        if earlier.baseline_id == self.baseline_id:
            raise BaselineError(
                "a baseline cannot supersede itself: identical content is the "
                "same baseline")
        self.supersedes = earlier.baseline_id
        earlier.superseded_by = self.baseline_id

    def to_dict(self) -> dict:
        """The JSON-serialisable form of the registry entry: id, creation time and author, label, and the entries it supersedes or is superseded by."""
        return {
            "baseline_id": self.baseline_id,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "label": self.label,
            "supersedes": self.supersedes,
            "superseded_by": self.superseded_by,
            "_note": ("registry metadata; deliberately outside the baseline's "
                      "canonical content and hash"),
        }
