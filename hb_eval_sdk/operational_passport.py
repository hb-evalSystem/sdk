"""
hb_eval_sdk/operational_passport.py — R7: the Operational Passport
NOT AN INDEPENDENT OPERATIONAL IDENTITY
    An Operational Passport is DERIVED, and only derived:
        Readiness Passport  ->  Enrollment ledger  ->  Operational logs
                            ->  current operational state
    It introduces no identity of its own beyond a content address, and no
    judgement of its own. There is no score, no verdict, no tier. Every
    statement it makes is a CLAIM paired with the evidence references that
    support it:
        LEDGER:<i>                 the i-th event of the enrollment ledger
        OPS:<seq>:<hash-prefix>    an operational event (R6)
    and every reference is checked to resolve.
WHY R7 IS NOT R4 WITH RUNTIME FIELDS
    R4 answers: what was demonstrated before production?
    R7 answers: what happened after deployment, and what state is the
                subject in now — and on what evidence?
    So R7 is temporal. It carries the ordered enrollment history, the
    observation window, activity recorded while the subject was NOT active,
    context changes, faults, and what stayed UNATTRIBUTED. The readiness
    decision is carried as a REFERENCE, labelled pre-production; it is never
    re-presented as a current operational fact.
LONGITUDINAL
    Each derivation may name the previous operational passport for the same
    readiness passport. The chain is checked: same readiness passport, time
    does not run backwards, the ledger only grows. A sequence of operational
    passports is therefore a verifiable history, not a set of snapshots.
BINDING THAT MAKES IT DERIVED
    Every operational event must carry an enrollment hash that is the hash of
    a PREFIX of this enrollment's ledger. An event recorded under a
    different enrollment — or a forged one — does not match any prefix and
    is refused. Events carrying a different readiness passport belong to
    another operational period and are refused.
"""
from __future__ import annotations
import hashlib
import json
from collections import Counter
from dataclasses import dataclass, replace
from typing import Optional
from .enforcement_evidence import summarise_enforcement
__all__ = ["OperationalPassport", "OperationalPassportError",
           "derive_operational_passport", "OPERATIONAL_PASSPORT_VERSION"]
OPERATIONAL_PASSPORT_VERSION = "hb-eval-operational-passport/v1"
class OperationalPassportError(Exception):
    """Raised when an operational passport cannot be derived honestly, for example because an upstream artefact fails verification."""
    pass
def _h(obj) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        default=str).encode()).hexdigest()
_STANDING_NOT_OBSERVED = (
    "covers only the operational logs supplied; executions not supplied are "
    "not represented",
    "attribution is declared once per handoff, not inferred; framework "
    "adapters are not yet wired to declare it (DW-033)",
    "log and ledger integrity is internal consistency, not authorship "
    "(DW-032, DW-009)",
    "no runtime metric is recomputed and no operational verdict is made; the "
    "only decision referenced is the pre-production readiness decision",
    "enforcement outcomes are the boundary's report unless a tool-side log "
    "corroborates them; tool logs are unsigned (DW-009)",
)
def _lifecycle(state, has_events, context_changed):
    """§19 lifecycle, derived from the enrollment state and observations.
    A mapping, not a judgement: each branch reads recorded facts."""
    if state == "APPROVED":
        return "VERIFIED"
    if state == "ACTIVE":
        if context_changed:
            return "CONTEXT_CHANGED"
        return "MONITORED" if has_events else "ACTIVE"
    if state == "PENDING":
        return "RE_EVALUATED"
    return state  # SUSPENDED · RECERTIFICATION_REQUIRED · REVOKED
@dataclass(frozen=True)
class OperationalPassport:
    """The in-production counterpart of the readiness passport: what the system was observed doing while enrolled.

    It carries the pre-production decision by reference and labelled as such, the enrolment it rests on,
    and claims that each cite the operational evidence behind them. It is derived, never edited.
    """
    readiness_passport_id: str
    readiness_passport_hash: str
    readiness_reference: dict
    """Pre-production decision, carried by reference and labelled as such."""
    system_id: str
    subject_participant_id: str
    enrollment_hash: str
    enrollment_state: str
    lifecycle_state: str
    enrollment_history: tuple
    """(ref, action, from_state, to_state, at, reason) for every ledger
    event — including the ones that led to suspension or recertification."""
    as_of: float
    observation_window: tuple          # (first_event_at, last_event_at)
    event_counts: tuple                # ((kind, n), ...)
    attributed_by_participant: tuple   # ((participant_id, n), ...)
    unattributed_refs: tuple
    outside_active_refs: tuple
    context_change_refs: tuple
    fault_refs: tuple
    log_hashes: tuple
    enforcement_records: tuple
    tool_log_hashes: tuple
    claims: tuple
    """((claim, (evidence_ref, ...)), ...). Every claim has evidence."""
    not_observed: tuple
    previous_operational_passport_hash: Optional[str] = None
    operational_passport_version: str = OPERATIONAL_PASSPORT_VERSION
    operational_passport_id: str = ""
    operational_passport_hash: str = ""
    def __post_init__(self):
        c = self._canonical()
        if not self.operational_passport_id:
            object.__setattr__(self, "operational_passport_id",
                               "OPP-" + _h(c)[7:23])
        if not self.operational_passport_hash:
            object.__setattr__(self, "operational_passport_hash", _h(c))
    def _canonical(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__
                if k not in ("operational_passport_id",
                             "operational_passport_hash")}
    def verify(self) -> dict:
        """Check the passport's hash and id against its content, and that every claim cites evidence. Returns `{"valid": bool, "problems": [...]}`."""
        problems = []
        c = self._canonical()
        if self.operational_passport_hash != _h(c):
            problems.append("operational passport content was altered")
        if self.operational_passport_id != "OPP-" + _h(c)[7:23]:
            problems.append("operational_passport_id does not match content")
        for claim, refs in self.claims:
            if not refs:
                problems.append(f"claim without evidence: {claim}")
        return {"valid": not problems, "problems": problems}
    def to_dict(self) -> dict:
        """The JSON-serialisable form, including `operational_passport_id` and `operational_passport_hash`."""
        return {**self._canonical(),
                "operational_passport_id": self.operational_passport_id,
                "operational_passport_hash": self.operational_passport_hash}
def derive_operational_passport(*, readiness_passport, enrollment,
                                operational_logs: tuple, as_of: float,
                                previous=None, tool_logs: tuple = ()
                                ) -> OperationalPassport:
    """Derive an operational passport from a readiness passport, an enrolment and the operational logs.

    Verifies each upstream artefact first and raises OperationalPassportError if the readiness passport
    or the chain from it to the enrolment does not hold. `as_of` is the time the derivation is for,
    `previous` an earlier passport to continue from, and `tool_logs` independent tool-execution logs
    used to corroborate enforcement claims.
    """
    rp = readiness_passport
    # ── the chain: readiness -> enrollment ──────────────────────────
    if not rp.verify()["valid"]:
        raise OperationalPassportError("the readiness passport does not "
                                       "verify")
    if not enrollment.verify()["valid"]:
        raise OperationalPassportError("the enrollment ledger does not "
                                       "verify")
    for f, a, b in (("system_id", enrollment.system_id, rp.system_id),
                    ("subject", enrollment.subject_participant_id,
                     rp.subject_participant_id),
                    ("configuration", enrollment.configuration_fingerprint,
                     rp.configuration_fingerprint)):
        if a != b:
            raise OperationalPassportError(
                f"enrollment and readiness passport differ in {f}")
    approvals = [i for i, e in enumerate(enrollment.events)
                 if e.action == "approve"
                 and e.passport_hash == rp.passport_hash]
    if not approvals:
        raise OperationalPassportError(
            "this readiness passport was never approved in this enrollment; "
            "there is no operational period to describe")
    ledger = enrollment.events
    prefix_hashes = {replace(enrollment, events=ledger[:k],
                             enrollment_hash="").enrollment_hash
                     for k in range(len(ledger) + 1)}
    # ── the chain: enrollment -> operational evidence ───────────────
    events = []
    for log in operational_logs:
        v = log.verify()
        if not v["valid"]:
            raise OperationalPassportError(
                f"an operational log does not verify: {v['problems']}")
        if log.topology_hash != rp.topology_hash:
            raise OperationalPassportError(
                "an operational log was recorded against a different "
                "topology")
        for e in log.events:
            if e.enrollment_hash not in prefix_hashes:
                raise OperationalPassportError(
                    f"{e.evidence_ref} was recorded under an enrollment that "
                    f"is not a prefix of this ledger")
            if e.passport_hash not in (None, rp.passport_hash):
                raise OperationalPassportError(
                    f"{e.evidence_ref} belongs to another readiness "
                    f"passport's operational period")
            events.append(e)
    last_ledger_at = ledger[-1].at if ledger else None
    last_event_at = max((e.at for e in events), default=None)
    for label, t in (("ledger", last_ledger_at), ("event", last_event_at)):
        if t is not None and as_of < t:
            raise OperationalPassportError(
                f"as_of precedes the last {label}; a passport cannot describe"
                f" a future it has not seen")
    # ── longitudinal chain ──────────────────────────────────────────
    prev_hash = None
    if previous is not None:
        if not previous.verify()["valid"]:
            raise OperationalPassportError("the previous operational passport"
                                           " does not verify")
        if previous.readiness_passport_hash != rp.passport_hash:
            raise OperationalPassportError(
                "the previous operational passport is for another readiness "
                "passport")
        if previous.as_of > as_of:
            raise OperationalPassportError("time runs backwards in the chain")
        if len(previous.enrollment_history) > len(ledger):
            raise OperationalPassportError("the ledger shrank since the "
                                           "previous passport")
        prev_hash = previous.operational_passport_hash
    # ── observations, each with its evidence ────────────────────────
    ref = lambda e: e.evidence_ref                              # noqa: E731
    unattributed = tuple(ref(e) for e in events
                         if e.attribution == "UNATTRIBUTED")
    outside = tuple(ref(e) for e in events if e.enrollment_state != "ACTIVE")
    contexts = tuple(ref(e) for e in events if e.kind == "CONTEXT_CHANGE")
    faults = tuple(ref(e) for e in events if e.kind == "FAULT")
    context_changed = any(e.kind == "CONTEXT_CHANGE"
                          and e.payload.get("state") != "CONTEXT_UNCHANGED"
                          for e in events)
    enf_records, enf_claims, enf_not_obs = summarise_enforcement(
        events, tool_logs=tool_logs, prefix_hashes=prefix_hashes,
        readiness_passport_hash=rp.passport_hash)
    history = tuple((f"LEDGER:{i}", e.action, e.from_state, e.to_state,
                     e.at, e.reason) for i, e in enumerate(ledger))
    state = enrollment.state
    last_ref = f"LEDGER:{len(ledger) - 1}"
    claims = [(f"enrollment state is {state}", (last_ref,)),
              ("readiness passport approved for operation",
               tuple(f"LEDGER:{i}" for i in approvals))]
    for i, e in enumerate(ledger):
        if e.to_state in ("SUSPENDED", "RECERTIFICATION_REQUIRED",
                          "REVOKED"):
            claims.append((f"{e.to_state}: {e.reason}", (f"LEDGER:{i}",)))
    if outside:
        claims.append(("activity was recorded while not ACTIVE", outside))
    if unattributed:
        claims.append(("some operational events have no known producer",
                       unattributed))
    if contexts:
        claims.append(("context was assessed during operation", contexts))
    if faults:
        claims.append(("faults were observed during operation", faults))
    claims.extend(enf_claims)
    return OperationalPassport(
        readiness_passport_id=rp.passport_id,
        readiness_passport_hash=rp.passport_hash,
        readiness_reference={
            "label": "PRE-PRODUCTION DECISION — not a current operational "
                     "fact",
            "decision_state": rp.decision_state,
            "policy_id": rp.policy_id, "scope_level": rp.scope_level,
            "attestation_hash": rp.attestation_hash},
        system_id=rp.system_id,
        subject_participant_id=rp.subject_participant_id,
        enrollment_hash=enrollment.enrollment_hash,
        enrollment_state=state,
        lifecycle_state=_lifecycle(state, bool(events), context_changed),
        enrollment_history=history, as_of=as_of,
        observation_window=(min((e.at for e in events), default=None),
                            last_event_at),
        event_counts=tuple(sorted(Counter(e.kind for e in events).items())),
        attributed_by_participant=tuple(sorted(Counter(
            e.participant_id for e in events
            if e.attribution == "ATTRIBUTED").items())),
        unattributed_refs=unattributed, outside_active_refs=outside,
        context_change_refs=contexts, fault_refs=faults,
        log_hashes=tuple(sorted(l.log_hash for l in operational_logs)),
        enforcement_records=enf_records,
        tool_log_hashes=tuple(sorted(l.hash for l in tool_logs)),
        claims=tuple(claims),
        not_observed=tuple(rp.not_observed) + _STANDING_NOT_OBSERVED
        + enf_not_obs,
        previous_operational_passport_hash=prev_hash)
# HB-Eval V2 Execution State
