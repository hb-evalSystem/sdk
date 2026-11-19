"""
hb_eval_sdk/enrollment.py — R5: production enrollment
READINESS PASSPORT != ENROLLMENT APPROVAL
    A Readiness Passport is an evidence-backed READINESS ARTEFACT: it says
    what the evidence supports, under which policy and scope.
    Enrollment is a separate OPERATIONAL DECISION, made under its own
    declared EnrollmentPolicy, that consumes a passport:
        Readiness Passport
            -> meets the declared enrollment policy?
            -> identity, scope, context, age valid?
            -> ENROLLMENT DECISION (APPROVED, recorded with its reasons)
            -> ACTIVE
    A passport alone never makes anything ACTIVE.
THE STATE MACHINE IS A LEDGER, NOT A FIELD
    An Enrollment carries no writable `state`. It carries an ordered,
    content-addressed log of events, and its state is the REPLAY of that log
    through the transition table. Constructing an Enrollment whose events
    do not replay legally raises. So
        Enrollment(state="ACTIVE")         does not exist as an API
        an ACTIVE without an approval      cannot be constructed
        an approval without a passport     cannot be constructed
    That is how the bypass paths are closed structurally rather than by
    convention.
BYPASS PATHS, EACH REFUSED
    no passport                         -> cannot reach PENDING, so cannot
                                           reach ACTIVE
    invalid / inconsistent passport     -> approval refused
    passport outside enrollment policy  -> approval refused
    expired passport                    -> approval and activation refused;
                                           an ACTIVE enrollment found expired
                                           moves to RECERTIFICATION_REQUIRED
    RECERTIFICATION_REQUIRED            -> cannot remain ACTIVE; the only
                                           way back is a NEW passport
    context or policy invalidation      -> ACTIVE moves to a non-active state
WHAT THIS IS NOT
    Not enforcement. A state here is RECORDED; nothing is stopped. Blocking an
    agent whose enrollment is not ACTIVE is the Runtime Enforcement Plane,
    R8. Calling this enforcement would claim control the SDK does not have.
TIME
    Every transition takes `now` from the caller. There is no hidden clock,
    so the same inputs always produce the same ledger and the same hash.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field, replace
from typing import Optional
__all__ = [
    "EnrollmentState", "EnrollmentPolicy", "EnrollmentEvent", "Enrollment",
    "EnrollmentError", "ENROLLMENT_VERSION", "TRANSITIONS",
    "new_enrollment", "request_enrollment", "approve_enrollment",
    "activate", "suspend", "resume", "apply_context_assessment",
    "apply_policy_change", "check_expiry", "resubmit", "revoke",
]
ENROLLMENT_VERSION = "hb-eval-enrollment/v1"
class EnrollmentError(Exception):
    """The requested transition is not permitted."""
class EnrollmentState:
    """The states of an agent's enrolment for production use.

    NOT_ENROLLED, PENDING (requested), APPROVED, ACTIVE, SUSPENDED, RECERTIFICATION_REQUIRED
    (the evidence behind it expired or its context changed), and REVOKED. The state is never stored:
    it is derived by replaying the enrolment's event ledger.
    """
    NOT_ENROLLED = "NOT_ENROLLED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    RECERTIFICATION_REQUIRED = "RECERTIFICATION_REQUIRED"
    REVOKED = "REVOKED"
    ALL = (NOT_ENROLLED, PENDING, APPROVED, ACTIVE, SUSPENDED,
           RECERTIFICATION_REQUIRED, REVOKED)
_S = EnrollmentState
TRANSITIONS = {
    (_S.NOT_ENROLLED, "request"): _S.PENDING,
    (_S.PENDING, "approve"): _S.APPROVED,
    (_S.APPROVED, "activate"): _S.ACTIVE,
    (_S.ACTIVE, "suspend"): _S.SUSPENDED,
    (_S.SUSPENDED, "resume"): _S.ACTIVE,
    (_S.APPROVED, "require_recertification"): _S.RECERTIFICATION_REQUIRED,
    (_S.ACTIVE, "require_recertification"): _S.RECERTIFICATION_REQUIRED,
    (_S.SUSPENDED, "require_recertification"): _S.RECERTIFICATION_REQUIRED,
    (_S.RECERTIFICATION_REQUIRED, "resubmit"): _S.PENDING,
    **{(s, "revoke"): _S.REVOKED for s in _S.ALL if s != _S.REVOKED},
}
"""The complete transition table. Anything not listed is illegal. REVOKED is
terminal. Note what is absent: no path into ACTIVE except `activate` from
APPROVED or `resume` from SUSPENDED, and no path out of
RECERTIFICATION_REQUIRED except a resubmission or a revocation."""
def _h(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True,
                                     separators=(",", ":"),
                                     default=str).encode()).hexdigest()
@dataclass(frozen=True)
class EnrollmentPolicy:
    """What a passport must show to be enrolled. Declared, versioned,
    content-addressed — the same four properties R1 gave every policy.
    There is NO default acceptance. An empty `accepted_policy_ids` is
    refused at construction: the absence of a policy is not permission.
    """
    enrollment_policy_version: str
    accepted_policy_ids: tuple
    allowed_scope_levels: tuple = ("AGENT", "SYSTEM")
    accepted_context_states: tuple = ("CONTEXT_UNCHANGED",)
    max_passport_age_seconds: Optional[float] = None
    allowed_capabilities: tuple = ()
    enrollment_policy_id: str = ""
    enrollment_policy_hash: str = ""
    def __post_init__(self):
        if not self.enrollment_policy_version:
            raise EnrollmentError("an enrollment policy must be versioned")
        if not self.accepted_policy_ids:
            raise EnrollmentError(
                "an enrollment policy must name the readiness policies it "
                "accepts; there is no default acceptance")
        if "RECERTIFICATION_REQUIRED" in self.accepted_context_states:
            raise EnrollmentError(
                "RECERTIFICATION_REQUIRED cannot be an accepted context: it "
                "means the evidence no longer applies")
        content = self._content()
        if not self.enrollment_policy_id:
            object.__setattr__(self, "enrollment_policy_id",
                               "ENP-" + _h(content)[:16])
        if not self.enrollment_policy_hash:
            object.__setattr__(self, "enrollment_policy_hash",
                               "sha256:" + _h(content))
    def _content(self) -> dict:
        return {"version": self.enrollment_policy_version,
                "accepted_policy_ids": sorted(self.accepted_policy_ids),
                "allowed_scope_levels": sorted(self.allowed_scope_levels),
                "accepted_context_states":
                    sorted(self.accepted_context_states),
                "max_passport_age_seconds": self.max_passport_age_seconds,
                "allowed_capabilities": sorted(self.allowed_capabilities)}
@dataclass(frozen=True)
class EnrollmentEvent:
    """One entry in an enrolment's ledger: the action, the state it moved from and to, when, why, and the hashes of the passport and attestation it was based on."""
    action: str
    from_state: str
    to_state: str
    at: float
    reason: str
    passport_hash: Optional[str] = None
    attestation_hash: Optional[str] = None
    policy_id: Optional[str] = None
    passport_issued_at: Optional[float] = None
    checks: tuple = ()
    """The conditions evaluated for an approval, recorded so the decision is
    auditable rather than a bare state change."""
    def to_dict(self) -> dict:
        """The JSON-serialisable form, including the list of checks that were run."""
        d = {k: getattr(self, k) for k in self.__dataclass_fields__}
        d["checks"] = list(self.checks)
        return d
@dataclass(frozen=True)
class Enrollment:
    """Identity of the enrolled subject plus the event ledger. `state` is
    derived by replay and cannot be set."""
    system_id: str
    subject_participant_id: str
    configuration_fingerprint: str
    enrollment_policy_id: str
    enrollment_policy_hash: str
    events: tuple = ()
    enrollment_version: str = ENROLLMENT_VERSION
    enrollment_hash: str = ""
    def __post_init__(self):
        self._replay()
        if not self.enrollment_hash:
            object.__setattr__(self, "enrollment_hash",
                               "sha256:" + _h(self._canonical()))
    def _replay(self) -> str:
        state, last_at = EnrollmentState.NOT_ENROLLED, None
        approved = False
        for i, e in enumerate(self.events):
            if e.from_state != state:
                raise EnrollmentError(
                    f"event {i} ({e.action}) starts from {e.from_state} but "
                    f"the ledger is in {state}")
            target = TRANSITIONS.get((state, e.action))
            if target is None or target != e.to_state:
                raise EnrollmentError(
                    f"event {i}: {e.action} from {state} to {e.to_state} is "
                    f"not a legal transition")
            if last_at is not None and e.at < last_at:
                raise EnrollmentError(f"event {i} is earlier than event "
                                      f"{i - 1}")
            if e.action in ("request", "resubmit", "approve") and \
                    not e.passport_hash:
                raise EnrollmentError(
                    f"event {i}: {e.action} without a passport")
            if e.action == "approve":
                if not (e.attestation_hash and e.policy_id and e.checks):
                    raise EnrollmentError(
                        f"event {i}: an approval must record the attestation,"
                        f" the policy and the checks it passed")
                approved = True
            if e.action in ("resubmit", "request"):
                approved = False
            if e.to_state == EnrollmentState.ACTIVE and not approved:
                raise EnrollmentError(
                    f"event {i}: ACTIVE without an approval in force")
            state, last_at = e.to_state, e.at
        return state
    @property
    def state(self) -> str:
        """The current state, derived by replaying the ledger. Raises EnrollmentError if the ledger records a transition the state machine does not allow."""
        return self._replay()
    @property
    def approval(self) -> Optional[EnrollmentEvent]:
        """The approval event currently in force, or None. A later `request` or `resubmit` withdraws an earlier approval."""
        current = None
        for e in self.events:
            if e.action == "approve":
                current = e
            elif e.action in ("resubmit", "request"):
                current = None
        return current
    def _canonical(self) -> dict:
        return {"system_id": self.system_id,
                "subject_participant_id": self.subject_participant_id,
                "configuration_fingerprint": self.configuration_fingerprint,
                "enrollment_policy_id": self.enrollment_policy_id,
                "enrollment_policy_hash": self.enrollment_policy_hash,
                "enrollment_version": self.enrollment_version,
                "events": [e.to_dict() for e in self.events]}
    def verify(self, passport=None, enrollment_policy=None) -> dict:
        """Replay the ledger and check its hash, and optionally check it against a readiness passport and an enrolment policy. Returns `{"valid": bool, "problems": [...]}`."""
        problems = []
        try:
            self._replay()
        except EnrollmentError as exc:
            problems.append(str(exc))
        if self.enrollment_hash != "sha256:" + _h(self._canonical()):
            problems.append("enrollment ledger was altered")
        if enrollment_policy is not None and \
                enrollment_policy.enrollment_policy_hash != \
                self.enrollment_policy_hash:
            problems.append("the enrollment policy is not the one enrolled "
                            "under")
        if passport is not None:
            ap = self.approval
            if ap is None or ap.passport_hash != passport.passport_hash:
                problems.append("the passport is not the one approved")
        return {"valid": not problems, "problems": problems}
    def _with(self, event: EnrollmentEvent) -> "Enrollment":
        return replace(self, events=self.events + (event,),
                       enrollment_hash="")
# ── transitions ─────────────────────────────────────────────────────
def _step(enr: Enrollment, action: str, now: float, reason: str,
          **fields) -> Enrollment:
    state = enr.state
    target = TRANSITIONS.get((state, action))
    if target is None:
        raise EnrollmentError(f"{action} is not permitted from {state}")
    if enr.events and now < enr.events[-1].at:
        raise EnrollmentError("time cannot run backwards in the ledger")
    return enr._with(EnrollmentEvent(action=action, from_state=state,
                                     to_state=target, at=now, reason=reason,
                                     **fields))
def new_enrollment(enrollment_policy: EnrollmentPolicy, *, system_id: str,
                   subject_participant_id: str,
                   configuration_fingerprint: str) -> Enrollment:
    """Create an enrolment for one subject in one system under a policy. Raises EnrollmentError if the system id, the subject participant id or the configuration fingerprint is missing."""
    for name, v in (("system_id", system_id),
                    ("subject_participant_id", subject_participant_id),
                    ("configuration_fingerprint", configuration_fingerprint)):
        if not v:
            raise EnrollmentError(f"enrollment requires {name}")
    return Enrollment(system_id=system_id,
                      subject_participant_id=subject_participant_id,
                      configuration_fingerprint=configuration_fingerprint,
                      enrollment_policy_id=enrollment_policy.enrollment_policy_id,
                      enrollment_policy_hash=enrollment_policy.enrollment_policy_hash)
def _same_subject(enr, passport):
    if passport is None:
        raise EnrollmentError(
            "no passport: an agent cannot enter the operational lifecycle "
            "without readiness evidence")
    mismatches = [n for n, a, b in (
        ("system_id", enr.system_id, passport.system_id),
        ("subject", enr.subject_participant_id,
         passport.subject_participant_id),
        ("configuration", enr.configuration_fingerprint,
         passport.configuration_fingerprint)) if a != b]
    if mismatches:
        raise EnrollmentError(
            f"the passport is for a different subject: {mismatches}")
def request_enrollment(enr: Enrollment, passport, *, now: float) -> Enrollment:
    """Request enrolment on the strength of a readiness passport. Returns a new Enrollment; the passport must be for the same subject."""
    _same_subject(enr, passport)
    return _step(enr, "request", now, "enrollment requested",
                 passport_hash=passport.passport_hash)
def resubmit(enr: Enrollment, passport, *, now: float) -> Enrollment:
    """The only way out of RECERTIFICATION_REQUIRED short of revocation, and
    it requires a passport other than the one that lapsed."""
    _same_subject(enr, passport)
    old = [e.passport_hash for e in enr.events if e.action == "approve"]
    if old and passport.passport_hash == old[-1]:
        raise EnrollmentError(
            "resubmitting the passport that required recertification does "
            "not recertify anything; a new evaluation is needed")
    return _step(enr, "resubmit", now, "resubmitted after re-evaluation",
                 passport_hash=passport.passport_hash)
def approve_enrollment(enr: Enrollment, *, passport, enrollment_policy,
                       attestation, policy_document, topology, lineage,
                       now: float, context_assessment=None) -> Enrollment:
    """The enrollment decision. Every check is recorded in the approval."""
    if enr.state != EnrollmentState.PENDING:
        raise EnrollmentError(f"approval requires PENDING, not {enr.state}")
    if enrollment_policy.enrollment_policy_hash != enr.enrollment_policy_hash:
        raise EnrollmentError("not the enrollment policy this enrollment "
                              "was opened under")
    _same_subject(enr, passport)
    requested = [e for e in enr.events if e.action in ("request", "resubmit")]
    if requested[-1].passport_hash != passport.passport_hash:
        raise EnrollmentError("not the passport that was submitted")
    v = passport.verify(attestation, policy_document, topology, lineage)
    if not v["valid"]:
        raise EnrollmentError(f"the passport does not verify against its "
                              f"artefacts: {v['problems']}")
    failures = []
    checks = ["passport verifies against attestation, policy, topology, "
              "lineage", "subject, system and configuration match"]
    if passport.decision_state != "PASS":
        failures.append(f"decision is {passport.decision_state}")
    else:
        checks.append("decision PASS")
    if passport.policy_id not in enrollment_policy.accepted_policy_ids:
        failures.append(f"readiness policy {passport.policy_id} is not "
                        f"accepted")
    else:
        checks.append(f"readiness policy {passport.policy_id} accepted")
    if passport.scope_level not in enrollment_policy.allowed_scope_levels:
        failures.append(f"scope {passport.scope_level} not allowed")
    else:
        checks.append(f"scope {passport.scope_level} allowed")
    if context_assessment is not None:
        if context_assessment.attestation_hash != attestation.attestation_hash:
            raise EnrollmentError("context assessment is for another "
                                  "attestation")
        ctx = context_assessment.state
    else:
        # NOT the passport's context_state. That was assessed when the
        # passport was ISSUED; enrollment asks whether the context holds NOW.
        # Falling back to it would let an issuance-time assessment approve an
        # enrollment made after the context may have changed. Found by
        # test_an_unassessed_context_is_not_accepted_by_default.
        ctx = "NOT_ASSESSED"
    if ctx not in enrollment_policy.accepted_context_states:
        failures.append(f"context {ctx} not accepted")
    else:
        checks.append(f"context {ctx} accepted")
    issued = attestation.produced_at
    if now < issued:
        failures.append("approval is dated before the evidence was produced")
    max_age = enrollment_policy.max_passport_age_seconds
    if max_age is not None:
        if now - issued > max_age:
            failures.append(f"passport expired: {now - issued:.0f}s old, "
                            f"limit {max_age:.0f}s")
        else:
            checks.append("passport within its age limit")
    if failures:
        raise EnrollmentError("enrollment refused: " + "; ".join(failures))
    return _step(enr, "approve", now, "enrollment policy satisfied",
                 passport_hash=passport.passport_hash,
                 attestation_hash=attestation.attestation_hash,
                 policy_id=passport.policy_id, passport_issued_at=issued,
                 checks=tuple(checks))
def _expired(enr, enrollment_policy, now) -> bool:
    ap = enr.approval
    max_age = enrollment_policy.max_passport_age_seconds
    return (ap is not None and max_age is not None
            and now - ap.passport_issued_at > max_age)
def activate(enr: Enrollment, *, enrollment_policy, now: float) -> Enrollment:
    """Activate an APPROVED enrolment. Raises EnrollmentError if it is not APPROVED, or if the approved passport expired before activation."""
    if enr.state != EnrollmentState.APPROVED:
        raise EnrollmentError(f"activation requires APPROVED, not "
                              f"{enr.state}")
    if _expired(enr, enrollment_policy, now):
        raise EnrollmentError("the approved passport expired before "
                              "activation")
    return _step(enr, "activate", now, "activated")
def suspend(enr: Enrollment, *, reason: str, now: float) -> Enrollment:
    """Suspend an enrolment, recording why. Returns a new Enrollment."""
    return _step(enr, "suspend", now, reason)
def resume(enr: Enrollment, *, enrollment_policy, now: float,
           context_assessment=None) -> Enrollment:
    """Resume a suspended enrolment. Raises EnrollmentError if the passport has expired, or if a supplied context assessment is in a state the policy does not accept."""
    if _expired(enr, enrollment_policy, now):
        raise EnrollmentError("cannot resume on an expired passport")
    if context_assessment is not None and context_assessment.state not in \
            enrollment_policy.accepted_context_states:
        raise EnrollmentError(f"cannot resume: context "
                              f"{context_assessment.state}")
    return _step(enr, "resume", now, "resumed")
def apply_context_assessment(enr: Enrollment, assessment, *,
                             enrollment_policy, now: float) -> Enrollment:
    """Context invalidation moves an operating enrollment out of ACTIVE."""
    ap = enr.approval
    if ap is None:
        return enr
    if assessment.attestation_hash != ap.attestation_hash:
        raise EnrollmentError("assessment is for another attestation")
    if assessment.state == "RECERTIFICATION_REQUIRED":
        return _step(enr, "require_recertification", now,
                     f"context changed: {list(assessment.invalidating)}")
    if assessment.state not in enrollment_policy.accepted_context_states \
            and enr.state == EnrollmentState.ACTIVE:
        return _step(enr, "suspend", now,
                     f"context {assessment.state} not accepted")
    return enr
def apply_policy_change(enr: Enrollment, new_policy_document, *,
                        now: float) -> Enrollment:
    """A different readiness policy means the approval no longer applies."""
    ap = enr.approval
    if ap is None or new_policy_document.policy_id == ap.policy_id:
        return enr
    return _step(enr, "require_recertification", now,
                 f"readiness policy changed from {ap.policy_id} to "
                 f"{new_policy_document.policy_id}")
def check_expiry(enr: Enrollment, *, enrollment_policy,
                 now: float) -> Enrollment:
    """If the passport behind an ACTIVE, APPROVED or SUSPENDED enrolment has expired, return an enrolment moved to RECERTIFICATION_REQUIRED; otherwise return it unchanged."""
    if enr.state in (EnrollmentState.ACTIVE, EnrollmentState.APPROVED,
                     EnrollmentState.SUSPENDED) and \
            _expired(enr, enrollment_policy, now):
        return _step(enr, "require_recertification", now,
                     "readiness passport expired")
    return enr
def revoke(enr: Enrollment, *, reason: str, now: float) -> Enrollment:
    """Revoke an enrolment, recording why. Returns a new Enrollment."""
    return _step(enr, "revoke", now, reason)
