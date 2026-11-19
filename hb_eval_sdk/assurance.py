"""
hb_eval_sdk/assurance.py — R10: continuous assurance
THE QUESTION
    Readiness said what the evidence supported BEFORE production.
    Operational evidence said what happened AFTER.
    R10 asks the standing question: does the operational state STILL satisfy
    the declared policy — and if not, what must follow?
        CONTINUE · ALERT · ENFORCE · RE_EVALUATE
NOT A NEW VERDICT, AND NOT A SCORE
    An assessment introduces no measurement. It reads the Operational
    Passport — which is itself derived and evidence-referenced — applies a
    DECLARED assurance policy, and records which rule fired with the
    passport's own evidence references. There is no number, no grade, no
    tier.
    An unassured state is therefore always traceable to a recorded fact:
    a ledger event, an operational event, an enforcement record, a tool log.
RULES ARE ORDERED AND THE DECIDING ONE IS RECORDED
    The first matching rule sets the state; later rules still contribute
    findings, because an operator needs to see everything that is wrong, not
    only the worst thing.
NO DEFAULT ASSURANCE
    A policy that declares no acceptable enrollment state is refused. Silence
    is not acceptance — the same rule as SLO thresholds, enrollment and
    enforcement.
WHAT THIS DOES NOT DO
    It does not enforce. ENFORCE is a REQUIRED ACTION addressed to the
    operator and the enforcement plane; nothing here blocks anything.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from typing import Optional
__all__ = ["AssuranceState", "RequiredAction", "AssurancePolicy",
           "AssuranceAssessment", "AssuranceError", "assess_assurance",
           "ASSURANCE_VERSION"]
ASSURANCE_VERSION = "hb-eval-assurance/v1"
class AssuranceError(Exception):
    """Raised when an assurance policy or assessment is malformed, or its inputs do not belong together."""
    pass
class AssuranceState:
    """The outcome of a continuous-assurance assessment.

    ASSURED: nothing observed contradicts the standing enrolment. ATTENTION: something deserves a look
    but does not by itself break the claim. NOT_ASSURED: observed evidence contradicts it.
    UNDETERMINED: the evidence is not enough to say either way, and must never be read as ASSURED.
    """
    ASSURED = "ASSURED"
    ATTENTION = "ATTENTION"
    NOT_ASSURED = "NOT_ASSURED"
    UNDETERMINED = "UNDETERMINED"
    ALL = (ASSURED, ATTENTION, NOT_ASSURED, UNDETERMINED)
class RequiredAction:
    """What an assessment requires the operator to do.

    CONTINUE: nothing. ALERT: tell a human. ENFORCE: apply the enforcement the policy calls for.
    RE_EVALUATE: the evidence no longer supports the standing evaluation; evaluate again.
    """
    CONTINUE = "CONTINUE"
    ALERT = "ALERT"
    ENFORCE = "ENFORCE"
    RE_EVALUATE = "RE_EVALUATE"
    ALL = (CONTINUE, ALERT, ENFORCE, RE_EVALUATE)
def _h(obj) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        default=str).encode()).hexdigest()
@dataclass(frozen=True)
class AssurancePolicy:
    """The rules an assessment is made under, content-addressed so that an assessment can name exactly
    which policy produced it.

    `acceptable_enrollment_states` and `acceptable_context_states` list the states that count as
    healthy. `require_forced_enforcement` makes a cooperative block (one the agent could have ignored)
    a finding rather than a success. `max_uncorroborated_enforcements`, when set, caps how many
    enforcement claims may rest on the enforcing boundary's word alone.
    """
    assurance_policy_version: str
    acceptable_enrollment_states: tuple = ("ACTIVE",)
    acceptable_context_states: tuple = ("CONTEXT_UNCHANGED",)
    require_forced_enforcement: bool = True
    """A cooperative block is not enforcement; if required and only
    cooperative blocks are recorded, that is a finding."""
    max_uncorroborated_enforcements: Optional[int] = None
    max_unattributed_events: Optional[int] = None
    max_faults: Optional[int] = None
    require_observation: bool = True
    """With no operational evidence at all, assurance is UNDETERMINED rather
    than ASSURED: nothing observed is not the same as nothing wrong."""
    assurance_policy_id: str = ""
    hash: str = ""
    def __post_init__(self):
        if not self.assurance_policy_version:
            raise AssuranceError("an assurance policy must be versioned")
        if not self.acceptable_enrollment_states:
            raise AssuranceError(
                "an assurance policy must name the enrollment states it "
                "accepts; silence is not acceptance")
        for bad in ("RECERTIFICATION_REQUIRED", "REVOKED"):
            if bad in self.acceptable_enrollment_states:
                raise AssuranceError(
                    f"{bad} cannot be an acceptable operating state")
        c = self._content()
        if not self.assurance_policy_id:
            object.__setattr__(self, "assurance_policy_id",
                               "ASP-" + _h(c)[7:23])
        if not self.hash:
            object.__setattr__(self, "hash", _h(c))
    def _content(self) -> dict:
        return {"version": self.assurance_policy_version,
                "enrollment": sorted(self.acceptable_enrollment_states),
                "context": sorted(self.acceptable_context_states),
                "require_forced_enforcement":
                    self.require_forced_enforcement,
                "max_uncorroborated": self.max_uncorroborated_enforcements,
                "max_unattributed": self.max_unattributed_events,
                "max_faults": self.max_faults,
                "require_observation": self.require_observation}
    def verify(self) -> dict:
        """Recompute the policy's hash. Returns `{"valid": bool, "problems": [...]}`; `valid` is False if the policy was altered after it was sealed."""
        ok = self.hash == _h(self._content())
        return {"valid": ok, "problems": [] if ok else ["policy altered"]}
@dataclass(frozen=True)
class AssuranceAssessment:
    """A sealed assessment: its state, the action it requires, the rule that decided it, and the findings,
    each of which cites the evidence it rests on.

    It also records the hashes of the operational passport and enrolment it was derived from, so it
    cannot be silently re-pointed at different inputs.
    """
    state: str
    required_action: str
    deciding_rule: str
    findings: tuple
    """((rule, severity, statement, (evidence_ref, ...)), ...)"""
    operational_passport_hash: str
    enrollment_hash: str
    assurance_policy_id: str
    assurance_policy_hash: str
    as_of: float
    assurance_version: str = ASSURANCE_VERSION
    assessment_id: str = ""
    hash: str = ""
    def __post_init__(self):
        c = self._canonical()
        if not self.assessment_id:
            object.__setattr__(self, "assessment_id", "ASM-" + _h(c)[7:23])
        if not self.hash:
            object.__setattr__(self, "hash", _h(c))
    def _canonical(self) -> dict:
        d = {k: getattr(self, k) for k in self.__dataclass_fields__
             if k not in ("assessment_id", "hash")}
        d["findings"] = [list(f[:3]) + [list(f[3])] for f in self.findings]
        return d
    def verify(self) -> dict:
        """Check the assessment's hash and that every finding cites evidence. A finding with no evidence reference is reported as a problem. Returns `{"valid": bool, "problems": [...]}`."""
        problems = []
        if self.hash != _h(self._canonical()):
            problems.append("assessment content was altered")
        for rule, sev, stmt, refs in self.findings:
            if not refs:
                problems.append(f"finding without evidence: {rule}")
        return {"valid": not problems, "problems": problems}
    def to_dict(self) -> dict:
        """The JSON-serialisable form, including `assessment_id` and `hash`."""
        return {**self._canonical(), "assessment_id": self.assessment_id,
                "hash": self.hash}
def assess_assurance(operational_passport, *, policy: AssurancePolicy,
                     as_of: float) -> AssuranceAssessment:
    """Read the passport, apply the declared policy, record what fired."""
    op = operational_passport
    if not op.verify()["valid"]:
        raise AssuranceError("the operational passport does not verify")
    if not policy.verify()["valid"]:
        raise AssuranceError("the assurance policy does not verify")
    if as_of < op.as_of:
        raise AssuranceError("assessment precedes the passport it reads")
    last_ledger = (f"LEDGER:{len(op.enrollment_history) - 1}"
                   if op.enrollment_history else None)
    findings, outcomes = [], []
    def add(rule, severity, statement, refs, state=None, action=None):
        if not refs:
            return
        findings.append((rule, severity, statement, tuple(refs)))
        if state:
            outcomes.append((rule, state, action))
    # A1 — is it in an acceptable operating state?
    if op.enrollment_state not in policy.acceptable_enrollment_states:
        action = {"RECERTIFICATION_REQUIRED": RequiredAction.RE_EVALUATE,
                  "PENDING": RequiredAction.RE_EVALUATE,
                  "APPROVED": RequiredAction.ALERT,
                  }.get(op.enrollment_state, RequiredAction.ENFORCE)
        add("A1_enrollment_state", "BLOCKING",
            f"enrollment is {op.enrollment_state}, which the assurance "
            f"policy does not accept for operation",
            [last_ledger] if last_ledger else [],
            AssuranceState.NOT_ASSURED, action)
    # A2 — a denied action was executed
    breaches = [r for r in op.enforcement_records
                if r["conformance"] == "BREACH"]
    add("A2_breach", "BLOCKING",
        f"{len(breaches)} denied action(s) executed",
        [x for r in breaches for x in r["evidence_refs"]],
        AssuranceState.NOT_ASSURED, RequiredAction.ENFORCE)
    # A3 — the tool's log contradicts the boundary
    contradicted = [r for r in op.enforcement_records
                    if r["corroboration"] == "CONTRADICTED"]
    add("A3_contradicted", "BLOCKING",
        f"{len(contradicted)} enforcement outcome(s) contradicted by the "
        f"tool's own log; the boundary's reports cannot be relied on",
        [x for r in contradicted for x in r["evidence_refs"]],
        AssuranceState.NOT_ASSURED, RequiredAction.ENFORCE)
    # A4 — activity while not ACTIVE
    add("A4_activity_outside_active", "BLOCKING",
        f"{len(op.outside_active_refs)} operational event(s) recorded while "
        f"the enrollment was not ACTIVE", list(op.outside_active_refs),
        AssuranceState.NOT_ASSURED, RequiredAction.ENFORCE)
    # A5 — cooperative blocks where forced enforcement is required
    if policy.require_forced_enforcement:
        weak = [r for r in op.enforcement_records
                if r["boundary_outcome"] in ("BLOCKED", "HALTED")
                and not r["forced"]]
        add("A5_cooperative_only", "ATTENTION",
            f"{len(weak)} action(s) blocked by a mechanism that is not "
            f"independent of the agent",
            [x for r in weak for x in r["evidence_refs"]],
            AssuranceState.ATTENTION, RequiredAction.ALERT)
    # A6 — context moved
    if op.context_change_refs and "CONTEXT_UNCHANGED" not in \
            policy.acceptable_context_states or \
            (op.lifecycle_state == "CONTEXT_CHANGED"):
        add("A6_context_changed", "ATTENTION",
            "the evaluation context changed during operation",
            list(op.context_change_refs) or ([last_ledger] if last_ledger
                                             else []),
            AssuranceState.ATTENTION, RequiredAction.RE_EVALUATE)
    # A7 — outcomes resting on the boundary's word
    unc = [r for r in op.enforcement_records
           if r["corroboration"] == "UNCORROBORATED"]
    if policy.max_uncorroborated_enforcements is not None and \
            len(unc) > policy.max_uncorroborated_enforcements:
        add("A7_uncorroborated", "ATTENTION",
            f"{len(unc)} enforcement outcome(s) rest on the boundary's "
            f"report alone, above the declared limit of "
            f"{policy.max_uncorroborated_enforcements}",
            [x for r in unc for x in r["evidence_refs"]],
            AssuranceState.ATTENTION, RequiredAction.ALERT)
    # A8 — events with no known producer
    if policy.max_unattributed_events is not None and \
            len(op.unattributed_refs) > policy.max_unattributed_events:
        add("A8_unattributed", "ATTENTION",
            f"{len(op.unattributed_refs)} operational event(s) have no known "
            f"producer, above the declared limit",
            list(op.unattributed_refs),
            AssuranceState.ATTENTION, RequiredAction.ALERT)
    # A9 — faults
    if policy.max_faults is not None and \
            len(op.fault_refs) > policy.max_faults:
        add("A9_faults", "ATTENTION",
            f"{len(op.fault_refs)} fault(s) observed, above the declared "
            f"limit", list(op.fault_refs),
            AssuranceState.ATTENTION, RequiredAction.ALERT)
    # A10 — nothing observed at all
    observed = sum(n for _, n in op.event_counts)
    if policy.require_observation and observed == 0:
        add("A10_no_observation", "ATTENTION",
            "no operational evidence was recorded; nothing observed is not "
            "the same as nothing wrong",
            [last_ledger] if last_ledger else [],
            AssuranceState.UNDETERMINED, RequiredAction.ALERT)
    if outcomes:
        rule, state, action = outcomes[0]
    else:
        rule, state, action = ("A0_no_finding", AssuranceState.ASSURED,
                               RequiredAction.CONTINUE)
    return AssuranceAssessment(
        state=state, required_action=action, deciding_rule=rule,
        findings=tuple(findings),
        operational_passport_hash=op.operational_passport_hash,
        enrollment_hash=op.enrollment_hash,
        assurance_policy_id=policy.assurance_policy_id,
        assurance_policy_hash=policy.hash, as_of=as_of)
