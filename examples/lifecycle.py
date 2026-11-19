"""
From evidence to continuous assurance, end to end, with no network and no credentials.

    python examples/lifecycle.py

This walks the whole V2 chain with the public API only, and prints what each layer decided:

    baselines -> decision -> attestation -> policy document -> topology -> lineage
      -> readiness passport -> enrolment -> operational log -> enforcement
      -> operational passport -> assurance

The inputs are the two example baselines in examples/ci_gate/. Everything it prints is derived;
nothing is scored by this script. Each artefact is content-addressed, so `verify()` on any of them
tells you whether it was altered after it was made.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.dirname(HERE)]
os.environ.setdefault("HBEVAL_ALLOW_FAULT_INJECTION", "true")

from hb_eval_sdk.assurance import AssurancePolicy, assess_assurance
from hb_eval_sdk.attestation import attest
from hb_eval_sdk.baseline import ReliabilityBaseline
from hb_eval_sdk.context_assessment import INVALIDATING_FIELDS, NON_INVALIDATING_FIELDS, assess_context
from hb_eval_sdk.enforcement import (ActionKind, EnforcementPolicy, EnforcementRequest, EnforcementResult,
                                     Mechanism, Outcome, decide_enforcement, record_result)
from hb_eval_sdk.enforcement_evidence import ToolExecutionLog
from hb_eval_sdk.enrollment import (EnrollmentPolicy, activate, approve_enrollment, new_enrollment,
                                    request_enrollment)
from hb_eval_sdk.lineage import EvidenceAttribution, EvidenceLineage
from hb_eval_sdk.operational import OperationalRecorder
from hb_eval_sdk.operational_passport import derive_operational_passport
from hb_eval_sdk.policy_document import policy_document_from_slo
from hb_eval_sdk.readiness_passport import ScopeLevel, issue_readiness_passport
from hb_eval_sdk.reliability_decision import SLOCondition, SLOPolicy, decide
from hb_eval_sdk.reliability_diff import diff_baselines
from hb_eval_sdk.topology import Participant, ParticipantKind, Relation, RelationKind, SystemTopology


def load(name):
    with open(os.path.join(HERE, "ci_gate", name), encoding="utf-8") as fh:
        return ReliabilityBaseline.from_dict(json.load(fh))      # verifies the stored hash on the way in


def run(verbose=True):
    say = print if verbose else (lambda *a, **k: None)
    out = {}

    # 1. Evidence -> decision -> attestation. Two baselines are compared against an SLO policy.
    reference, candidate = load("ref.json"), load("cand.json")
    slo = SLOPolicy("org-v1", (SLOCondition("frr", "gte", 0.8),))
    decision = decide(diff_baselines(reference, candidate), slo)
    attestation = attest(decision, candidate)
    out["decision"] = decision.state
    say(f"1. decision against the SLO ........ {decision.state}")
    say(f"   attestation ..................... {attestation.attestation_id}  (verifies: {attestation.verify()['valid']})")

    # 2. The policy that produced the decision, as a content-addressed document.
    policy = policy_document_from_slo(slo)
    say(f"2. policy document ................. {policy.policy_id}  kind={policy.kind}")

    # 3. Who is in the system, and who did what.
    system = Participant(ParticipantKind.SYSTEM, "travel-system", system_id="sys-1")
    planner = Participant(ParticipantKind.AGENT, "planner", system_id="sys-1", agent_id="A", agent_instance_id="A#1")
    booker = Participant(ParticipantKind.SUB_AGENT, "booker", system_id="sys-1", agent_id="B", agent_instance_id="B#7")
    tool = Participant(ParticipantKind.TOOL, "payments", system_id="sys-1")
    delegation = Relation(RelationKind.DELEGATED_TO, planner.participant_id, booker.participant_id,
                          delegation_id="dlg-1", execution_id="EX-1")
    uses = Relation(RelationKind.USES_TOOL, booker.participant_id, tool.participant_id, execution_id="EX-1")
    topology = SystemTopology("sys-1", (system, planner, booker, tool), (delegation, uses))
    lineage = EvidenceLineage(topology, (
        EvidenceAttribution("STEP:1", planner.participant_id, "A#1", "EX-1", relation_ids=(delegation.relation_id,)),
        EvidenceAttribution("STEP:4", booker.participant_id, "B#7", "EX-1",
                            relation_ids=(delegation.relation_id, uses.relation_id))))
    say(f"3. topology / lineage .............. {topology.topology_id} / {lineage.lineage_id}")
    say(f"   who produced STEP:4 ............. {lineage.trace('STEP:4')}")

    # 4. A readiness passport: a pre-production decision, carried by reference.
    current = {f: getattr(attestation, f) for f in INVALIDATING_FIELDS + NON_INVALIDATING_FIELDS}
    context = assess_context(attestation, current)
    passport = issue_readiness_passport(
        attestation=attestation, subject_baseline=candidate, policy_document=policy, topology=topology,
        lineage=lineage, subject_participant_id=planner.participant_id, scope_level=ScopeLevel.AGENT,
        context_assessment=context)
    say(f"4. readiness passport .............. {passport.passport_id}  context={context.state}")

    # 5. Enrolment: the agent is admitted to production through an auditable state machine.
    enrol_policy = EnrollmentPolicy("enr-v1", accepted_policy_ids=(passport.policy_id,), max_passport_age_seconds=3600)
    t0 = attestation.produced_at
    enrolment = new_enrollment(enrol_policy, system_id=passport.system_id,
                               subject_participant_id=passport.subject_participant_id,
                               configuration_fingerprint=passport.configuration_fingerprint)
    enrolment = request_enrollment(enrolment, passport, now=t0 + 5)
    enrolment = approve_enrollment(enrolment, passport=passport, enrollment_policy=enrol_policy, attestation=attestation,
                                   policy_document=policy, topology=topology, lineage=lineage, now=t0 + 10,
                                   context_assessment=context)
    enrolment = activate(enrolment, enrollment_policy=enrol_policy, now=t0 + 20)
    out["enrolment"] = enrolment.state
    say(f"5. enrolment ....................... {enrolment.state}  (ledger of {len(enrolment.events)} events, "
        f"verifies: {enrolment.verify()['valid']})")

    # 6. In production: an enforcement boundary decides, observes, and records what happened.
    recorder = OperationalRecorder(topology=topology, enrollment=enrolment, execution_id="EX-1", session_id="SN-1",
                                   clock=lambda: t0 + 100)
    enforcement_policy = EnforcementPolicy("enf-v1", allowed_actions=(ActionKind.TOOL_CALL,),
                                           denied_targets=("payments.transfer",))
    request = EnforcementRequest.create(
        correlation_id="c1", action=ActionKind.TOOL_CALL, target="payments.transfer", arguments={"amount": 1000},
        participant_id=booker.participant_id, agent_instance_id="B#7", execution_id="EX-1", session_id="SN-1",
        enrollment_hash=enrolment.enrollment_hash, requested_at=t0 + 100)
    verdict = decide_enforcement(request, policy=enforcement_policy, enrollment=enrolment, topology=topology)
    result = EnforcementResult(decision_id=verdict.decision_id, decision_hash=verdict.hash, mechanism=Mechanism.SIDECAR,
                               outcome=Outcome.BLOCKED, observed_at=t0 + 101)
    event = record_result(request, verdict, result)
    recorder.record_enforcement(event)
    out["enforcement"] = (verdict.decision, event.conformance)
    say(f"6. enforcement ..................... {verdict.decision} by rule {verdict.rule!r}; "
        f"observed {result.outcome}; conformance {event.conformance}")

    # 7. An independent log kept by the tool itself corroborates (or contradicts) the boundary's claim.
    tool_log = ToolExecutionLog(tool="payments.transfer", window_start=t0 + 50, window_end=t0 + 200, complete=True,
                                observations=())                    # complete, and nothing executed
    op_passport = derive_operational_passport(readiness_passport=passport, enrollment=enrolment,
                                              operational_logs=(recorder.log(),), as_of=t0 + 5000,
                                              tool_logs=(tool_log,))
    say(f"7. operational passport ............ {op_passport.operational_passport_id}  (verifies: {op_passport.verify()['valid']})")

    # 8. Continuous assurance: a required ACTION, never a new score. It does not enforce anything itself.
    assessment = assess_assurance(op_passport, policy=AssurancePolicy("asr-v1"), as_of=op_passport.as_of + 10)
    out["assurance"] = (assessment.state, assessment.required_action)
    say(f"8. assurance ....................... {assessment.state} -> {assessment.required_action}  "
        f"(decided by {assessment.deciding_rule})")
    for rule, severity, statement, refs in assessment.findings:
        say(f"   finding {rule}: {statement}  [cites {len(refs)} record(s)]")
    return out


if __name__ == "__main__":
    run()
