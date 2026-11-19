# hb-eval-sdk user guide

Every `python` block in this guide is executed by the test suite (`tests/test_examples.py`), top to
bottom, in one shared namespace. If a block here stops working, CI fails. Blocks that are
illustrative only are fenced as `text`.

The guide follows the order in which you would adopt the SDK: **measure** an agent, **decide** whether
the measurement is good enough, then (optionally) **carry that decision into production** and keep
checking it. Nothing here needs an account, a network connection or an API key.

## 1. Install and look around

```text
pip install hb-eval-sdk
hb-eval version
hb-eval demo --fast        # a scripted agent degrading, watched and halted, fully offline
```

Python 3.9 or newer. The SDK has three dependencies (`requests`, `cryptography`, `pydantic`);
everything else is optional (`[mcp]`, `[otel]`).

## 2. Measure: fault injection and live monitoring

Fault injection breaks a tool on purpose and records, from outside the agent, what happened. It is
**off unless `HBEVAL_ALLOW_FAULT_INJECTION=true`**, so it cannot fire in production by accident.

```python
import os
os.environ["HBEVAL_ALLOW_FAULT_INJECTION"] = "true"

from hb_eval_sdk.faults import fault_context, wrap_tool
from hb_eval_sdk.evidence import evidence_for
from hb_eval_sdk.monitoring import MonitorSession


class OfflineClient:
    """Monitoring with nothing to send to: the session still measures, it just uploads nothing."""


def search(query):
    return {"hits": 3}


with MonitorSession(OfflineClient(), "demo-agent", stream=False) as session:
    with fault_context(session, "search", mode="error_5xx", http_status=503):
        try:
            wrap_tool(search, "search")("flights")
        except Exception as error:
            print("the agent saw:", type(error).__name__)
    session.record_step(action="search", success=False, had_fault=True, recovered_intentionally=False)

events = evidence_for(session, create=False).events
print([(e.intended_type, e.injection_status, e.observed_outcome) for e in events])
print("failure resilience so far:", session.live_metrics["frr"])
```

The evidence record is written by the instrumentation, not by the agent, and it is immutable once
written. That is the property the rest of the SDK builds on.

### Safe Halt

A session can stop an agent whose reliability is degrading. A halt policy is validated when the
session is created: a policy that is malformed, or names a metric that can never drive a live
decision, raises `ValueError` at once instead of silently doing nothing.

```python
with MonitorSession(OfflineClient(), "demo-agent", stream=False,
                    halt_policy={"metric": "frr", "below": 0.5, "for_steps": 3}) as guarded:
    for _ in range(3):
        guarded.record_step(action="call", success=False, had_fault=True, recovered_intentionally=False)
        if guarded.should_halt:
            break

print(guarded.should_halt, "-", guarded.halt_reason)
```

Rules in `policies=[...]` (retry, escalate, halt) are tolerant by design, so one typo cannot take down
the run the other rules protect. They are never *silently* tolerant: every rejected rule is logged as
a warning and listed, with the reason, in `session.summary["policy"]["dropped_policies"]`.

## 3. Decide: baselines, a policy, an attestation

A *baseline* is a sealed set of measurements. Comparing two baselines against an *SLO policy* gives a
decision that is exactly one of `PASS`, `FAIL` or `INCONCLUSIVE`. Evidence that cannot be compared is
`INCONCLUSIVE`; it is never rounded to a pass.

```python
import json
from hb_eval_sdk.baseline import ReliabilityBaseline
from hb_eval_sdk.reliability_decision import SLOCondition, SLOPolicy, decide
from hb_eval_sdk.reliability_diff import diff_baselines
from hb_eval_sdk.attestation import attest


def load(name):
    with open(os.path.join("examples", "ci_gate", name), encoding="utf-8") as fh:
        return ReliabilityBaseline.from_dict(json.load(fh))   # verifies the stored hash on the way in


reference, candidate = load("ref.json"), load("cand.json")
slo = SLOPolicy("org-v1", (SLOCondition("frr", "gte", 0.8),))
decision = decide(diff_baselines(reference, candidate), slo)
attestation = attest(decision, candidate)

print(decision.state, attestation.attestation_id, attestation.verify()["valid"])
```

The same comparison is available to CI with no code at all:

```text
hb-eval gate --reference-baseline ref.json --candidate-baseline cand.json --slo-policy slo.json --enforce
```

Exit codes: `0` pass (or fail in warn mode), `1` gate failed, `2` usage or configuration error
(a missing credential is not a reliability failure), `3` inconclusive, `4` recertification required.

## 4. The V2 chain: from a decision to production assurance

Each layer below consumes the previous one and **adds no score of its own**. Every artefact is
content-addressed: `verify()` returns `{"valid": bool, "problems": [...]}` and tells you whether it was
altered after it was made.

| Layer | Module | What it is | What it refuses |
|---|---|---|---|
| R1 | `policy_document` | A policy (runtime or SLO) as one content-addressed document | An id that was assigned rather than derived from the content |
| R2 | `topology` | Who is in the system and how they relate (delegation, tool use) | Relations to participants that do not exist |
| R3 | `lineage` | Which participant produced which evidence | A producer the topology does not contain |
| R4 | `readiness_passport` | A pre-production decision, carried by reference | Issuing on inconsistent inputs; issuing `VERIFIED` (only the platform can) |
| R5 | `enrollment` | An auditable state machine for admitting an agent to production | Any transition not in the table; activating on an expired passport |
| R6 | `operational` | A hash-chained log of what happened in production | Events an agent could fabricate (enforcement, enrolment changes) |
| R7 | `operational_passport` | What the system was observed doing while enrolled | Deriving from an artefact that does not verify |
| R8 | `enforcement` | A boundary that decides and observes, outside the agent | Calling a cooperative block "independent" |
| R9 | `enforcement_evidence` | Enforcement as evidence, corroborated by the tool's own log | Treating the boundary's word as proof |
| R10 | `assurance` | A required *action* (continue, alert, enforce, re-evaluate) | Inventing a verdict, a grade or a score |

The submodules are public API. Import them by name: `from hb_eval_sdk import enrollment`.

### 4.1 Policy, topology, lineage

```python
from hb_eval_sdk.policy_document import policy_document_from_slo
from hb_eval_sdk.topology import Participant, ParticipantKind, Relation, RelationKind, SystemTopology
from hb_eval_sdk.lineage import EvidenceAttribution, EvidenceLineage

policy = policy_document_from_slo(slo)

system = Participant(ParticipantKind.SYSTEM, "travel-system", system_id="sys-1")
planner = Participant(ParticipantKind.AGENT, "planner", system_id="sys-1", agent_id="A", agent_instance_id="A#1")
booker = Participant(ParticipantKind.SUB_AGENT, "booker", system_id="sys-1", agent_id="B", agent_instance_id="B#7")
payments = Participant(ParticipantKind.TOOL, "payments", system_id="sys-1")

delegation = Relation(RelationKind.DELEGATED_TO, planner.participant_id, booker.participant_id,
                      delegation_id="dlg-1", execution_id="EX-1")
uses = Relation(RelationKind.USES_TOOL, booker.participant_id, payments.participant_id, execution_id="EX-1")
topology = SystemTopology("sys-1", (system, planner, booker, payments), (delegation, uses))

lineage = EvidenceLineage(topology, (
    EvidenceAttribution("STEP:1", planner.participant_id, "A#1", "EX-1", relation_ids=(delegation.relation_id,)),
    EvidenceAttribution("STEP:4", booker.participant_id, "B#7", "EX-1",
                        relation_ids=(delegation.relation_id, uses.relation_id)),
))

trace = lineage.trace("STEP:4")
print(trace.participant_name, "via", [(kind, source, target) for kind, source, target, *_ in trace.relationships])
```

A lineage that has been altered after it was built does not crash `trace()` with an obscure error: it
raises `LineageError` and says the lineage has been altered or mismatched.

### 4.2 A readiness passport and enrolment

```python
from hb_eval_sdk.context_assessment import INVALIDATING_FIELDS, NON_INVALIDATING_FIELDS, assess_context
from hb_eval_sdk.readiness_passport import ScopeLevel, issue_readiness_passport
from hb_eval_sdk.enrollment import (EnrollmentPolicy, activate, approve_enrollment, new_enrollment,
                                    request_enrollment)

# Has the context the decision was made in changed? Here it has not.
current = {f: getattr(attestation, f) for f in INVALIDATING_FIELDS + NON_INVALIDATING_FIELDS}
context = assess_context(attestation, current)

passport = issue_readiness_passport(
    attestation=attestation, subject_baseline=candidate, policy_document=policy, topology=topology,
    lineage=lineage, subject_participant_id=planner.participant_id, scope_level=ScopeLevel.AGENT,
    context_assessment=context)

enrol_policy = EnrollmentPolicy("enr-v1", accepted_policy_ids=(passport.policy_id,), max_passport_age_seconds=3600)
t0 = attestation.produced_at
enrolment = new_enrollment(enrol_policy, system_id=passport.system_id,
                           subject_participant_id=passport.subject_participant_id,
                           configuration_fingerprint=passport.configuration_fingerprint)
enrolment = request_enrollment(enrolment, passport, now=t0 + 5)
enrolment = approve_enrollment(enrolment, passport=passport, enrollment_policy=enrol_policy,
                               attestation=attestation, policy_document=policy, topology=topology,
                               lineage=lineage, now=t0 + 10, context_assessment=context)
enrolment = activate(enrolment, enrollment_policy=enrol_policy, now=t0 + 20)

print(enrolment.state, len(enrolment.events), "ledger events,", enrolment.verify()["valid"])
```

The state is never stored. It is derived by replaying the ledger, so it cannot disagree with its own
history. `suspend`, `resume`, `revoke`, `check_expiry` and `resubmit` are the other transitions.

### 4.3 Enforcement and the operational record

```python
from hb_eval_sdk.operational import OperationalRecorder
from hb_eval_sdk.enforcement import (ActionKind, EnforcementPolicy, EnforcementRequest, EnforcementResult,
                                     Mechanism, Outcome, decide_enforcement, record_result)

recorder = OperationalRecorder(topology=topology, enrollment=enrolment, execution_id="EX-1",
                               session_id="SN-1", clock=lambda: t0 + 100)
enforcement_policy = EnforcementPolicy("enf-v1", allowed_actions=(ActionKind.TOOL_CALL,),
                                       denied_targets=("payments.transfer",))

request = EnforcementRequest.create(
    correlation_id="c1", action=ActionKind.TOOL_CALL, target="payments.transfer", arguments={"amount": 1000},
    participant_id=booker.participant_id, agent_instance_id="B#7", execution_id="EX-1", session_id="SN-1",
    enrollment_hash=enrolment.enrollment_hash, requested_at=t0 + 100)
verdict = decide_enforcement(request, policy=enforcement_policy, enrollment=enrolment, topology=topology)

# The boundary reports what it OBSERVED happen. Policy and observation are separate facts.
result = EnforcementResult(decision_id=verdict.decision_id, decision_hash=verdict.hash,
                           mechanism=Mechanism.SIDECAR, outcome=Outcome.BLOCKED, observed_at=t0 + 101)
event = record_result(request, verdict, result)
recorder.record_enforcement(event)

print(verdict.decision, "by", verdict.rule, "| observed", result.outcome, "| conformance", event.conformance)
```

`conformance` compares the decision with the observation. `CONFORMANT` means they agreed. A denied
request that executed anyway is a `BREACH`; an allowed one that was blocked is `OVER_ENFORCEMENT`.
A mechanism that runs inside the agent (`IN_PROCESS_COOPERATIVE`) is always recorded as **not
independent**: it can only ever be an observation, never proof of enforcement.

An agent cannot author its own enforcement evidence. Trying to record an `ENFORCEMENT` event as the
agent raises `OperationalError`; only a sealed enforcement record can be added.

### 4.4 The operational passport and assurance

```python
from hb_eval_sdk.enforcement_evidence import ToolExecutionLog
from hb_eval_sdk.operational_passport import derive_operational_passport
from hb_eval_sdk.assurance import AssurancePolicy, assess_assurance

# The tool keeps its own log. It is complete and shows nothing executed, which corroborates the block.
tool_log = ToolExecutionLog(tool="payments.transfer", window_start=t0 + 50, window_end=t0 + 200,
                            complete=True, observations=())
operational = derive_operational_passport(readiness_passport=passport, enrollment=enrolment,
                                          operational_logs=(recorder.log(),), as_of=t0 + 5000,
                                          tool_logs=(tool_log,))
assessment = assess_assurance(operational, policy=AssurancePolicy("asr-v1"), as_of=operational.as_of + 10)

print(assessment.state, "->", assessment.required_action, "| decided by", assessment.deciding_rule)
for rule, severity, statement, evidence in assessment.findings:
    print(" ", rule, "-", statement, f"[cites {len(evidence)}]")
```

`assess_assurance` returns a *required action*; it never takes one. `ENFORCE` means "someone must
apply the policy", not "this function applied it". Every finding cites the records it rests on, and
"nothing was observed" is `UNDETERMINED`, which is deliberately not the same as `ASSURED`.

The complete walk-through, with narration, is `examples/lifecycle.py`.

## 5. Talking to the Gateway

```text
export HBEVAL_API_KEY=...  HBEVAL_AES_KEY=...  HBEVAL_SIGNING_SECRET=...
```

```python
import base64
from hb_eval_sdk import HBEvalClient

key = base64.b64encode(bytes(range(32))).decode()          # demonstration key material only
client = HBEvalClient(api_key="demo", aes_key=key, signing_secret=key, gateway_url="https://gateway.example.com")
print(client.gateway_url, client.max_retries, client.timeout)
```

- Requests are AES-256-GCM encrypted and HMAC-signed with a **separate** secret. See `docs/PROTOCOL.md`
  and the conformance vectors in `docs/protocol_vectors.json`.
- The gateway URL must be `https`. Plain `http` is accepted only for loopback, or with
  `allow_insecure_http=True`, because every request carries your API key.
- If the Gateway is unreachable the client raises `SafeHaltError`. It never returns a default verdict.
  A response with no verdict is `UNSAFE`.
- The wire protocol and the measurement protocol are different numbers, on purpose. See
  `docs/PROTOCOL.md` §1, and `hb_eval_sdk.protocol` for the compatibility rule.

## 6. Where the limits are

Read `SECURITY.md` and `docs/THREAT_MODEL.md`. The short version: the instrumentation shares a
process with the agent, so it is evidence rather than a sandbox; attestations are unsigned and
unanchored in this package; and these metrics describe observed behaviour, they do not predict
production failures.
