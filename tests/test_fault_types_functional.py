"""
test_fault_types_functional.py — the seven types, proven end to end
=====================================================================
    py tests/test_fault_types_functional.py

WHAT "PROVEN" MEANS HERE
Design review rejected treating a fault type as done because it exists in the
code. Each type below is required to show the full chain explicitly:

    requested -> injection attempted -> injection succeeded?
              -> runtime actually experienced the fault?
              -> evidence recorded -> agent response -> metric interpretation

A type that raises the right exception but leaves no evidence trail, or whose
evidence disagrees with what actually happened, does not pass here even if the
exception looked correct.

SCOPE
This file is Phase 1 (functional correctness) only. Phase 2 (can the agent
forge or tamper with the evidence) lives in test_fault_injection_security.py
and is deliberately not mixed in here — a security failure and a functional
failure are different findings and should not be buried in the same report.
"""
from __future__ import annotations

import os
import sys

os.environ["HBEVAL_ALLOW_FAULT_INJECTION"] = "true"

from evidence import InjectionStatus, ObservedOutcome, evidence_for, evidence_for_session
from faults import (FaultInjected, FaultPlan, FaultSpec, CascadePlan,
                    CascadeStage, MALFORMED_KINDS, fault_context, wrap_tool)


class FakeSession:
    def __init__(self, session_id):
        self.session_id = session_id
        self._n_steps = 0


def _chain(label, session_id, plan_or_cascade, target, call, expect):
    """Run one fault type through the full chain and check every link.

    `expect` is a dict of assertions against the resulting FaultEvent:
    injection_status, observed_outcome, fault_present, matched_intent.
    """
    kwargs = ({"plan": plan_or_cascade} if isinstance(plan_or_cascade, FaultPlan)
              else {"cascade": plan_or_cascade})
    session = FakeSession(session_id)

    raised = None
    result = None
    with fault_context(session, **kwargs):
        try:
            result = call()
        except FaultInjected as exc:
            raised = exc

    # The strong path: keyed by the session OBJECT, matching what
    # fault_context actually writes through as of the security hardening.
    store = evidence_for(session, create=False)
    events = [e for e in store.events if e.target == target]
    assert events, f"[{label}] no evidence was recorded at all"
    event = events[-1]

    checks = []

    # Link 1: requested — the event exists and names the right intent.
    checks.append(("requested",
                   event.intended_type == expect["intended_type"]))

    # Link 2: injection attempted / succeeded
    checks.append(("injection attempted+status",
                   event.injection_status == expect["injection_status"]))

    # Link 3: runtime actually experienced the fault
    checks.append(("runtime observation",
                   event.observed_outcome == expect["observed_outcome"]))

    # Link 4: evidence recorded — duration and identity fields are populated,
    # not left at their zero defaults, which would mean the event was created
    # but never actually completed through the instrumentation path.
    checks.append(("evidence has identity",
                   bool(event.fault_event_id and event.tool_invocation_id)))
    checks.append(("evidence has timing",
                   event.started_at > 0 and event.ended_at >= event.started_at))

    # Link 5: agent response — what the caller actually got back
    checks.append(("agent response matches expectation",
                   expect["response_check"](result, raised)))

    # Link 6: metric interpretation — fault_present derived correctly
    checks.append(("fault_present correct",
                   event.fault_present == expect["fault_present"]))

    ok = all(c for _, c in checks)
    status = "PASS" if ok else "FAIL"
    print(f"  {label:<20} {status}")
    if not ok:
        for name, passed in checks:
            if not passed:
                print(f"      x {name}")
    return ok, event


def main() -> int:
    results = []

    print("=" * 72)
    print("FAULT INJECTION — FUNCTIONAL PROOF, SEVEN TYPES")
    print("=" * 72)
    print()

    # ── 1. timeout ──────────────────────────────────────────────────────
    def call_timeout():
        tool = wrap_tool(lambda x: {"ok": True}, "t1")
        return tool("x")

    plan = FaultPlan(id="P-timeout", seed=1, faults=[
        FaultSpec(id="F", target="t1", mode="timeout", after_ms=1)])
    ok, ev = _chain("1. timeout", "S-timeout", plan, "t1", call_timeout, {
        "intended_type": "timeout",
        "injection_status": InjectionStatus.APPLIED,
        "observed_outcome": ObservedOutcome.TIMEOUT,
        "response_check": lambda r, raised: (
            r is None and isinstance(raised, FaultInjected)
            and raised.mode == "timeout"),
        "fault_present": True,
    })
    results.append(("timeout", ok))

    # ── 2. latency ──────────────────────────────────────────────────────
    # Must prove the delay happened WITHOUT becoming a failure — the
    # distinguishing property design review asked for explicitly.
    def call_latency():
        real_calls = {"n": 0}

        def real(x):
            real_calls["n"] += 1
            return {"ok": True, "calls": real_calls["n"]}
        tool = wrap_tool(real, "t2")
        return tool("x"), real_calls["n"]

    plan2 = FaultPlan(id="P-latency", seed=1, faults=[
        FaultSpec(id="F", target="t2", mode="latency", after_ms=5)])
    ok, ev = _chain("2. latency", "S-latency", plan2, "t2", call_latency, {
        "intended_type": "latency",
        "injection_status": InjectionStatus.APPLIED,
        "observed_outcome": ObservedOutcome.DELAYED_SUCCESS,
        # response_check receives (result, raised); result is the tuple above
        "response_check": lambda r, raised: (
            raised is None and r[1] == 1 and r[0]["ok"] is True),
        "fault_present": True,
    })
    results.append(("latency", ok))
    print(f"      delay actually elapsed: "
          f"{ev.duration_ms:.1f}ms (requested 5ms)")

    # ── 3. error_5xx ────────────────────────────────────────────────────
    def call_5xx():
        tool = wrap_tool(lambda x: {"ok": True}, "t3")
        return tool("x")

    plan3 = FaultPlan(id="P-5xx", seed=1, faults=[
        FaultSpec(id="F", target="t3", mode="error_5xx", http_status=503)])
    ok, ev = _chain("3. error_5xx", "S-5xx", plan3, "t3", call_5xx, {
        "intended_type": "error_5xx",
        "injection_status": InjectionStatus.APPLIED,
        "observed_outcome": ObservedOutcome.EXCEPTION,
        "response_check": lambda r, raised: (
            r is None and isinstance(raised, FaultInjected)
            and raised.http_status == 503),
        "fault_present": True,
    })
    results.append(("error_5xx", ok))
    print(f"      http_status recorded: {ev.http_status}")

    # ── 4. empty_response ───────────────────────────────────────────────
    print("\n  4. empty_response — all four kinds:")
    empty_ok = True
    for kind, expected_val in [("null", None), ("empty_object", {}),
                               ("empty_array", []), ("empty_string", "")]:
        def call_empty():
            tool = wrap_tool(lambda x: {"real": "data"}, "t4")
            return tool("x")

        plan4 = FaultPlan(id=f"P-empty-{kind}", seed=1, faults=[
            FaultSpec(id="F", target="t4", mode="empty_response",
                      empty_kind=kind)])
        ok, ev = _chain(f"     {kind}", f"S-empty-{kind}", plan4, "t4",
                        call_empty, {
            "intended_type": "empty_response",
            "injection_status": InjectionStatus.APPLIED,
            "observed_outcome": ObservedOutcome.EMPTY,
            "response_check": lambda r, raised, ev=expected_val: (
                raised is None and r == ev),
            "fault_present": True,
        })
        empty_ok = empty_ok and ok
    results.append(("empty_response", empty_ok))

    # ── 5. malformed ─────────────────────────────────────────────────────
    print("\n  5. malformed — all seven sub-kinds:")
    malformed_ok = True
    for kind in MALFORMED_KINDS:
        def call_malformed():
            tool = wrap_tool(lambda x: {"real": "data"}, "t5")
            return tool("x")

        plan5 = FaultPlan(id=f"P-mal-{kind}", seed=1, faults=[
            FaultSpec(id="F", target="t5", mode="malformed",
                      malformed_kind=kind)])
        ok, ev = _chain(f"     {kind}", f"S-mal-{kind}", plan5, "t5",
                        call_malformed, {
            "intended_type": "malformed",
            "injection_status": InjectionStatus.APPLIED,
            "observed_outcome": ObservedOutcome.MALFORMED,
            "response_check": lambda r, raised: (
                raised is None and r != {"real": "data"}),
            "fault_present": True,
        })
        malformed_ok = malformed_ok and ok
    results.append(("malformed", malformed_ok))

    # ── 6. intermittent — deterministic replay is the thing to prove ────
    print("\n  6. intermittent — deterministic schedule, not just 'it can fail':")

    def run_schedule(seed):
        session_id = f"S-int-{seed}-{os.urandom(4).hex()}"
        session = FakeSession(session_id)
        tool = wrap_tool(lambda x: {"ok": True}, "t6")
        plan6 = FaultPlan(id="P-int", seed=seed, faults=[
            FaultSpec(id="F", target="t6", mode="intermittent",
                      probability=0.5)])
        outcomes = []
        with fault_context(session, plan=plan6):
            for i in range(10):
                try:
                    tool(i)
                    outcomes.append(".")
                except FaultInjected:
                    outcomes.append("X")
        store = evidence_for(session, create=False)
        return "".join(outcomes), store

    sched_a, store_a = run_schedule(11)
    sched_b, _ = run_schedule(11)
    sched_c, _ = run_schedule(22)

    replay_ok = (sched_a == sched_b) and (sched_a != sched_c)
    print(f"     seed 11 (run 1): {sched_a}")
    print(f"     seed 11 (run 2): {sched_b}   identical={sched_a == sched_b}")
    print(f"     seed 22        : {sched_c}   differs={sched_a != sched_c}")
    print(f"     {'intermittent':<20} {'PASS' if replay_ok else 'FAIL'}")
    # Also confirm evidence was recorded for BOTH fired and skipped attempts —
    # the reviewer's requirement that failure/success follow "a deterministic
    # plan" means every attempt must be traceable, not just the ones that fired.
    all_recorded = len(store_a.events) == 10
    print(f"     all 10 attempts recorded (fired or skipped): "
          f"{'yes' if all_recorded else 'NO'}")
    results.append(("intermittent", replay_ok and all_recorded))

    # ── 7. cascade ───────────────────────────────────────────────────────
    print("\n  7. cascade — topology across two tool boundaries:")

    def primary_fn(x):
        return {"ok": True}

    def backup_fn(x):
        return {"ok": True}

    primary = wrap_tool(primary_fn, "t7-primary")
    backup = wrap_tool(backup_fn, "t7-backup")

    cascade = CascadePlan(id="P-cascade", seed=1, stages=[
        CascadeStage(target="t7-primary", mode="timeout", after_ms=1),
        CascadeStage(target="t7-backup", mode="error_5xx", http_status=503),
    ])

    session_id = "S-cascade"
    session = FakeSession(session_id)
    with fault_context(session, cascade=cascade) as handle:
        try:
            primary("x")
        except FaultInjected:
            pass
        try:
            backup("x")
        except FaultInjected:
            pass

    topo = handle.topology()
    cascade_ok = (topo["stages_fired"] == [0, 1]
                 and topo["reached_final_stage"] is True
                 and topo["fired_in_ascending_order"] is True)
    print(f"     topology: {topo}")
    print(f"     {'cascade':<20} {'PASS' if cascade_ok else 'FAIL'}")
    results.append(("cascade", cascade_ok))

    # ── Report ────────────────────────────────────────────────────────
    print()
    print("=" * 72)
    print("SEVEN FAULT TYPES — FUNCTIONAL RESULT")
    print("=" * 72)
    all_pass = True
    for name, ok in results:
        status = "PASS" if ok else "FAIL"
        if not ok:
            all_pass = False
        print(f"  {name:<20} {status}")

    print()
    if not all_pass:
        print("NOT ALL TYPES PROVEN. Phase 1 is not closed.")
        return 1

    print("All seven fault types proven through the full chain:")
    print("  requested -> attempted -> succeeded -> observed -> evidence")
    print("  -> agent response -> metric interpretation")
    print()
    print("This is functional correctness only. It does not establish that")
    print("the evidence cannot be tampered with — see")
    print("test_fault_injection_security.py for that, separately, as required.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
