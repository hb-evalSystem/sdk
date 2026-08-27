"""
test_fault_injection_security.py — Phase 2, standalone, as required
=====================================================================
    py tests/test_fault_injection_security.py

WHY THIS FILE IS SEPARATE FROM FUNCTIONAL TESTS
Design review was explicit: a functional pass and a security pass are
different findings, and burying an adversarial result inside a functional
report hides it. This file answers exactly seven questions, in the reviewer's
own wording, and nothing else:

    1. Can the agent change runtime_observed (i.e. mutate a committed event)?
    2. Can the agent pass source= to force its own provenance label?
    3. Can the agent change `injected` status after the fact?
    4. Can the agent forge session_id to write into another session's store?
    5. Can the agent delete evidence?
    6. Can the agent make a failed injection appear to have succeeded?
    7. Do results change if the agent tampers with the state?

THE RULE THIS FILE ENFORCES
"If the security test fails, Real Runtime Fault Injection is not considered
closed." A failure here is not a warning — it is a blocking finding, and this
file's exit code says so.

WHAT PASSING HERE DOES NOT MEAN
It does not mean the layer is secure against a determined adversary with full
reflection access to the Python process. No in-process design provides that,
and every test below that closes a vector says explicitly what it closes and
what it does not. Test 8 is not one of the reviewer's seven; it exists to
state the acknowledged residual limit honestly rather than let its absence
imply the other seven add up to a complete security boundary.
"""
from __future__ import annotations

import dataclasses
import os
import sys

os.environ["HBEVAL_ALLOW_FAULT_INJECTION"] = "true"

from evidence import (FaultEvent, PendingFaultEvent, InjectionStatus,
                      ObservedOutcome, evidence_for, evidence_for_session,
                      new_event, seal)
from faults import FaultPlan, FaultSpec, fault_context, wrap_tool, FaultInjected


class FakeSession:
    def __init__(self, session_id):
        self.session_id = session_id
        self._n_steps = 0


def _setup_one_fault(session_id="S-SEC"):
    """Produce one real, committed fault event to attack.

    Returns (store, session) — the session object is needed by callers that
    use the strong evidence_for() lookup, which is now the real path.
    """
    tool = wrap_tool(lambda x: {"ok": True}, "api")
    plan = FaultPlan(id="SEC", seed=1, faults=[
        FaultSpec(id="F", target="api", mode="timeout", after_ms=1)])
    session = FakeSession(session_id)
    with fault_context(session, plan=plan):
        try:
            tool("x")
        except FaultInjected:
            pass
    return evidence_for(session, create=False), session


def main() -> int:
    findings = []   # (question_number, description, closed: bool, note: str)

    print("=" * 72)
    print("FAULT INJECTION — SECURITY, PHASE 2 (standalone)")
    print("=" * 72)
    print()
    print("Seven questions. Each is a blocking finding if it fails.")
    print()

    # ══ 1. Change a committed event's runtime_observed field? ═══════════
    print("[1] Can the agent change a committed event's fields "
          "(e.g. runtime_observed / observed_outcome)?")
    store, _sess1 = _setup_one_fault("S-Q1")
    event = store.events[0]
    original = event.observed_outcome
    closed = False
    try:
        event.observed_outcome = ObservedOutcome.NORMAL
        print(f"    result: MUTATED to {event.observed_outcome!r} — OPEN")
    except dataclasses.FrozenInstanceError as e:
        closed = True
        print(f"    result: rejected ({type(e).__name__}) — CLOSED")
    findings.append((1, "mutate committed event field", closed,
                     "FaultEvent is frozen; assignment raises"))

    # ══ 2. Can the agent pass source= to force its own provenance? ══════
    print("\n[2] Can the agent pass source= to fault_context/wrap_tool to "
          "set its own provenance label?")
    import inspect
    import faults as faults_module
    sig_fc = str(inspect.signature(faults_module.fault_context))
    sig_wt = str(inspect.signature(faults_module.wrap_tool))
    has_source_param = "source" in sig_fc or "source" in sig_wt
    closed = not has_source_param
    print(f"    fault_context signature: {sig_fc}")
    print(f"    wrap_tool signature:     {sig_wt}")
    print(f"    result: {'no source= parameter exists — CLOSED' if closed else 'OPEN'}")
    findings.append((2, "supply source= as caller", closed,
                     "no such parameter in the public API"))

    # ══ 3. Can the agent change injection_status after the fact? ════════
    print("\n[3] Can the agent change `injected` / injection_status after "
          "the event was committed?")
    store3, _sess3 = _setup_one_fault("S-Q3")
    ev3 = store3.events[0]
    original_status = ev3.injection_status
    closed = False
    try:
        ev3.injection_status = InjectionStatus.FAILED
        print(f"    result: CHANGED to {ev3.injection_status!r} — OPEN")
    except dataclasses.FrozenInstanceError:
        closed = True
        print(f"    result: rejected — CLOSED "
              f"(still {original_status!r})")
    findings.append((3, "mutate injection_status post-commit", closed,
                     "same freeze as [1]; same mechanism"))

    # ══ 4. Can the agent forge session_id to reach another session? ═════
    print("\n[4] Can the agent forge/guess a session_id STRING to reach "
          "another session's real evidence store?")
    victim_store, victim_session = _setup_one_fault("S-VICTIM-SECRET-ID")
    victim_id_string = victim_session.session_id
    print(f"    victim's session_id string (assume the attacker somehow "
          f"obtained this, e.g. from a log line): {victim_id_string!r}")

    # This is the actual attack: the attacker has ONLY the string, not the
    # live victim session object (they were never handed it — different
    # session, different code, different part of the same process).
    attacker_store = evidence_for_session(victim_id_string, create=False)

    # Two things must both hold for this to be closed:
    #   a) the weak, string-keyed lookup must NOT return the real store
    #   b) it must not even auto-create an empty stand-in that could be
    #      confused for the real one downstream
    reached_real_evidence = (
        attacker_store is not None
        and attacker_store.summary()["events_recorded"] > 0
        and attacker_store is victim_store)
    print(f"    evidence_for_session(victim_id_string) result: "
          f"{'DOES reach real evidence — OPEN' if reached_real_evidence else 'returns nothing usable — CLOSED'}")
    if attacker_store is not None:
        print(f"      (a store WAS returned, but events_recorded="
              f"{attacker_store.summary()['events_recorded']}, and it is "
              f"{'the same object as' if attacker_store is victim_store else 'a DIFFERENT, unrelated object from'} "
              f"the victim's real store)")

    closed4 = not reached_real_evidence
    findings.append((4, "forge/guess session_id string to reach another "
                     "session's evidence", closed4,
                     "real evidence is written via evidence_for(session_OBJECT), "
                     "keyed by Python object identity — a different keyspace "
                     "entirely from evidence_for_session(string). Knowing the "
                     "string reaches, at most, an empty, unrelated store in the "
                     "weak registry, never the real one."))

    # ══ 5. Can the agent delete evidence? ════════════════════════════════
    print("\n[5] Can the agent delete evidence from the store?")
    store5, _sess5 = _setup_one_fault("S-Q5")
    before = len(store5.events)

    print(f"    store5.events is a: {type(store5.events).__name__} "
          f"(tuple -- no .append/.clear/.remove exist on it)")

    # Attempt 1: mutate through the public `events` property's return value.
    attempt1_blocked = False
    try:
        store5.events.clear()
        print("    store5.events.clear() -> succeeded — OPEN")
    except AttributeError as e:
        attempt1_blocked = True
        print(f"    store5.events.clear() -> {type(e).__name__} — blocked")

    # Attempt 2: the vector that was OPEN before this fix — reach the
    # backing list directly as an instance attribute.
    attempt2_blocked = False
    try:
        store5._events.clear()
        print("    store5._events.clear() -> succeeded — OPEN "
              "(this was the actual finding before the fix)")
    except AttributeError as e:
        attempt2_blocked = True
        print(f"    store5._events.clear() -> {type(e).__name__} — blocked "
              f"(no such attribute exists on the instance anymore)")

    after = len(evidence_for(_sess5, create=False).events)
    unaffected = (after == before)
    print(f"    events before={before}, after both attempts={after} "
          f"({'unaffected' if unaffected else 'CHANGED'})")

    closed5 = attempt1_blocked and attempt2_blocked and unaffected
    findings.append((5, "delete evidence from the store", closed5,
                     "the events list is no longer an instance attribute at "
                     "all (moved to a module-private id()-keyed dict); "
                     "`store._events` raises AttributeError rather than "
                     "exposing a mutable list to clear"))

    # ══ 6. Can the agent make a failed injection appear successful? ═════
    print("\n[6] Can the agent make a failed injection APPEAR successful "
          "(or vice versa) after the fact?")

    # 6a — mutate an already-committed event's status (same mechanism as [1]/[3])
    store6b, _sess6 = _setup_one_fault("S-Q6")
    ev6 = store6b.events[0]
    mutation_closed = False
    try:
        ev6.injection_status = InjectionStatus.APPLIED
        print(f"    6a  mutate committed status: succeeded — OPEN")
    except dataclasses.FrozenInstanceError:
        mutation_closed = True
        print(f"    6a  mutate committed status: rejected — CLOSED")

    # 6b — the vector 6a does NOT cover: fabricate an entirely NEW event
    # claiming success where none occurred, and inject it directly via
    # record(), bypassing the dispatch path (and its token) entirely. An
    # earlier version of this security suite verified this manually during
    # development and then never encoded it as an assertion — which meant a
    # deliberate breakage of the token check in evidence.record() still
    # reported "CONFORMANCE PASSED", because nothing here actually exercised
    # that specific line. Encoded now so that gap cannot recur silently.
    fabricated = new_event(target="api-fabricated", intended_type="error_5xx",
                           intended_params={})
    fabricated.injection_status = InjectionStatus.APPLIED
    fabricated.observed_outcome = ObservedOutcome.EXCEPTION
    fabricated.started_at = fabricated.ended_at = 1.0
    sealed_fake = seal(fabricated)
    injection_closed = False
    try:
        store6b.record(sealed_fake)   # NOTE: no _token= passed at all
        print(f"    6b  inject fabricated event, no token: "
              f"succeeded — OPEN (this is the exact attack the token gate "
              f"exists to stop)")
    except PermissionError as e:
        injection_closed = True
        print(f"    6b  inject fabricated event, no token: "
              f"rejected ({type(e).__name__}) — CLOSED")

    # 6c — the derivation itself: even setting aside the two structural
    # protections above, a genuinely FAILED injection must never derive
    # fault_present=True. Backstops 6a/6b rather than replacing them.
    failed_ev = new_event(target="x", intended_type="timeout",
                          intended_params={})
    failed_ev.injection_status = InjectionStatus.FAILED
    failed_ev.observed_outcome = ObservedOutcome.NORMAL
    derivation_correct = failed_ev.fault_present is False
    print(f"    6c  failed injection's fault_present = "
          f"{failed_ev.fault_present} "
          f"({'CORRECT' if derivation_correct else 'WRONG'})")

    closed = mutation_closed and injection_closed and derivation_correct
    findings.append((6, "disguise failed injection as successful", closed,
                     "6a: committed events are frozen. 6b: record() without "
                     "the instrumentation token is rejected, closing direct "
                     "fabrication-and-injection. 6c: the fault_present "
                     "derivation independently refuses a failed injection "
                     "regardless of what the caller claims."))

    # ══ 7. Do results change if the agent tampers with SESSION state? ═══
    print("\n[7] Do the recorded results change if the agent tampers with "
          "objects it legitimately holds (e.g. the MonitorSession)?")
    session7 = FakeSession("S-Q7")
    tool7 = wrap_tool(lambda x: {"ok": True}, "api")
    plan7 = FaultPlan(id="P7", seed=1, faults=[
        FaultSpec(id="F", target="api", mode="timeout", after_ms=1)])
    with fault_context(session7, plan=plan7):
        try:
            tool7("x")
        except FaultInjected:
            pass
        # Agent has full read/write access to its own session object —
        # that is normal and expected. Tamper with everything on it.
        session7.session_id = "SOMETHING-ELSE"
        session7._n_steps = 99999
        for attr in list(vars(session7)):
            pass  # already covered above; session objects are simple here

    store7 = evidence_for(session7, create=False)
    unaffected = (len(store7.events) == 1
                 and store7.events[0].observed_outcome == ObservedOutcome.TIMEOUT
                 and store7.events[0].session_id == "S-Q7")
    print(f"    result: evidence store for the ORIGINAL session_id "
          f"{'unaffected by tampering with the session object — CLOSED' if unaffected else 'CHANGED — OPEN'}")
    findings.append((7, "results change when agent tampers with session",
                     unaffected,
                     "the evidence store is keyed and populated at the "
                     "moment of injection, before any tampering could occur; "
                     "later changes to the session object do not reach "
                     "already-recorded events"))

    # ══ 8. The acknowledged residual limit (not one of the seven, stated
    #        for honesty) ═══════════════════════════════════════════════
    print("\n[8] (Not one of the seven — stated for completeness) Can code "
          "with full reflection access defeat the token gate?")
    import faults as fm
    reachable = hasattr(fm, "_TOKEN")
    print(f"    faults._TOKEN is reachable via `import faults; faults._TOKEN`: "
          f"{reachable}")
    print("    This is not treated as a failure. It is the acknowledged "
          "limit: no in-process design stops code with full reflection "
          "access to the same Python process. Stated here rather than "
          "implied by omission.")

    # ── Report ──────────────────────────────────────────────────────────
    print()
    print("=" * 72)
    print("SECURITY MATRIX — RESULT")
    print("=" * 72)
    blocking = []
    for num, desc, closed, note in findings:
        status = "CLOSED" if closed else "OPEN"
        print(f"  [{num}] {desc:<52} {status}")
        if note:
            print(f"        {note}")
        if not closed:
            blocking.append((num, desc))

    print()
    if blocking:
        print(f"BLOCKING — {len(blocking)} of 7 questions remain OPEN:")
        for num, desc in blocking:
            print(f"  * [{num}] {desc}")
        print()
        print("Per the standing rule: Real Runtime Fault Injection is NOT")
        print("considered closed while any of the seven security questions")
        print("is open.")
        return 1

    print("All seven closed within the stated scope (see notes above for")
    print("exactly what each closure does and does not cover).")
    print()
    print("REAL RUNTIME FAULT INJECTION — SECURITY LAYER: CONFORMANCE PASSED")
    print()
    print("This does not claim resistance to an adversary with full")
    print("reflection access to the same process — see [8]. It claims that")
    print("the direct paths a caller would ordinarily reach are closed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
