"""
conformance.py — the fault-injection conformance procedure
==========================================================
    PYTHONPATH=hb_eval_sdk pytest tests/fault_injection/        # 1 test
    PYTHONPATH=hb_eval_sdk python tests/fault_injection/conformance.py

ADOPTED as the conformance procedure for 2.13.0. It was written to the contract the project's own
documents give for it — a row-by-row report across the fault types plus provenance, tamper
resistance and replay; non-zero exit if any row fails; exactly one pytest-collected test (pyproject
widens python_files so this file is collected) — because the earlier file was not recoverable. It
is not byte-equivalent to that file, and does not claim to be.

That it does its whole job is shown, not asserted: tests/fault_injection/mutation_check.py breaks each
guarded property in a scratch copy (mutable evidence, wrong provenance label on events and on the
store summary, a seed-ignoring schedule, faults never applied, evidence reachable by a forgeable
session string) and requires this suite to turn red every time. CI runs both.

WHAT EACH ROW MEANS
  type:<mode>   (all 13 modes) the fault was requested, applied, and the runtime observed it
  chain         the two standalone suites are run unchanged:
                test_fault_types_functional  (seven types, full chain)
                test_fault_injection_security (the seven adversarial questions)
  provenance    committed evidence is labelled runtime_observed and is frozen
  replay        the same plan + seed reproduces the same decisions; another
                seed does not silently collapse onto it

A SUITE THAT HAS NEVER BEEN SEEN TO FAIL HAS NOT BEEN SHOWN TO WORK.
`--self-check` feeds the immutability probe a deliberately mutable object and
requires it to report MUTABLE; a probe that cannot say no proves nothing.
"""
from __future__ import annotations
import contextlib, dataclasses, io, os, sys

os.environ["HBEVAL_ALLOW_FAULT_INJECTION"] = "true"
_HERE = os.path.dirname(os.path.abspath(__file__))
_TESTS = os.path.dirname(_HERE)
for _p in (_TESTS, os.path.join(_TESTS, "..", "hb_eval_sdk")):
    if os.path.isdir(_p) and os.path.abspath(_p) not in sys.path:
        sys.path.insert(0, os.path.abspath(_p))

from evidence import (FaultEvent, InjectionStatus, ObservedOutcome,   # noqa: E402
                      evidence_for)
from faults import (FAULT_MODES, FaultInjected, FaultPlan, FaultSpec,   # noqa: E402
                    fault_context, wrap_tool)


class _Session:
    def __init__(self, sid):
        self.session_id, self._n_steps = sid, 0


_LAST_SESSION = {}


def _tool(x=1):
    return {"value": 42, "items": [1, 2, 3], "ok": True, "x": x}


def _run_mode(mode: str):
    session = _Session(f"CONF-{mode}")
    _LAST_SESSION[mode] = session
    kw = dict(after_ms=5) if mode in ("timeout", "latency") else {}
    if mode == "error_5xx":
        kw["http_status"] = 503
    raised = None
    with fault_context(session, "conf_tool", mode=mode, seed=7, **kw):
        fn = wrap_tool(_tool, "conf_tool")
        try:
            # state faults need history: make a first, un-faulted-looking call
            fn(1)
            fn(2)
        except BaseException as exc:                       # noqa: BLE001
            raised = exc
    store = evidence_for(session, create=False)
    return raised, (list(store.events) if store is not None else [])


def row_types():
    rows = []
    for mode in FAULT_MODES:
        try:
            raised, ev = _run_mode(mode)
            e = ev[0] if ev else None
            ok = (e is not None and e.intended_type == mode
                  and e.injection_status == InjectionStatus.APPLIED
                  and e.observed_outcome in ObservedOutcome.ALL)
            detail = (f"{e.injection_status}/{e.observed_outcome}"
                      if e else "no evidence recorded")
        except Exception as exc:                          # noqa: BLE001
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        rows.append((f"type:{mode}", ok, detail))
    return rows


def _capture(fn):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = fn()
    return code


def row_chain():
    rows = []
    for label, modname in (("chain:seven types (functional)", "test_fault_types_functional"),
                           ("chain:tamper resistance (security)", "test_fault_injection_security")):
        try:
            mod = __import__(modname)
            code = _capture(mod.main)
            rows.append((label, code == 0, f"exit {code}"))
        except Exception as exc:                          # noqa: BLE001
            rows.append((label, False, f"{type(exc).__name__}: {exc}"))
    return rows


def _is_frozen(obj) -> bool:
    """True if assigning to an existing field raises. The probe itself must be
    able to answer False — see --self-check."""
    field = next(iter(vars(obj)))
    try:
        setattr(obj, field, getattr(obj, field))
    except dataclasses.FrozenInstanceError:
        return True
    return False


def row_provenance():
    raised, ev = _run_mode("error_5xx")
    if not ev:
        return [("provenance", False, "no evidence")]
    e = ev[0]
    src = e.to_dict().get("provenance", {}).get("source")
    store = evidence_for(_LAST_SESSION["error_5xx"], create=False)
    ssrc = store.summary().get("source") if store is not None else None
    return [("provenance:event labelled runtime_observed", src == "runtime_observed", src),
            ("provenance:summary labelled runtime_observed", ssrc == "runtime_observed", ssrc),
            ("provenance:committed evidence is immutable", _is_frozen(e),
             "frozen" if _is_frozen(e) else "MUTABLE")]


def _decisions(seed, n=60):
    plan = FaultPlan(id="REPLAY", seed=seed, faults=[
        FaultSpec(id="F1", target="rp", mode="error_5xx", http_status=503,
                  probability=0.5)])
    session = _Session(f"CONF-REPLAY-{seed}")
    with fault_context(session, plan=plan):
        fn = wrap_tool(_tool, "rp")
        for i in range(n):
            try:
                fn(i)
            except FaultInjected:
                pass
    store = evidence_for(session, create=False)
    return [(e.attempt_index, e.injection_status)
            for e in (store.events if store is not None else [])], plan.fingerprint()


def row_replay():
    a, fa = _decisions(1234)
    b, fb = _decisions(1234)
    c, _ = _decisions(98765)
    return [("replay:same seed, same decisions", a == b and fa == fb,
             f"{len(a)} events"),
            ("replay:different seed, different decisions", a != c,
             "seeds are not collapsing")]


def run(verbose: bool = True) -> int:
    rows = row_types() + row_chain() + row_provenance() + row_replay()
    if verbose:
        print("FAULT-INJECTION CONFORMANCE")
        print("=" * 72)
        for name, ok, detail in rows:
            print(f"  {'PASS' if ok else 'FAIL'}  {name:<46} {detail}")
        passed = sum(1 for _, ok, _ in rows if ok)
        print("=" * 72)
        print(f"  {passed}/{len(rows)} rows pass")
    return 0 if all(ok for _, ok, _ in rows) else 1


def test_conformance_suite():
    assert run(verbose=True) == 0


def self_check() -> int:
    import types
    detected = _is_frozen(types.SimpleNamespace(a=1)) is False
    print(f"  self-check: probe reports a mutable object as mutable -> "
          f"{'OK' if detected else 'BROKEN'}")
    return 0 if detected else 1


if __name__ == "__main__":
    sys.exit(self_check() if "--self-check" in sys.argv else run())
