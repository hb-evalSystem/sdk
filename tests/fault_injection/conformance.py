"""
tests/fault_injection/conformance.py — Phase 3: the unified report
=====================================================================
    py tests/fault_injection/conformance.py

WHAT THIS IS
Not a new test. It runs the two suites that already establish something —
Phase 1 functional (all seven fault types through the full chain) and Phase 2
security (the seven adversarial questions, standalone) — and produces one
report that says exactly what closed and what did not, per the format
design review specified:

    timeout             PASS
    latency             PASS
    ...
    provenance          PASS
    tamper resistance   PASS
    replay              PASS

    REAL RUNTIME FAULT INJECTION
    STATUS: CONFORMANCE PASSED

WHY A SEPARATE RUNNER RATHER THAN JUST "ALL TESTS PASSED"
"All tests passed" answers one question. This suite exists because the
project needs to answer several different ones, and answering them together
as a single boolean would hide which one failed. A functional break and a
security break are different findings with different implications, and this
report keeps them visibly separate even while giving one final verdict.

EXIT CODE IS THE CONTRACT
0 only if every row is PASS. CI, or a human deciding whether Phase 4 (SDK
release) may proceed, should gate on the exit code, not on reading the text.
"""
from __future__ import annotations

import importlib.util
import io
import os
import sys
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent

# The functional and security suites import `evidence` and `faults` as bare
# top-level modules — matching this SDK's existing test convention (see
# test_policy.py: `from policy import ...`), which runs with `hb_eval_sdk/`
# itself on the path (`PYTHONPATH=hb_eval_sdk pytest tests/`) rather than
# importing through the installed package name.
#
# Resolved relative to this file rather than assuming the caller's cwd or an
# externally-set PYTHONPATH, so `py tests/fault_injection/conformance.py`
# works from any working directory without extra setup — the layout
# `<repo>/hb_eval_sdk/` next to `<repo>/tests/` is the SDK's actual shape and
# is not expected to change.
_SDK_ROOT = HERE.parent.parent / "hb_eval_sdk"
if _SDK_ROOT.is_dir():
    sys.path.insert(0, str(_SDK_ROOT))
sys.path.insert(0, str(HERE.parent))


def _run_module(path: Path):
    """Import and run a test module's main(), capturing its stdout.

    Returns (exit_code, captured_output). Each suite is run in-process rather
    than shelled out, so a single Python interpreter and environment is used
    throughout — consistent with how these suites are meant to be invoked in
    CI.
    """
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    buf = io.StringIO()
    old_argv = sys.argv
    sys.argv = [str(path)]
    try:
        with redirect_stdout(buf):
            spec.loader.exec_module(module)
            code = module.main()
    finally:
        sys.argv = old_argv
    return code, buf.getvalue()


def _extract_functional_rows(output: str) -> dict:
    """Pull the seven fault-type PASS/FAIL lines out of the functional
    suite's own report table, rather than re-deriving them — the functional
    suite is the source of truth for its own results.
    """
    rows = {}
    in_table = False
    for line in output.splitlines():
        if "SEVEN FAULT TYPES" in line:
            in_table = True
            continue
        if in_table:
            stripped = line.strip()
            if not stripped:
                if rows:
                    break
                continue
            parts = stripped.rsplit(None, 1)
            if len(parts) == 2 and parts[1] in ("PASS", "FAIL"):
                rows[parts[0]] = parts[1]
    return rows


def _extract_security_summary(output: str) -> str:
    """PASS if the security suite's own verdict line says conformance
    passed; FAIL otherwise. Deliberately binary at this level — the
    per-question detail belongs to the security suite's own report, which
    conformance.py surfaces separately below rather than re-parsing.
    """
    return "PASS" if "SECURITY LAYER: CONFORMANCE PASSED" in output else "FAIL"


def _extract_determinism(output: str) -> str:
    """Whether the functional suite's own replay check passed."""
    for line in output.splitlines():
        if line.strip().startswith("intermittent") and (
                "PASS" in line or "FAIL" in line):
            return "PASS" if "PASS" in line else "FAIL"
    return "FAIL"


def main() -> int:
    print("=" * 72)
    print("HB-EVAL — REAL RUNTIME FAULT INJECTION")
    print("CONFORMANCE SUITE v1")
    print("=" * 72)
    print()

    os.environ.setdefault("HBEVAL_ALLOW_FAULT_INJECTION", "true")

    functional_path = HERE.parent / "test_fault_types_functional.py"
    security_path = HERE.parent / "test_fault_injection_security.py"

    if not functional_path.exists() or not security_path.exists():
        print(f"FATAL: expected test files not found next to this suite.")
        print(f"  looked for: {functional_path}")
        print(f"  looked for: {security_path}")
        return 2

    print("Running Phase 1 (functional, seven fault types)...")
    func_code, func_output = _run_module(functional_path)

    print("Running Phase 2 (security, standalone, seven questions)...")
    sec_code, sec_output = _run_module(security_path)

    fault_rows = _extract_functional_rows(func_output)
    security_verdict = _extract_security_summary(sec_output)
    determinism_verdict = _extract_determinism(func_output)
    provenance_verdict = "PASS" if func_code == 0 else "FAIL"

    print()
    print("=" * 72)
    print("RESULTS")
    print("=" * 72)
    print()

    order = ["timeout", "latency", "error_5xx", "empty_response",
             "malformed", "intermittent", "cascade"]
    all_ok = True
    for name in order:
        status = fault_rows.get(name, "MISSING")
        if status != "PASS":
            all_ok = False
        print(f"  {name:<20} {status}")

    print()
    if provenance_verdict != "PASS":
        all_ok = False
    print(f"  {'provenance':<20} {provenance_verdict}")

    if security_verdict != "PASS":
        all_ok = False
    print(f"  {'tamper resistance':<20} {security_verdict}")

    if determinism_verdict != "PASS":
        all_ok = False
    print(f"  {'replay':<20} {determinism_verdict}")

    print()
    print("=" * 72)

    if not all_ok:
        print("REAL RUNTIME FAULT INJECTION")
        print("STATUS: CONFORMANCE FAILED")
        print()
        print("Per the standing rule, the layer is not considered closed.")
        print("Failing rows, in order:")
        for name in order:
            if fault_rows.get(name) != "PASS":
                print(f"  * {name}: {fault_rows.get(name, 'not run')}")
        if provenance_verdict != "PASS":
            print("  * provenance: functional suite exited non-zero")
        if security_verdict != "PASS":
            print("  * tamper resistance: see the security suite's own "
                 "output for which of the seven questions is open")
        if determinism_verdict != "PASS":
            print("  * replay: the intermittent schedule did not reproduce")
        print()
        print("Full functional output:")
        print("-" * 72)
        print(func_output)
        print("Full security output:")
        print("-" * 72)
        print(sec_output)
        return 1

    print("REAL RUNTIME FAULT INJECTION")
    print("STATUS: CONFORMANCE PASSED")
    print()
    print("What this establishes:")
    print("  - All seven fault types are injected at the tool boundary, not")
    print("    merely described to the agent, and each was proven through")
    print("    the full chain from request to metric interpretation.")
    print("  - Committed evidence cannot be mutated (frozen dataclass).")
    print("  - Evidence cannot be forged into the store without the")
    print("    instrumentation token, held only by the trusted dispatch path.")
    print("  - Guessing or knowing a session_id string does not reach real")
    print("    evidence; the real registry is keyed by object identity.")
    print("  - Intermittent and cascade schedules are seeded and replay")
    print("    identically from the same seed.")
    print()
    print("What this does NOT establish (see test_fault_injection_security.py,")
    print("finding [8], and Part VIII of the accompanying book):")
    print("  - Resistance to an adversary with full reflection access to the")
    print("    same Python process. No in-process design provides that.")
    print("  - That these fault types match every real production failure")
    print("    mode. They match the ones implemented; real infrastructure")
    print("    faults below the tool boundary remain out of scope.")
    print("  - Anything about predictive validity. This is a claim about")
    print("    the injection layer's own correctness, not about what the")
    print("    resulting metrics predict.")
    return 0


# ── pytest entry point ──────────────────────────────────────────────────
#
# The narrative `main()` above is genuinely more useful for a human doing a
# manual conformance check — it produces the row-by-row report design review
# asked for. But `pytest tests/fault_injection/` collecting zero tests and
# exiting 0 looks identical to a passing suite, which is a worse failure mode
# than a red one: it reports success for work that never ran.
#
# So this wraps the same `main()` as an actual pytest test. Output is still
# printed (pytest shows captured stdout on failure, and with `-s` always),
# and the pass/fail signal now reaches pytest's own reporting rather than
# being silently skipped.
def test_conformance():
    """`pytest tests/fault_injection/` runs this. See main() above for the
    full row-by-row report, which is also printed when this test runs."""
    code = main()
    assert code == 0, (
        "Real Runtime Fault Injection conformance FAILED — rerun "
        "`py tests/fault_injection/conformance.py` directly for the full "
        "row-by-row report (functional types, provenance, tamper "
        "resistance, replay)."
    )


if __name__ == "__main__":
    sys.exit(main())
