"""
test_fault_injection_concurrency.py — isolation across threads, tasks, nesting
=================================================================================
    py tests/test_fault_injection_concurrency.py

WHY THIS FILE EXISTS
API review, done deliberately before assigning a release version rather than
after, tested three things the design had documented intentions about but no
actual test for: thread safety, asyncio safety, and nested fault_context
behaviour. Two of the three were broken.

`_active` was a plain module-level variable. A fault_context opened on one
thread was visible to tool calls made concurrently on a DIFFERENT thread —
demonstrated directly below, and it would have surfaced the first time
someone ran fault-injection scenarios in parallel to speed up a battery, or
tested an agent built on an async framework, which is most of them.

Fixed by moving to contextvars.ContextVar, which isolates both threads (each
gets an independent context) and asyncio Tasks (each inherits a copy of its
parent's context at creation, so siblings running concurrently on one thread
do not see each other's fault_context).

WHAT THIS DOES NOT TEST
It does not test every possible interleaving. Concurrency bugs are
notoriously interleaving-sensitive, and passing here is evidence the fix
works for the interleavings exercised, not a proof for all of them.
"""
from __future__ import annotations

import asyncio
import os
import sys
import threading
import time

os.environ["HBEVAL_ALLOW_FAULT_INJECTION"] = "true"

from faults import FaultPlan, FaultSpec, fault_context, wrap_tool, FaultInjected


class FakeSession:
    def __init__(self, session_id):
        self.session_id = session_id


def main() -> int:
    failures = []

    print("=" * 72)
    print("FAULT INJECTION — CONCURRENCY AND NESTING")
    print("=" * 72)

    # ── 1. Thread isolation ──────────────────────────────────────────────
    print("\n[1] Two threads, one opens a fault_context, the other does not")
    tool = wrap_tool(lambda x: {"ok": True}, "shared_target")
    results = {}

    def with_fault():
        plan = FaultPlan(id="T1", seed=1, faults=[
            FaultSpec(id="F", target="shared_target", mode="timeout",
                      after_ms=40)])
        with fault_context(FakeSession("S-T1"), plan=plan):
            time.sleep(0.06)   # stay open while the other thread runs
            try:
                tool("x")
                results["with_fault"] = "not faulted"
            except FaultInjected:
                results["with_fault"] = "faulted"

    def without_fault():
        time.sleep(0.02)       # start after the first thread's context opens
        try:
            tool("x")
            results["without_fault"] = "not faulted"
        except FaultInjected:
            results["without_fault"] = "faulted"

    t1 = threading.Thread(target=with_fault)
    t2 = threading.Thread(target=without_fault)
    t1.start(); t2.start()
    t1.join(); t2.join()

    print(f"    thread with fault_context open: {results.get('with_fault')}")
    print(f"    thread with none open:          {results.get('without_fault')}")

    if results.get("with_fault") != "faulted":
        failures.append("the thread that opened fault_context was not faulted")
    if results.get("without_fault") != "not faulted":
        failures.append("LEAK: a thread with no fault_context open was "
                        "faulted by another thread's context")

    # ── 2. asyncio Task isolation ────────────────────────────────────────
    print("\n[2] Two asyncio Tasks on the same event loop, same test")

    async_tool = wrap_tool(lambda x: {"ok": True}, "async_target")

    async def task_with_fault():
        plan = FaultPlan(id="A1", seed=1, faults=[
            FaultSpec(id="F", target="async_target", mode="timeout",
                      after_ms=30)])
        with fault_context(FakeSession("S-A1"), plan=plan):
            await asyncio.sleep(0.05)
            try:
                async_tool("x")
                return "not faulted"
            except FaultInjected:
                return "faulted"

    async def task_without_fault():
        await asyncio.sleep(0.01)
        try:
            async_tool("x")
            return "not faulted"
        except FaultInjected:
            return "faulted"

    async def run_both():
        return await asyncio.gather(task_with_fault(), task_without_fault())

    r_with, r_without = asyncio.run(run_both())
    print(f"    task with fault_context open: {r_with}")
    print(f"    task with none open:          {r_without}")

    if r_with != "faulted":
        failures.append("the async task that opened fault_context was not "
                        "faulted")
    if r_without != "not faulted":
        failures.append("LEAK: an async task with no fault_context open was "
                        "faulted by a concurrent sibling task's context")

    # ── 3. Nesting: documented shadow-and-restore behaviour ──────────────
    print("\n[3] Nested fault_context — inner shadows outer, restores on exit")

    tool_a = wrap_tool(lambda x: {"a": True}, "target_a")
    tool_b = wrap_tool(lambda x: {"b": True}, "target_b")
    outer_plan = FaultPlan(id="OUTER", seed=1, faults=[
        FaultSpec(id="F1", target="target_a", mode="timeout", after_ms=1)])
    inner_plan = FaultPlan(id="INNER", seed=1, faults=[
        FaultSpec(id="F2", target="target_b", mode="error_5xx")])

    session = FakeSession("S-NEST")
    outer_before_ok = inner_isolated_ok = restored_ok = False

    with fault_context(session, plan=outer_plan):
        try:
            tool_a("x")
            outer_before_ok = False
        except FaultInjected:
            outer_before_ok = True

        with fault_context(session, plan=inner_plan):
            try:
                tool_a("x")   # outer's target — must NOT fire inside inner
                inner_isolated_ok = True
            except FaultInjected:
                inner_isolated_ok = False

        try:
            tool_a("x")   # outer's target — must fire again after inner exits
            restored_ok = False
        except FaultInjected:
            restored_ok = True

    print(f"    outer fires before nesting:  "
          f"{'yes' if outer_before_ok else 'NO'}")
    print(f"    outer target silent inside inner (documented): "
          f"{'yes' if inner_isolated_ok else 'NO'}")
    print(f"    outer restored after inner exits: "
          f"{'yes' if restored_ok else 'NO'}")

    if not (outer_before_ok and inner_isolated_ok and restored_ok):
        failures.append("nested fault_context does not shadow-and-restore "
                        "as documented")

    print()
    print("=" * 72)
    if failures:
        print(f"FAILED — {len(failures)}:")
        for f in failures:
            print(f"  * {f}")
        return 1

    print("Concurrency and nesting hold.")
    print()
    print("Thread and asyncio isolation are provided by contextvars, not")
    print("locking — there is no contention between unrelated concurrent")
    print("scenarios. Nesting shadows rather than composes, by design; see")
    print("fault_context's docstring for the reasoning.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
