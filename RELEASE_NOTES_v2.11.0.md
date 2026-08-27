# Release notes for v2.11.0 — paste into GitHub

> **How to use this file.** On GitHub: Releases → Draft a new release → tag
> `v2.11.0`, target `main`, title `v2.11.0 — Real runtime fault injection`.
> Paste everything below the line into the description box. This file itself
> is not part of the package and does not need to be committed, though there
> is no harm in keeping it.

---

## Real runtime fault injection

Until this release, HB-Eval's fault battery **described** a failure to the
agent — it appended text to the task and scored the reply. That measures
something real: how an agent responds to being *told* a tool failed. It is not
the same as how an agent responds to a tool that *actually* failed.

This release closes that gap at instrumented tool boundaries.

```python
from hb_eval_sdk import FaultPlan, FaultSpec, fault_context, wrap_tool, FaultInjected

tracking = wrap_tool(carrier_api.get_tracking, "carrier_api")

plan = FaultPlan(id="FI-001", seed=42, faults=[
    FaultSpec(id="F1", target="carrier_api", mode="timeout", after_ms=5000),
])

with client.monitor(agent_id="support-agent") as session:
    with fault_context(session, plan=plan):
        try:
            result = tracking(order_id)    # blocks 5s, then raises
        except FaultInjected:
            result = cache.get(order_id)   # your agent adapts
```

**Why this changes the measurement, not just the ergonomics.** Because the
system causes the fault, the system knows the fault occurred. `had_fault` on
this path is `runtime_observed` rather than `agent_reported` — and every metric
that reads it inherits the stronger provenance: FRR's denominator, IRS's judged
set, and PEI's fault episodes stop depending on the agent's own account of
whether anything went wrong.

### Seven fault modes

`timeout` · `latency` · `error_5xx` · `empty_response` (4 kinds) ·
`malformed` (7 kinds) · `intermittent` · `connection_refused`

`empty_response` and `malformed` carry sub-kinds because an agent that handles
`{}` may not handle `null`, and one that catches invalid JSON may sail straight
past a valid-but-wrong enum value.

### Cascade topologies

`CascadePlan` arms stage *N* only after stage *N−1* has fired. Before stage 1
fires, stage 2's target is untouched — which is what makes it possible to
observe whether the agent's fallback logic reaches it at all. An agent that
never calls its backup produces `reached_final_stage: False`, and that absence
is the finding rather than a gap in the test.

### Evidence: three states, never collapsed

```
intended    what the plan asked for
injected    whether the injector actually applied it
observed    what the runtime actually saw
```

A plan can request a timeout, the injector can fail to apply it, and the call
can return normally. Recording that as `had_fault = True` would manufacture
evidence for a fault that never occurred, so `fault_present` is derived and
requires both *applied* and a non-normal observed outcome.

### Deterministic replay

Every decision derives from `(seed, plan_id, target, attempt_index)` rather
than a shared random stream — so adding an unrelated tool call elsewhere does
not shift the schedule. `FaultPlan.fingerprint()` identifies which faults a
result was produced under.

### Off unless enabled

Requires `HBEVAL_ALLOW_FAULT_INJECTION=true`. An injector that runs because
somebody forgot to disable it will eventually break something real on a day
nobody was testing.

---

## Fixed

**Concurrency.** Fault context state was a plain module-level variable, so a
context opened on one thread was visible to tool calls on another. Found by
testing it directly during API review, before this version was assigned. Now
uses `contextvars.ContextVar`, which isolates threads *and* asyncio Tasks —
the latter matters because most agent frameworks are async, and tasks on one
event loop share an OS thread that `threading.local()` would not have
separated.

**Nesting.** A `fault_context` inside another shadows it fully and restores it
exactly on exit. This was already the behaviour; it is now documented and
tested.

---

## Security

The evidence layer was hardened against the party being measured:

- Committed `FaultEvent` records are **frozen** — they cannot be rewritten
  after the fact.
- `record()` requires an instrumentation token held only by the trusted
  dispatch path, so fabricated events cannot be injected.
- Real evidence is keyed by the session object's **Python identity**, not its
  `session_id` string — knowing or guessing the string reaches nothing real.
- The event list is not an instance attribute, so it cannot be cleared.
- There is deliberately **no `source=` parameter** anywhere in the public API.
  A provenance label the measured party can set is not provenance.

Each item corresponds to a test in `tests/test_fault_injection_security.py`,
which is kept separate from the functional suite so that a security failure and
a functional failure are never reported as one number.

---

## What this release does NOT close

- **Unwrapped tools.** A tool not passed through `wrap_tool` is untouched, by
  design.
- **Faults below the tool boundary.** No network partitions, no real database
  corruption, no memory exhaustion.
- **The fault battery is unchanged.** `evaluate_with_battery()` still uses
  task-level injection; its fingerprint (`ce481b32763df1ca`) has not moved and
  earlier results remain comparable.
- **In-process tampering by a determined adversary.** The instrumentation runs
  in the agent's own process. The measures above close the direct paths;
  nothing in Python closes reflection.
- **Predictive validity.** This improves where the measurement's inputs come
  from. It says nothing about whether the metrics predict production failures.

---

## Compatibility

**Nothing was altered or removed — this release is entirely additive.**

- `SCORING_VERSION` remains `v3`; metric definitions did not move, so
  passports and results from 2.10.x remain directly comparable.
- Protocol version remains `2.7.0`; the wire format is unchanged.
- Existing code continues to work without modification.

---

## Verification

```bash
pip install --upgrade hb-eval-sdk
python -c "import hb_eval_sdk as h; print(h.__version__, h.fault_context is not None)"
# 2.11.0 True
```

From a clone:

```bash
PYTHONPATH=hb_eval_sdk pytest tests/                    # 73 passed
PYTHONPATH=hb_eval_sdk pytest tests/fault_injection/    # conformance suite
```

The conformance suite prints a row-by-row report across the seven fault types
plus provenance, tamper resistance and replay. It was verified to fail
correctly by deliberately breaking the security gate and confirming the report
went red — a suite that has never been seen to fail has not been shown to work.

**Full detail:** [CHANGELOG.md](./CHANGELOG.md)
