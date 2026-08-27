# Changelog

All notable changes to `hb-eval-sdk`.

This file starts at 2.11.0. Earlier releases were tracked only in commit
history — which is why this file exists: a release that adds a capability
without a written record of what it adds, and what it still does not do, is
a release its users have to reverse-engineer.

Versions follow [semantic versioning](https://semver.org). The **protocol
version** (currently `2.7.0`) is a separate number describing the wire format
between SDK and Gateway, and does not move when the library does.

---

## [2.11.0] — 2026-08-26

### Added — real runtime fault injection

Until this release, the fault battery *described* a failure to the agent: it
appended text to the task and scored the reply. That is a real measurement of
a real thing — how an agent responds to being told a tool failed — and it is
not the same as how an agent responds to a tool that actually failed.

This release closes that gap **at instrumented tool boundaries**.

```python
from hb_eval_sdk import FaultPlan, FaultSpec, fault_context, wrap_tool

tracking = wrap_tool(carrier_api.get_tracking, "carrier_api")

plan = FaultPlan(id="FI-001", seed=42, faults=[
    FaultSpec(id="F1", target="carrier_api", mode="timeout", after_ms=5000),
])

with client.monitor(agent_id="support-agent") as session:
    with fault_context(session, plan=plan):
        try:
            result = tracking(order_id)   # actually blocks, then actually raises
        except FaultInjected:
            result = cache.get(order_id)  # your agent adapts
```

**Why this matters beyond convenience.** Because the system causes the fault,
the system knows the fault occurred. `had_fault` on this path is
`runtime_observed` rather than `agent_reported` — and every metric reading it
inherits the stronger provenance: FRR's denominator, IRS's judged set, and
PEI's fault episodes stop depending on the agent's own account of whether
anything went wrong.

#### Seven fault modes

| Mode | What actually happens |
|---|---|
| `timeout` | Blocks for the configured delay, then raises. Synthetic at the tool boundary — the underlying call is never made, so the duration does not depend on network conditions nobody controls. |
| `latency` | Delays, then lets the real call proceed. The only mode that does not prevent the work: it tests patience, not error handling. |
| `error_5xx` | Raises immediately, carrying an HTTP status. |
| `empty_response` | Returns an empty value. Four kinds — `null`, `empty_object`, `empty_array`, `empty_string` — because agents that handle one do not necessarily handle another. |
| `malformed` | Returns a structurally wrong value. Seven kinds: `wrong_schema`, `missing_required_field`, `wrong_type`, `invalid_enum`, `truncated_payload`, `invalid_json`, `unexpected_nested_structure`. |
| `intermittent` | Fails with probability *p*, on a deterministic schedule. The hardest shape to handle, because a retry sometimes works and teaches the agent the wrong lesson. |
| `connection_refused` | Raises as an unreachable host would. |

#### Cascade topologies

`CascadePlan` is a separate primitive from `FaultPlan`, and the distinction is
the point. A `FaultPlan` with two targets faults **both** from the first call
onward, independently — useful, and not a cascade. A `CascadePlan` arms stage
*N* only after stage *N−1* has fired:

```python
cascade = CascadePlan(id="C1", seed=42, stages=[
    CascadeStage(target="primary_carrier", mode="timeout", after_ms=2000),
    CascadeStage(target="backup_carrier", mode="error_5xx", http_status=503),
])
```

Before stage 1 fires, stage 2's target is untouched. That is what makes it
possible to observe whether the agent's own fallback logic reaches it at all —
and an agent that never calls the backup produces
`reached_final_stage: False`, which is the finding, not a gap in the test.

#### Evidence: three states, never collapsed

A boolean `had_fault` destroys the difference between three situations that
come apart in practice:

```
intended    what the plan asked for
injected    whether the injector actually applied it   (applied/skipped/failed/partial)
observed    what the runtime actually saw
```

A plan can request a timeout, the injector can fail to apply it, and the call
can return normally. Recording that as `had_fault = True` would manufacture
evidence for a fault that never occurred, so `fault_present` is **derived** and
requires both *applied* **and** a non-normal observed outcome.

`matched_intent` separately records whether the runtime outcome matched what
was intended — a plan asking for a 5xx and a runtime raising a connection
error is an injection that applied and manifested differently, which is worth
recording rather than reporting as "5xx observed".

#### Deterministic replay

Every fault decision derives from `(seed, plan_id, target, attempt_index)`,
not from a shared random stream. A shared stream makes the outcome depend on
how many other calls happened first, so adding an unrelated tool call
elsewhere would shift the schedule — and a schedule that moves when unrelated
code changes cannot be replayed.

`FaultPlan.fingerprint()` and `CascadePlan.fingerprint()` identify *which*
faults a result was produced under. Two results with different plan
fingerprints were not measured against the same faults.

#### Off unless explicitly enabled

Requires `HBEVAL_ALLOW_FAULT_INJECTION=true`. Defaults to **off**, and the
default is the important part: an injector that runs because somebody forgot
to disable it will eventually break something real on a day nobody was
testing. With the flag unset, `fault_context` is a no-op that reports itself
as disabled rather than failing to start.

### Fixed

- **Concurrency.** Fault context state was a plain module-level variable, so a
  `fault_context` opened on one thread was visible to tool calls made on a
  different thread. Found by testing it directly during API review, before
  this version number was assigned. Now uses `contextvars.ContextVar`, which
  isolates both threads and asyncio Tasks — the latter matters because most
  agent frameworks are async and tasks on one event loop share an OS thread,
  which `threading.local()` would not have separated.

- **Nesting semantics.** A `fault_context` opened inside another shadows it
  fully while active and restores it exactly on exit. This was the behaviour
  before, but it was undocumented; it is now stated in the docstring and
  covered by a test.

### Security

The evidence layer was hardened against the party being measured. Each item
below corresponds to a test in `tests/test_fault_injection_security.py`:

- **Committed events are immutable.** `FaultEvent` is a frozen dataclass;
  `event.observed_outcome = "normal"` raises. An earlier draft used a mutable
  dataclass, which meant any code reaching the store could rewrite what a real
  event said happened.
- **Evidence cannot be forged into the store.** `record()` requires an
  instrumentation token held only by the trusted dispatch path.
- **Session identifiers do not grant access.** Real evidence is keyed by the
  session object's Python identity, not by its `session_id` string — knowing
  or guessing the string reaches nothing real.
- **Evidence cannot be deleted.** The event list is not an instance attribute
  at all, so `store._events.clear()` raises `AttributeError`.
- **No caller-supplied provenance.** There is deliberately no `source=`
  parameter anywhere in the public API. A provenance label the measured party
  can set is not provenance.

### What this release does NOT close

Stated here rather than left to be discovered:

- **Unwrapped tools.** A tool you did not pass through `wrap_tool` cannot be
  affected, by design — the narrowness is the feature, but it is a real limit
  on coverage.
- **Faults below the tool boundary.** This does not sever network connections,
  corrupt a real database, or exhaust real memory.
- **The fault battery is unchanged.** `evaluate_with_battery()` still uses
  task-level injection. Its battery fingerprint (`ce481b32763df1ca`) has not
  moved, and results from it remain comparable to earlier runs.
- **In-process tampering by a determined adversary.** The instrumentation runs
  in the agent's own process, and a process is not a security boundary against
  code running inside it. The measures above close the direct paths; nothing
  in Python closes reflection.
- **Anything about predictive validity.** This release improves where the
  measurement's inputs come from. It says nothing about whether the resulting
  metrics predict production failures — that requires evidence this project
  does not yet have.

### Unchanged

- `SCORING_VERSION` remains `v3`. Metric definitions did not move, so
  passports and results from 2.10.x remain directly comparable.
- Protocol version remains `2.7.0`. Nothing about the wire format changed.
- No existing API was altered or removed. Everything here is additive.

### Testing

```bash
PYTHONPATH=hb_eval_sdk pytest tests/                    # 73 passed
PYTHONPATH=hb_eval_sdk pytest tests/fault_injection/    # conformance suite
PYTHONPATH=hb_eval_sdk python tests/fault_injection/conformance.py
```

The conformance suite prints a row-by-row report across the seven fault types
plus provenance, tamper resistance and replay, and exits non-zero if any row
fails. It was verified to fail correctly by deliberately breaking the
security gate and confirming the report went red — a suite that has never been
seen to fail has not been shown to work.

---

## Earlier releases

Tracked in commit history and in the release notes on GitHub. Notable points:

- **2.10.0** — field-level evidence provenance; four provenance sources
  (`agent_reported`, `runtime_inferred`, `runtime_observed`,
  `externally_observed`); PEI v2.
- **2.9.x** — `handled_deliberately`; IRS v2 widened from recovery alone to
  deliberate handling including resistance and abstention.
- **2.8.0** — battery runners may return behavioural evidence alongside the
  response text.
