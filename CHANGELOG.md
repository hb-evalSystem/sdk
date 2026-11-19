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

## [2.13.0]

### Added — from evidence to enrolment, enforcement and continuous assurance

Ten modules on top of 2.12.0, in the order the specification builds them:
`policy_document` (R1), `topology` (R2), `lineage` (R3), `readiness_passport`
(R4), `enrollment` (R5), `operational` (R6), `operational_passport` (R7),
`enforcement` (R8, SDK half), `enforcement_evidence` (R9), `assurance` (R10).

### Changed
- `attestation.py`: the DW-008 limitation no longer says the evidence schema
  "is still moving" — it has been frozen since Phase 9A.
- `__version__` now agrees with `pyproject.toml` (it said 2.11.0 in 2.12.0).

### Protocol
- `PROTOCOL_VERSION` (wire) 2.7.0 → **2.8.0**: additive enforcement surface only. It is now a
  separate number from `MEASUREMENT_PROTOCOL_VERSION` (2.7.0), which stamps passports.
- NEW `hb_eval_sdk.protocol`: the major.minor compatibility rule that `config.py` documented but
  nothing enforced. The client now reads the Gateway's `X-HBEval-Protocol` response header once
  and warns (`ProtocolMismatchWarning`) on a mismatch; a Gateway that does not advertise is
  `unknown`, never `ok`.
- NEW `docs/PROTOCOL.md`, reconstructed from the code both peers cite it from.

### Added — CI/CD
- `.github/workflows/ci.yml`: tests on Python 3.9–3.13; tests at the declared dependency floors;
  conformance + mutation check; flake8 hard errors; bandit; pip-audit (3.12 clean, 3.9 with an
  explicit allow-list); build + `twine check --strict` + clean-venv install + version agreement;
  the gate action exercised end to end with no secrets.
- `release.yml` (tag-driven, PyPI trusted publishing, build attestation, checksums), `codeql.yml`,
  `dependabot.yml`. Third-party actions are pinned to commit SHAs.
- `action.yml`: the gate as a composite action. Inputs reach the shell through the environment,
  never interpolated into the script.
- `examples/ci_gate/`: offline fixtures (PASS / FAIL / INCONCLUSIVE).

### Security
- Dependency floors raised to the lowest versions with no known advisory (`cryptography>=50.0.0`,
  `pydantic>=2.4.0`, `requests>=2.33.0` / `urllib3>=2.8.0` on Python >= 3.10). The previous floors
  admitted 44 known advisories. On Python 3.9 the newest `requests` and `urllib3` still carry
  advisories fixed only for Python >= 3.10; see SECURITY.md.
- `HBEvalClient._post` always sends a timeout (a caller that forgets one can no longer hang the agent).
- A fault-evidence record that fails to write is now logged instead of vanishing silently.

### Fixed
- `hb-eval gate` no longer demands `--agent` and `--task` when `--reference-baseline` and
  `--candidate-baseline` are given; the legacy path still requires them (exit 2).

### Quality
- Tests: 756 → **1,141**. Coverage 76% → **95%** (CI fails below 90%). `client.py` 35% → 93%; `mcp_server.py` 0% → covered;
  `gate.py`, `monitoring.py`, `auto.py`, `otel_bridge.py`, the three framework adapters and the CLI are now tested.
- Property-based fuzzing (Hypothesis) of every input parser. Its first run found a crash (`policies=True`).
- Static typing: `py.typed` ships; `mypy` is clean on the whole package under both supported `mcp` majors; implicit-Optional
  annotations fixed. Public API docstrings: 60% → **100%** (404 of 404).
- The user guide's code is executed by the test suite. `examples/lifecycle.py` runs the whole V2 chain offline.
- `docs/`: `USER_GUIDE.md`, `API_STABILITY.md`, `THREAT_MODEL.md`, `PERFORMANCE.md`, `protocol_vectors.json`.

### Fixed (found while testing)
- **MCP server**: `retrieve_qualified_memory` failed on every successful call (a pydantic object was passed to `json.dumps`).
  And `pip install hb-eval-sdk[mcp]` resolved to `mcp` 2.x, where `FastMCP` no longer exists, so the server could not
  start and blamed a package that was installed. Both major versions are now supported and tested.
- **LangChain**: `HBEvalLangChainCallback` raised `AttributeError` inside the user's own run (it was not a valid handler).
  List-style message content was stringified as a Python repr. LangGraph answered with the last message even when it was a
  tool message; it now answers with the last AI message.
- **Client**: `max_retries=0` was silently replaced by the default; a negative per-call retry count made `evaluate()` return
  `None` (a gate failing open); an empty gateway URL silently redirected traffic to the default Gateway.
- **Gate**: failure text was written into GitHub workflow commands unescaped (a newline could inject another command);
  a non-numeric metric from the Gateway raised an exception and exited 1, the code for "the gate failed".
- **Policies**: a mistyped rule was dropped with no trace, though the docstring promised it would be reported; a non-list
  `policies` argument raised `TypeError`. Dropped rules are now logged and listed in the session summary with the reason.
- **`auto`**: malformed credentials in the environment raised at import, contradicting its promise that importing it cannot
  stop an application. **Demo CLI**: `--connect` with bad credentials crashed with a traceback and printed a retired metric name.
- **OpenTelemetry bridge**: failures to open a session were logged at DEBUG, so a run could silently go unmonitored.
- **`lineage.trace`** raised `AttributeError`/`StopIteration` on a corrupted lineage; it now raises `LineageError`.

- **`evaluate()` crashed on the Gateway's most common answer.** For an agent evaluated without fault injection the Gateway
  returns `INSUFFICIENT_DATA` (FRR, IRS and TI cannot be measured when nothing failed), and the SDK's `Verdict` enum only knew
  `SAFE` and `UNSAFE`, so the typed API raised "unexpected error". Found by running the real client against the real Gateway.
  `Verdict.INSUFFICIENT_DATA` is added (never SAFE), and `EvaluationResult` now keeps `qualified`, `tier_status`,
  `tier_provisional` and `unmeasured_metrics`, which were silently dropped.

### Changed
- **Security**: the gateway URL must be `https` unless it is loopback or `allow_insecure_http=True` is passed, because every
  request carries the API key. `HBEVAL_GATEWAY_URL` is honoured when no URL is given.
- Framework integrations and the V2 submodules are **lazy** (PEP 562): `import hb_eval_sdk` no longer imports LangChain,
  LangGraph or CrewAI. A change to a callback base class had made it load LangChain eagerly (~200 ms).
- Optional-dependency floors raised to advisory-free versions: `langchain-core>=1.3.3` (`>=0.3.85` on 3.9), `langgraph>=1.2.14`
  (`>=0.3.15` on 3.9), `mcp>=1.30.0,<3`. At their previous floors they admitted 29 known advisories.
- `pytest` now works from a fresh checkout with no environment set up (`conftest.py`).

### Added — release hygiene
- `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`; `tests/__init__.py`;
  `tests/fault_injection/conformance.py` (rewritten — see its docstring).

### Unchanged
- Battery fingerprint `ce481b32763df1ca`; `SCORING_VERSION` `v3`.
- `MEASUREMENT_PROTOCOL_VERSION` stays `2.7.0`: no metric computation changed.

### Testing
```bash
HBEVAL_ALLOW_FAULT_INJECTION=true PYTHONPATH=hb_eval_sdk:. pytest tests    # 1141 passed
```

---

## [2.12.0] — 2026-09-17

### Added — the evidence chain

Until this release the SDK measured reliability and reported numbers. It had
no way to say what a number rested on, whether two numbers could be compared
at all, or whether a conclusion drawn a week ago still applied.

This release adds eight layers between a measurement and an operational
conclusion. Each has a state meaning **"I cannot say"**, and none of those
states collapses into a positive or a negative answer.

```
Evidence  ->  Baseline  ->  Comparability  ->  Diff  ->  Decision
          ->  Attestation  ->  Context assessment  ->  Durable evidence
```

#### Evidence and provenance — `evidence_package`

Each metric carries typed references to the evidence it was computed from,
separated into numerator, denominator and supporting references. A metric
whose evidence was expected and did not arrive is `missing`, and a `missing`
metric **cannot become a baseline**. Provenance is a gate here, not an audit
trail: a number without its inputs does not enter the pipeline.

An envelope serialises and reconstructs with its canonical hash preserved.

#### Baseline and comparability — `baseline`, `comparability`

```python
from hb_eval_sdk.baseline import ReliabilityBaseline
from hb_eval_sdk.comparability import compare

baseline = ReliabilityBaseline.from_envelope(envelope)
verdict = compare(baseline_a, baseline_b, identity_a, identity_b)
# COMPARABLE | NOT_COMPARABLE | UNKNOWN
```

Two evaluations are compared only when the measurement context permits it,
decided per metric and for the pair. `UNKNOWN` exists because a baseline
stores its evaluation context as an opaque hash: when the hashes differ and
the identities were not supplied, the reason is genuinely unavailable, and
`NOT_COMPARABLE` would claim more than is known.

#### Differences and decisions — `reliability_diff`, `reliability_decision`

```python
from hb_eval_sdk.reliability_diff import diff_baselines
from hb_eval_sdk.reliability_decision import decide, SLOPolicy, SLOCondition

policy = SLOPolicy("org-v1", (SLOCondition("frr", "gte", 0.80),))
decision = decide(diff_baselines(baseline_a, baseline_b), policy)
# PASS | FAIL | INCONCLUSIVE | RECERTIFICATION_REQUIRED
```

`delta` is `None` where no comparison was made — never `0.0`, which means the
values were equal and is a measurement.

**SLO thresholds are organizational policy.** There is no default policy, no
default threshold and no default tolerance in this SDK. Without a declared
policy the verdict is `INCONCLUSIVE`: the absence of a threshold is not
permission.

#### Bounded attestation — `attestation`

```python
from hb_eval_sdk.attestation import attest
statement = attest(decision, subject_baseline)   # PASS decisions only
```

An attestation states that a subject reached a `PASS` decision, under a
declared policy, on identified evidence, within a stated scope. Its
limitations travel inside the artefact.

#### Context assessment — `context_assessment`

```python
from hb_eval_sdk.context_assessment import assess_context
result = assess_context(attestation, current_context)
# CONTEXT_UNCHANGED | RECERTIFICATION_REQUIRED | UNDETERMINED
```

`CONTEXT_UNCHANGED` means no change was detected in the context that was
supplied and compared. It is **not** a statement that the agent did not
change, and **not** a statement that the attestation is still valid.

New evidence does not invalidate a context: an attestation says a decision
was reached *on this evidence*, and that stays true when newer evidence
appears.

#### Evidence persistence — `evidence_store`

```python
from hb_eval_sdk.evidence_store import store_evidence, load_evidence
store_evidence(envelope, "evidence/run-42.json")
restored = load_evidence("evidence/run-42.json")   # raises on any alteration
```

Atomic write, and a reload that verifies the payload bytes, the
reconstruction, and the canonical hash against an independently recorded one.
Any tamper raises; no failure path returns an artefact.

### Changed

- **`gate` no longer computes a regression by raw subtraction.** Previously
  `hb-eval gate --baseline` subtracted two metric dictionaries and failed the
  build on the result, with no check of comparability, metric version,
  provenance or battery identity. It now reports the numbers as an
  observation and makes no reliability claim from them.
- **Two new exit codes**, `3` (`INCONCLUSIVE`) and `4`
  (`RECERTIFICATION_REQUIRED`). `0`, `1` and `2` keep their published
  meanings exactly.
- **New gate flags** `--reference-baseline`, `--candidate-baseline` and
  `--slo-policy` enable the evidence-gated decision path. `--baseline` is
  unchanged and remains the legacy raw-report input.
- `METRIC_NAMES["irs"]` corrected to **Intentional Recovery Score**.

### Limits of this release — read before relying on it

- **An attestation is not a certification.** There is no issuing authority,
  no signature, no external anchor and no revocation. It is tamper-evident
  within the producing process only.
- **Evidence persistence is not provenance.** The store detects
  *alteration*; it does not establish *authorship*. Anyone who can rewrite a
  stored container can recompute every digest it holds and the substitution
  verifies. Closing that needs a signature and an external anchor, neither of
  which ships here.
- **Persistence is not yet a durable evidence system.** There is no retention
  policy, no storage backend, no indexing or retrieval, no backup, no
  cross-host concurrency and no garbage collection. Evidence survives a
  process; that is less than being durably stored.
- **`CONTEXT_UNCHANGED` is bounded by what was declared.** The current
  context comes from the caller, not from runtime observation, and sampling
  parameters sit outside the configuration fingerprint — so it means
  unchanged *under the represented configuration identity*, not proof that
  every runtime parameter held.
- **IRS remains provisional.** No judge has been validated, and a provisional
  metric drives a decision only when a policy declares it eligible.
- **Scope is one battery slot.** An attestation covers the slot it was issued
  for and says nothing about an agent as a whole.
- **No causal attribution and no reproducible-regression claim.** A
  difference is reported, never explained.
- **All results to date are from synthetic SDK executions.** No real-agent
  empirical validation ships with this release.

### Verification

```
417 tests passing
Phase 0 regression baseline byte-identical across all eight phases
battery_spec_fingerprint unchanged: ce481b32763df1ca
evidence schema frozen: hb-eval-evidence/v1
```

The frozen evidence schema is versioned separately from the storage container
format (`hb-eval-container/v2`), so a storage change cannot move an
artefact's identity.

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
