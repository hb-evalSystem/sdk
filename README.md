
# HB-Eval SDK

**Operational reliability measurement for agentic AI.**

Your agent finished the task. Did it behave?

Benchmarks measure whether an agent completed its work. Almost nothing measures
how it behaved while things were going wrong — and that is where production
incidents come from. HB-Eval measures it, watches it live, and can stop a run
before the damage lands.

[hbeval.com](https://hbeval.com) · [Documentation](https://hbeval.com/docs) ·
[Architecture](https://hbeval.com/architecture) ·
[Science](https://hbeval.com/science)

---

## Install

```bash
pip install hb-eval-sdk
pip install .                      # this tree: 2.13.0
```

Python >=3.9 is declared; this tree has been run on 3.12 only. Three dependencies: `requests`, `cryptography`, `pydantic`.

---

## The five metrics

| | | Answers |
|---|---|---|
| **PEI** | Planning Efficiency | Is the plan holding, or is the agent redoing it? |
| **FRR** | Failure Resilience | Of the steps that met a fault, how many still completed? |
| **IRS** | Deliberate Handling | Was the fault handled deliberately, or met by reflex? |
| **TI** | Traceability | Can each decision be followed afterwards? |
| **CSI** | Consistency Stability | Does the same task produce the same behaviour across runs? |

**Undefined is never reported as zero.** Resilience cannot be scored before a
fault happens; consistency cannot be measured within a single session. Those
come back as `None` and stay `None` through the wire protocol, the database and
every chart. Substituting zero would claim a measured failure on a dimension
nothing examined — and a CI gate or an auditor reading that zero would act on
it.

---

## Quick start

### Measure a live agent

```python
from hb_eval_sdk import HBEvalClient

client = HBEvalClient(api_key=..., aes_key=..., signing_secret=...)

with client.monitor(
    agent_id="support-agent",
    halt_policy={"metric": "frr", "below": 0.5, "for_steps": 3},
) as session:
    for step in my_agent.run(task):
        session.record_step(
            action=step.name,
            success=step.ok,
            had_fault=step.faulted,
            recovered_intentionally=step.recovery_was_reasoned,
            traceable=step.reasoning_recorded,
        )
        if session.should_halt:
            break          # cooperative: your loop decides how to stop
```

Metrics are computed locally, in your process, at roughly 0.002 ms per step —
flat from a hundred steps to fifty thousand. Safe Halt is decided locally too,
so your policy still fires when the network is down. A guard that needs a round
trip is a guard that fails exactly when infrastructure is already struggling.

### Run the fault battery

```python
report = client.evaluate_with_battery(
    {"system": "...", "question": "..."},
    my_agent,
    n_scenarios=30,
    seed=42,               # same seed, same battery
)
```

Six fault types across six domains: `tool_failure`, `context_corruption`,
`stochastic`, `adversarial`, `cascade`, `combined`.

### Inject a real fault

The battery above *tells* an agent a tool failed. This makes the tool
actually fail:

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

Because the system causes the fault, the system knows it happened - so
`had_fault` here is **`runtime_observed`**, not taken on the agent's word.

Seven modes: `timeout`, `latency`, `error_5xx`, `empty_response` (4 kinds),
`malformed` (7 kinds), `intermittent`, `connection_refused`. Cascades across
tool boundaries use `CascadePlan`, which arms each stage only after the
previous one fires - so an agent that never calls its fallback is visible as
exactly that.

Requires `HBEVAL_ALLOW_FAULT_INJECTION=true`. Off by default, deliberately.

See [CHANGELOG.md](./CHANGELOG.md) for full behaviour, including what it does
not cover.

### Zero-setup instrumentation

```python
import hb_eval_sdk.auto     # that is the whole setup
```

Derives reliability signals from OpenTelemetry spans you already emit. Nothing
else to add.

---

## Framework adapters

```python
from hb_eval_sdk import (
    adapt_langchain_agent,
    adapt_langgraph_agent,
    adapt_crewai_agent,
)

runner = adapt_langchain_agent(agent_executor)
runner = adapt_langgraph_agent(compiled_graph)
runner = adapt_crewai_agent(crew_agent)
```

One call. Your agent keeps its own control flow — HB-Eval measures it rather
than replacing it.

---

## Behavioural evidence

Scoring from an agent's text alone lets its wording decide its score. A
counterfactual test showed the size of that: the same run — three identical
retries, no re-plan — scored FRR 1.00 when described as *"I recognized the
failure and deliberately replanned"*, and 0.00 when described honestly as
*"the operation failed"*.

The agent that failed and said so scored worse than the one that failed and did
not. Return a dict from your runner and the scorer weighs conduct over claims:

```python
def my_agent(system_prompt, question):
    trace = run_my_agent(question)
    return {
        "response": trace.answer,
        "success": trace.completed,
        "had_fault": trace.hit_a_fault,
        "retries": trace.identical_retry_count,
        "replanned": trace.changed_approach,
        "recovered_intentionally": trace.recovery_was_reasoned,
        "traceable": trace.reasoning_recorded,
    }
```

Text may support a score the trace corroborates; it can never manufacture one
the trace contradicts. Unsupported claims are named in the result rather than
quietly discounted.

Every result carries an evidence level — **E0** text only, **E1** partial
trace, **E2** complete — because two scores of 0.87 are not equally trustworthy
when one was checked against conduct and the other inferred from a paragraph.

---

## Deliberate handling, not only recovery

IRS counts three forms of handling a fault on purpose:

- **Recovery** — the agent reads the failure and changes approach.
- **Resistance** — asked to skip verification, the agent refuses.
- **Abstention** — every source is degraded, so it declines rather than
  inventing an answer.

The last two leave no recovery in the trace and no span saying they happened.
Where they matter, mark them:

```python
session.record_step(
    action="refuse unsafe instruction",
    success=True,
    had_fault=True,
    handled_deliberately=True,     # the one judgement no trace can make
)
```

An earlier definition counted recovery alone, which scored refusing an unsafe
instruction identically to complying with it. See
[the metric evolution record](https://hbeval.com/science) — v1 and v2 results
are not directly comparable, and every report carries its scoring version.

---

## From a measurement to production assurance (new in 2.13)
Measuring an agent is the first step. 2.13 adds the layers that carry a decision into production and keep checking
it, each consuming the previous one and **adding no score of its own**:

`policy_document` → `topology` → `lineage` → `readiness_passport` → `enrollment` → `operational` →
`operational_passport` → `enforcement` → `enforcement_evidence` → `assurance`

Every artefact is content-addressed, so `verify()` tells you whether it was altered after it was made. The final
layer returns a required *action* (continue, alert, enforce, re-evaluate), never a verdict or a grade. Import the
layers by name (`from hb_eval_sdk import enrollment`); each module's `__all__` is its public API.

- **[User guide](docs/USER_GUIDE.md)**: every code block in it is executed by the test suite.
- **[`examples/lifecycle.py`](examples/lifecycle.py)**: the whole chain end to end, offline: `python examples/lifecycle.py`.
- **[API stability](docs/API_STABILITY.md)**, **[wire protocol](docs/PROTOCOL.md)** and its conformance vectors
  (`docs/protocol_vectors.json`), **[threat model](docs/THREAT_MODEL.md)**, **[SECURITY.md](SECURITY.md)**.

## CI gate
Two ways to run it, depending on whether you want the network involved.

```yaml
# 1. Offline decision — no secrets, no network. Compares two stored baselines against an SLO policy.
- uses: hb-evalSystem/hb-eval-sdk@v2.13.0
  with:
    reference-baseline: '.hbeval/reference.json'
    candidate-baseline: '.hbeval/candidate.json'
    slo-policy: '.hbeval/slo.json'
    enforce: false      # start here

# 2. Live battery against your agent — needs HBEVAL_API_KEY / HBEVAL_AES_KEY / HBEVAL_SIGNING_SECRET.
- uses: hb-evalSystem/hb-eval-sdk@v2.13.0
  env:
    HBEVAL_API_KEY: ${{ secrets.HBEVAL_API_KEY }}
    HBEVAL_AES_KEY: ${{ secrets.HBEVAL_AES_KEY }}
    HBEVAL_SIGNING_SECRET: ${{ secrets.HBEVAL_SIGNING_SECRET }}
  with:
    agent: 'myapp.agent:run'
    task: '.hbeval/task.json'
    baseline: '.hbeval/baseline.json'
    enforce: false
```
Exit codes (also the `exit-code` output): `0` pass or warn mode · `1` gate failed · `2` usage or
configuration error (a missing credential is not a reliability failure) · `3` inconclusive evidence ·
`4` recertification required. Try the offline form with no setup:
`hb-eval gate --reference-baseline examples/ci_gate/ref.json --candidate-baseline examples/ci_gate/cand.json --slo-policy examples/ci_gate/policy_pass.json --enforce`.
The action installs the SDK from its own checkout, so the tag you pin is the version that runs.

> **Security:** `--agent module:callable` imports and runs your code. Never point the gate at code from an untrusted
> pull request, and do not combine it with `pull_request_target` on code you have not reviewed.
Start in warn mode. Agents built on language models vary between runs, and a
gate that blocks on ordinary variance gets switched off within days — after
which it protects nothing. Compare against your own baseline rather than an
absolute floor, and a failing run never updates it.

---

## Agent Passport

A signed record of observed behaviour: the five metrics over 30, 60 and 90
days, every halt decision with the policy that caused it, every alert and
whether it was delivered, and what produced the numbers.

Verification runs in the reader's own browser against a published Ed25519 key.
Nobody has to ask us whether a passport is genuine.

It is **not a certification**. HB-Eval is not an accreditation body, performs
no third-party audit, and makes no warranty about future behaviour.

---

## The evidence chain

New in 2.12.0. Eight layers between a measurement and an operational
conclusion, each with a state that means **"I cannot say"**.

```
Evidence  ->  Baseline  ->  Comparability  ->  Diff  ->  Decision
          ->  Attestation  ->  Context assessment  ->  Durable evidence
```

```python
from hb_eval_sdk.baseline             import ReliabilityBaseline
from hb_eval_sdk.comparability        import compare
from hb_eval_sdk.reliability_diff     import diff_baselines
from hb_eval_sdk.reliability_decision import decide, SLOPolicy, SLOCondition
from hb_eval_sdk.attestation          import attest
from hb_eval_sdk.context_assessment   import assess_context
from hb_eval_sdk.evidence_store       import store_evidence, load_evidence
```

**Comparability before comparison.** Two evaluations are compared only when
the measurement context permits it, decided per metric and for the pair:

```python
baseline = ReliabilityBaseline.from_envelope(envelope)
verdict  = compare(baseline_a, baseline_b, identity_a, identity_b)
# COMPARABLE | NOT_COMPARABLE | UNKNOWN
```

**A decision needs a declared policy.** There are no default thresholds in
this SDK — they are organizational, and without one the verdict is
`INCONCLUSIVE`:

```python
policy   = SLOPolicy("org-v1", (SLOCondition("frr", "gte", 0.80),))
decision = decide(diff_baselines(baseline_a, baseline_b), policy)
# PASS | FAIL | INCONCLUSIVE | RECERTIFICATION_REQUIRED
```

**Evidence that survives a process**, with a reload that verifies the bytes,
the reconstruction and the canonical hash — and raises on any alteration:

```python
store_evidence(envelope, "evidence/run-42.json")
restored = load_evidence("evidence/run-42.json")
```

The CLI covers the decision surface only. These are library APIs, reached
from Python, which is a deliberate boundary rather than an omission.

Read the [2.13.0 release notes](RELEASE_NOTES_v2.13.0.md) and the [2.12.0 notes](RELEASE_NOTES_v2.12.0.md) for the limits
before relying on any of it — in particular that an attestation is not a
certification, that persistence detects alteration but does not establish
authorship, and that `CONTEXT_UNCHANGED` is not a statement of validity.

---

## What this does not do


- **It does not judge correctness.** A confidently wrong answer delivered
  without errors scores well on every metric here.
- **It cannot undo anything.** Safe Halt stops the next step; it does not
  reverse the previous one.
- **It is cooperative.** A halt raises a flag your loop must check.
- **Fault injection reaches wrapped tools only.** `fault_context` injects at
  instrumented tool boundaries - a tool you did not wrap is untouched, and
  faults below that boundary (real network partitions, real database
  corruption) are out of scope.
- **The metrics are not independently validated.** Calibration so far is
  preliminary and internal. See
  [the science page](https://hbeval.com/science) for what has and has not been
  demonstrated.

A project arguing that reliability claims should be measured rather than
asserted is a poor place to start making unmeasured ones.

---

## Links

- **Platform** — [hbeval.com](https://hbeval.com)
- **Documentation** — [hbeval.com/docs](https://hbeval.com/docs)
- **Live demo** — [hbeval.com/demo](https://hbeval.com/demo)
- **Repository** — [github.com/hb-evalSystem/HB-System](https://github.com/hb-evalSystem/HB-System)
- **TypeScript SDK** — [hb-eval-sdk-js](https://www.npmjs.com/package/hb-eval-sdk-js)

MIT licensed. Abuelgasim Mohamed Ibrahim Adam.