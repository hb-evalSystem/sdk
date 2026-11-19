# hb-eval-sdk 2.12.0 — release notes

**The evidence chain.**

---

## What this release is

Until 2.12.0 the SDK measured reliability and reported numbers. It had no way
to say what a number rested on, whether two numbers could be compared at all,
or whether a conclusion drawn last week still applied.

This release adds eight layers between a measurement and an operational
conclusion.

```
Evidence  ->  Baseline  ->  Comparability  ->  Diff  ->  Decision
          ->  Attestation  ->  Context assessment  ->  Durable evidence
```

**Every layer has a state that means "I cannot say", and none of them
collapses into a positive or a negative answer:**

```
provenance      applicable · not_applicable · MISSING
comparability   COMPARABLE · NOT_COMPARABLE · UNKNOWN
per metric      COMPARABLE · NOT_COMPARABLE · NOT_APPLICABLE
decision        PASS · FAIL · INCONCLUSIVE · RECERTIFICATION_REQUIRED
context         CONTEXT_UNCHANGED · RECERTIFICATION_REQUIRED · UNDETERMINED
```

That is the release. The refusals are the point, not a side effect of
caution: a pipeline that turns missing evidence into a number produces a
verdict nobody can check.

---

## The defect this release corrects

`hb-eval gate --baseline` previously did this:

```python
drop = prev - value
if drop > max_regression:
    fail_the_build()
```

Two dictionaries of numbers, subtracted. No check of comparability, metric
version, provenance, battery identity, envelope integrity or baseline
eligibility. **Two evaluations from different batteries, different scenarios
or different metric implementations compared cleanly and blocked a pull
request.**

It now reports the numbers as an observation and makes no reliability claim
from them. The authoritative decision path is evidence-gated and reached
through the new flags.

---

## Upgrading

**Nothing breaks.** Every 2.11.0 flag, exit code and entry point is
unchanged.

```
--baseline           unchanged — legacy raw-report input, no longer produces
                     a reliability verdict
--reference-baseline NEW   } the evidence-gated decision path
--candidate-baseline NEW   } both required together
--slo-policy         NEW   } no policy, no PASS

exit 0 · 1 · 2       unchanged meanings
exit 3               NEW  INCONCLUSIVE
exit 4               NEW  RECERTIFICATION_REQUIRED
```

A pipeline branching on zero-versus-nonzero sees no change in shape. A
pipeline distinguishing `1` from `2` sees new values, never a changed meaning
of an old one.

**The CLI covers the decision surface only.** Attestation, context assessment
and evidence persistence are library APIs, reached from Python. That is a
deliberate boundary and is documented in `gate.py`.

---

## Entry points

```python
from hb_eval_sdk.baseline            import ReliabilityBaseline
from hb_eval_sdk.comparability       import compare
from hb_eval_sdk.reliability_diff    import diff_baselines
from hb_eval_sdk.reliability_decision import decide, SLOPolicy, SLOCondition
from hb_eval_sdk.attestation         import attest
from hb_eval_sdk.context_assessment  import assess_context
from hb_eval_sdk.evidence_store      import store_evidence, load_evidence
```

---

## 🔴 What 2.12.0 does NOT provide

**Read this before relying on any of it.**

### An attestation is not a certification

No issuing authority, no signature, no external anchor, no revocation. It is
tamper-evident within the producing process only. The word "certification"
appears nowhere in the artefact, and that is deliberate: an artefact calling
itself a certification while lacking all four would assert exactly what it
cannot support.

### Evidence persistence is not provenance

The store detects **alteration**. It does not establish **authorship**.
Anyone who can rewrite a stored container recomputes every digest it holds,
and the substitution verifies. Closing that needs a signature over the
container with a key the attacker does not hold, and an external anchor so
the signature cannot be replaced. Neither ships here.

### Persistence is not yet a durable evidence system

```
no retention policy      no storage backend       no indexing or retrieval
no backup or recovery    no cross-host concurrency no garbage collection
```

Evidence survives a process. That is less than being durably stored, and the
difference is left visible rather than collapsed.

### `CONTEXT_UNCHANGED` is not validity

The current context is declared by the caller, not observed at runtime, and
sampling parameters sit outside the configuration fingerprint. It means
unchanged **under the represented configuration identity** — not proof that
every provider or runtime parameter held.

### Other standing limits

- **IRS is provisional.** No judge has been validated. A provisional metric
  drives a decision only when a policy declares it eligible; silence is not
  eligibility.
- **Scope is one battery slot.** An attestation covers the slot it was issued
  for and says nothing about an agent as a whole.
- **No causal attribution.** A difference is reported, never explained.
- **No reproducible-regression claim.**
- **No default SLO thresholds.** They are organizational policy and this SDK
  holds none. Without a declared policy the verdict is `INCONCLUSIVE`.
- **All results to date come from synthetic SDK executions.** No real-agent
  empirical validation ships with this release.

---

## Verification

```
417 tests passing
Phase 0 regression baseline byte-identical across all eight phases
battery_spec_fingerprint unchanged   ce481b32763df1ca
evidence schema frozen               hb-eval-evidence/v1
storage container format             hb-eval-container/v2
```

The evidence schema and the storage container are versioned **separately**, so
a change to how evidence is stored cannot move an artefact's identity.

Every layer was closed through an assessment, a scope lock, an implementation
and a final audit, with the open limits recorded in a deferred work register
rather than left to be discovered. **Thirty items; eight closed; twenty-two
open and named.**
