# What monitoring costs

Reproduce with `python benchmarks/overhead.py` (add `--json` for machine-readable output). The figures below
were measured once, in a Linux container, Python 3.12, with the SDK at 2.13.0. **Your numbers will differ**;
what should hold on any machine is the *shape*: the work on the agent's thread stays in microseconds, and a
slow Gateway does not make it slower.

| Operation | n | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| `record_step`, no streaming | 20,000 | 4.2 µs | 7.6 µs | 22.1 µs |
| `record_step`, streaming to a fast Gateway | 20,000 | 5.8 µs | 9.8 µs | 35.1 µs |
| `record_step`, streaming to a Gateway that takes **2 s per call** | 5,000 | 5.4 µs | 8.3 µs | 27.1 µs |
| a wrapped tool call with fault injection **disabled** (the production default) | 20,000 | 0.2 µs | 0.2 µs | 0.4 µs |
| one injected fault, end to end (context, injection, evidence record) | 3,000 | 22.2 µs | 48.0 µs | 70.5 µs |
| the same tool call, unwrapped (baseline) | 20,000 | 0.1 µs | 0.1 µs | 0.2 µs |

- **Streaming is off the agent's thread.** The slow-Gateway row is the evidence: p99 does not grow when the
  network is slow, because events are handed to a background worker. `tests/test_monitoring_session.py` asserts
  this, so a regression fails CI rather than a benchmark.
- **With fault injection disabled, a wrapped call costs about a tenth of a microsecond more than an unwrapped
  one.** The gate is checked, and nothing else happens.
- **Importing the package is not free.** In this environment a cold `import hb_eval_sdk` took a median of about
  230 ms. Most of that is the three required dependencies (`requests`, `cryptography`, `pydantic`), not this
  package's own code, and none of the optional frameworks are imported at all (`tests/test_public_api.py`
  enforces that). If start-up time matters to you, measure it in your own environment.

These are measurements of the instrumentation's cost. They say nothing about how reliable an agent is.
