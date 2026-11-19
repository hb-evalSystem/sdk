# HB-Eval SDK 2.13.0: provenance and what is still open

Read this before merging into your repository. It says where each part of this tree came from and which claims
have NOT been verified. Nothing here is presented as original where it is not.

## Provenance
| Part | Origin |
|---|---|
| Baseline (the 32 pre-existing modules, their tests, docs) | the uploaded `HB-Eval-SDK-v2.12.0.zip` |
| R1-R10 modules and their 313 tests | **recovered verbatim from project transcripts**, not from git history |
| `sidecar/hbeval_sidecar.py`, `run_proof.py`, `gateway_main.py`, `noncooperative_agent.py` | recovered from transcripts |
| `tests/fault_injection/conformance.py` | **written for 2.13.0** (the original was not recoverable); adopted, and proven by `mutation_check.py` |
| `tool_server.py`, `sidecar_main.py` (R8 harness) | **written for 2.13.0** |
| Everything under `.github/`, `action.yml`, `examples/`, `docs/` (guide, protocol, stability, threat model, performance), `benchmarks/`, `conftest.py` | written for 2.13.0 |
| ~490 new tests (client, MCP, gate, monitoring, integrations, CLI, contracts, fuzzing, public API, examples) | written for 2.13.0 |

## What to do first
1. **Diff against your repository before merging.** The recovered R1-R10 files are the versions shown in the
   transcripts. If your repository already holds these modules, yours win; compare them, and run this suite
   against yours. A hash manifest of every file in this tree is in `MANIFEST.sha256`.
2. Keep your original `tests/fault_injection/conformance.py` if you have one (put ours beside it as
   `conformance_rewritten.py`).

## What has NOT been verified
- **The GitHub workflows have not run on GitHub.** Every command in every job was run locally, and the workflow files
  pass `actionlint` and `shellcheck`, but the first push is the first real run, and it may be red.
- **Windows and macOS** are in CI (`os-matrix`) but were not run here. A static scan found no POSIX-only constructs in
  the package or tests.
- **PyPI trusted publishing and the `pypi` / `testpypi` environments** must be configured once by the maintainer.
- The TestPyPI rehearsal (`Rehearsal (TestPyPI)` workflow) has not been run.
- **Not an independent audit or penetration test.** See `SECURITY.md` and `docs/THREAT_MODEL.md`.
- Python 3.9 cannot be advisory-free, and its framework extras carry many advisories (see `SECURITY.md`).
- The MCP server was verified over stdio only. It must not be exposed over a network transport without an
  authentication layer in front of it.
- Real-agent behaviour: all evidence so far comes from scripted and adversarial processes, not from production agents.
- Recovered files are the versions shown in the transcripts. An in-sandbox patch that was described but never shown
  is not included.

## Reproduce
```text
pip install ".[dev]" && pytest                    # a bare run; no environment needed
python tests/fault_injection/conformance.py && python tests/fault_injection/mutation_check.py
python examples/lifecycle.py && python benchmarks/overhead.py
```
