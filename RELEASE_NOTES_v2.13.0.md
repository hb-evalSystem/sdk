# hb-eval-sdk 2.13.0

PyPI's latest release before this is 2.11.0; 2.12.0 was never published. This release adds R1–R10 on top
of the 2.12.0 baseline and has been verified only as stated below.

## What it adds
| Layer | Module | One line |
|---|---|---|
| R1 | `policy_document` | unified policy identity |
| R2 | `topology` | multi-agent identity and the relationship plane |
| R3 | `lineage` | relationship <-> evidence binding |
| R4 | `readiness_passport` | the V2 Readiness Passport |
| R5 | `enrollment` | production enrolment |
| R6 | `operational` | runtime operational evidence |
| R7 | `operational_passport` | the Operational Passport |
| R8 | `enforcement` | the enforcement contract (SDK half) |
| R9 | `enforcement_evidence` | enforcement as operational evidence |
| R10 | `assurance` | continuous assurance |

## Verified (re-run for this release, not quoted)
- **1,141 tests** pass on Python 3.9, 3.10, 3.11, 3.12 and 3.13 (a bare `pytest` from a fresh install; the
  optional-extras tests run where the extras are installed). The suite also passes with the core dependencies at
  their declared floors on 3.9, 3.10 and 3.13, and with the extras at theirs on 3.10 and 3.12.
- **Coverage 95%** (CI fails below 90%). `mypy` clean on the whole package under both supported `mcp` majors.
  Public API docstrings 404/404. `bandit` 0 medium or high. `flake8` hard errors 0.
- Dependencies audit clean (`pip-audit`) at their floors on 3.10-3.13, for the core and for every extra. Python
  3.9 has a documented residual: see `SECURITY.md`.
- Battery fingerprint `ce481b32763df1ca` unchanged. R8 end-to-end proof 37/37 with two OS identities, and the
  same-uid negative control fails by design (`experiments/r8_two_process/`, needs root and a `hbagent` user).
- Conformance suite 20/20, and 6/6 deliberate breakages of what it guards are caught
  (`tests/fault_injection/mutation_check.py`).
- Wheel and sdist build; `twine check --strict` passes; the wheel installs in a clean environment; the sdist alone
  installs and passes the suite; an SBOM (CycloneDX) is generated.

## Bugs fixed that you may have been bitten by
See "Fixed (found while testing)" in `CHANGELOG.md`. The ones most likely to matter: the MCP server could not start
on a fresh `pip install hb-eval-sdk[mcp]`; `evaluate()` crashed on the Gateway's `INSUFFICIENT_DATA` answer, which is what an agent with no faults gets; `HBEvalLangChainCallback` raised inside your own LangChain run;
`max_retries=0` was ignored; and a Gateway response with a non-numeric metric made the CI gate exit 1.

## Changed in this release that you must know about
- **Wire protocol 2.7.0 → 2.8.0** (additive: the enforcement surface). `MEASUREMENT_PROTOCOL_VERSION` stays
  2.7.0: nothing about how a metric is computed changed. The client now warns on a major.minor mismatch with the
  Gateway (`ProtocolMismatchWarning`); an older Gateway that does not advertise is reported as unknown.
  See `docs/PROTOCOL.md`.
- **The gateway URL must be https** (loopback excepted, or `allow_insecure_http=True`).
- **Dependency floors raised** to advisory-free versions (see `SECURITY.md`). A very old environment may need an upgrade.
- Framework integrations are lazy; `import hb_eval_sdk` no longer imports LangChain, LangGraph or CrewAI.
- `hb-eval gate` no longer requires `--agent`/`--task` on the offline decision path.

## Provenance you should know
The R1–R10 sources and tests were recovered from project transcripts, not from
a git checkout. `tests/fault_injection/conformance.py`, `tool_server.py` and
`sidecar_main.py` were rewritten; conformance is proven by a mutation battery, not assumed. See `RECOVERY_NOTES.md`.

## Limits (unchanged by this release; see `docs/THREAT_MODEL.md`)
- Attestations are unsigned and unanchored (DW-008 / DW-009 / DW-010).
- The instrumentation shares a process with the agent: not a security boundary
  against code running inside it. The R8 sidecar is the answer to that, and its
  proof is a harness, not a production deployment.
- Nothing here says the metrics predict production failures.
- Persistence for the V2 artefacts is not in the SDK (DW-043).
