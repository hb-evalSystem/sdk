# API stability and versioning

`hb-eval-sdk` follows [semantic versioning](https://semver.org). This page says what that promise covers.

## What is public

| Surface | Stability |
|---|---|
| `HBEvalClient` and its exceptions; `MonitorSession` and `halt_policy` / `policies` / `tool_policy` | **Stable.** Breaking changes only in a major release, with a deprecation period first. |
| The CLI: `hb-eval demo`, `gate`, `version`, and the exit codes of `gate` | **Stable.** The exit codes are a contract: CI pipelines depend on them. |
| The GitHub Action (`action.yml`) inputs and its `exit-code` output | **Stable.** |
| `fault_context`, `wrap_tool`, `FaultPlan`, `FaultSpec`, the fault modes and evidence types | **Stable.** Adding a mode is a minor release; the battery's fingerprint changes only when the battery does. |
| The V2 submodules (`policy_document`, `topology`, `lineage`, `readiness_passport`, `enrollment`, `operational`, `operational_passport`, `enforcement`, `enforcement_evidence`, `assurance`) | **Stable for the names in each module's `__all__`.** That list *is* the public surface of the module. |
| Artefact wire formats (`to_dict()` shapes and the hashes derived from them) | **Stable within a major version.** A change to what is hashed is a breaking change, because it invalidates every artefact already issued. |
| `hb_eval_sdk.mcp_server` tools and their arguments | **Stable.** Tools may gain optional arguments in a minor release. |
| Names beginning with an underscore, modules beginning with an underscore, and anything not listed in a module's `__all__` | **Private.** May change in any release. |
| `experiments/`, `sidecar/`, `tests/` | **Not part of the package API.** |

## What each number means

- **Package version** (`2.13.0`): the release. Patch = fixes. Minor = additions. Major = breaking changes.
- **Wire protocol** (`PROTOCOL_VERSION`, `2.8.0`): which requests exist and how they are signed and shaped. A new
  endpoint raises the minor. A change that would break an older peer raises the major. See `docs/PROTOCOL.md`.
- **Measurement protocol** (`MEASUREMENT_PROTOCOL_VERSION`, `2.7.0`): the protocol the *scores* were produced
  under. Results under different measurement protocols are not directly comparable, so this moves **only** when
  how a metric is computed moves, never because an endpoint was added.
- **`SCORING_VERSION`** and **battery fingerprint**: identify how metrics are computed and what was injected.

These move independently. The package can change for years without the wire or measurement protocol moving.

## Compatibility with the Gateway

The client compares its wire protocol with the Gateway's (`X-HBEval-Protocol` response header) and warns on a major
or minor mismatch (`ProtocolMismatchWarning`). A Gateway that does not advertise a version is reported as
*unknown*, never as compatible. Patch differences are never an event.

## Supported Python and dependencies

Python 3.9 and newer are tested on every release. Python 3.9 reached end of life in October 2025; the newest
`requests` and `urllib3` installable on 3.9 carry advisories whose fixes need Python 3.10 or newer (see
`SECURITY.md`), so **3.10 or newer is recommended**. Dependency floors are set to the lowest versions with no
known advisory at release time, and the suite is run at those floors.

## Deprecation

A deprecated name keeps working for at least one minor release, emits a `DeprecationWarning` that names its
replacement, and is listed under "Deprecated" in `CHANGELOG.md`. Security fixes may be exempt from this period.
