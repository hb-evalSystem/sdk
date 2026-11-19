# Threat model

This document says what `hb-eval-sdk` is trying to protect, from whom, how, and where the protection stops. It
describes the package in this repository. It is a model, not an audit: it records the reasoning, and a reviewer
should challenge it.

## What the SDK is for

It produces **evidence about an agent's reliability** that a third party can check, and carries decisions made on
that evidence into production. The assets worth protecting are therefore:

1. **The integrity of the evidence**: a fault that was injected, a step that was observed, a block that happened.
2. **The integrity of the decision**: PASS/FAIL/INCONCLUSIVE and every artefact derived from it.
3. **The confidentiality of what is sent to the Gateway**: payloads and the API key.
4. **The availability of the agent**: monitoring must never be the reason an agent stops working.

## Trust boundaries

```text
 agent code ──(in-process)── SDK instrumentation ──(HTTPS, AES-GCM, HMAC)── Gateway ── platform
      │                              │
      └── tools ◄── enforcement boundary (sidecar / proxy; out of process, R8) ──► tool's own log
```

The agent under test is **not trusted**. The instrumentation is trusted only as far as it can be, because it
shares a process with the agent (see "What this does not stop").

## Adversaries and what stops them

| Adversary | Goal | Mitigation in this package | Test |
|---|---|---|---|
| **The agent under test** | Write or edit its own evidence; make a failure look like a success | Evidence is written only by instrumentation holding a private token; stores are keyed by object identity, not a guessable string; committed events are frozen; provenance is labelled `runtime_observed` | `tests/test_fault_injection_security.py`; `conformance.py`; `mutation_check.py` |
| **The agent** | Author its own enforcement evidence | `OperationalRecorder.record` refuses `ENFORCEMENT` and enrolment events; they can only be added from sealed artefacts | `test_enforcement_evidence.py` |
| **The agent** | Be credited for a block it could have ignored | A cooperative, in-process mechanism is always recorded as not independent | `test_enforcement_contract.py`, R8 two-identity proof |
| **Anyone** | Alter an artefact after it was issued | Every artefact is content-addressed; `verify()` recomputes the hash; `from_dict` re-verifies on load | per-module suites |
| **Network attacker** | Read or forge Gateway traffic | AES-256-GCM encryption; HMAC-SHA256 under a *separate* secret over nonce, timestamp and ciphertext; fresh nonce per attempt; HTTPS required for non-loopback gateways | `tests/test_client_network.py`, `docs/protocol_vectors.json` |
| **A hostile or broken Gateway response** | Make the SDK report a pass | A response with no verdict is `UNSAFE`; an unrecognised verdict is an error; a non-numeric metric fails the gate closed | `test_client_network.py`, `test_gate_legacy.py` |
| **An unreachable Gateway** | Be treated as "fine" | `SafeHaltError`; retries re-encrypt with fresh nonces; a negative retry count is refused rather than becoming a silent no-op | `test_client_network.py` |
| **A prompt-injected assistant (MCP)** | Point the platform at an internal host, or pass hostile arguments | Public-HTTPS-only agent URL filter (the Gateway re-checks with DNS); bounded integers; consent is required and explicit; errors never echo exception text | `tests/test_mcp_server.py` |
| **A malicious pull request (CI)** | Inject workflow commands; run code with secrets | Annotation text is escaped; action inputs reach the shell through the environment, never the script; workflows pin third-party actions to commit SHAs and request least privilege | `test_gate_legacy.py`, `ci.yml` |
| **Malformed input** | Crash or confuse the SDK | Fuzzed: payload validation, policy normalisation, protocol parsing, URL validation, text extraction | `tests/test_fuzz.py` |
| **A dependency with a known flaw** | Compromise the environment | Floors set to advisory-free versions; weekly `pip-audit`; Dependabot | `ci.yml` |

## Availability: monitoring must not break the agent

Telemetry, streaming and the OpenTelemetry bridge are best-effort and isolated: a failing client, a malformed
span or a broken callback degrades monitoring and never raises into the agent. `import hb_eval_sdk.auto` cannot
fail an application whatever its environment holds. Failures of this kind are **reported once** as warnings, not
swallowed silently, because a session that silently never opens is indistinguishable from an agent with nothing
to report.

## What this does not stop

State these plainly, because they are the limits of the guarantee.

1. **Code running inside the agent's process can defeat in-process instrumentation** by reflection. The direct
   paths are closed and tested; Python offers no way to close reflection. This is why R8 enforcement is defined
   as a boundary *outside* the agent's process, and why the SDK never labels an in-process block as independent.
2. **Attestations and passports from this package are unsigned and unanchored.** They are tamper-evident within a
   process, not independently verifiable. Signing and anchoring are properties of a service that holds a key.
3. **A shared-secret enforcement API is a stop-gap.** The sidecar-to-Gateway link needs workload identity
   (mTLS) in a real deployment.
4. **`gate --agent module:callable` imports and runs your code.** Never point it at code from an untrusted pull
   request, and do not run it under `pull_request_target` with that code checked out.
5. **The metrics describe observed behaviour.** They do not predict production failures, and no document in this
   project may say they do.
6. **Python 3.9 cannot be advisory-free** (see `SECURITY.md`).
7. **This is automated analysis plus tests.** It is not an independent security audit or a penetration test.
