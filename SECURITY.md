# Security Policy — hb-eval-sdk

## Scope, stated plainly
This library measures and records. It is **not** a sandbox.

- **In-process instrumentation is not a security boundary.** Fault-injection
  evidence is produced inside the agent's own Python process; a determined
  adversary running code in that process can use reflection to defeat it. The
  direct paths are closed and tested (`tests/test_fault_injection_security.py`);
  nothing in Python closes reflection.
- **Attestations and passports from this package are unsigned and unanchored**
  (DW-008, DW-009, DW-010). They are tamper-evident within a process, not
  independently verifiable. Signing is a property of the hosted service.
- **The enforcement contract (R8)** is only as independent of the agent as the
  process that carries it. The sidecar harness in `experiments/r8_two_process/`
  demonstrates the property with two OS identities; it is not a deployment.

## Verification performed at release (2.13.0), and what it does not prove
- **bandit** (medium and high severity gate): 0 findings. 11 low-severity findings are triaged, not
  hidden: 8 are deliberate "observability must never break the agent" handlers
  (`monitoring.py`, `otel_bridge.py`, `client.py`), 2 are non-cryptographic randomness
  (a seeded scenario selector for reproducibility; reservoir sampling of overhead timings), 1 is a
  false positive on string constants named like credentials (`DecisionState`).
- **pip-audit**: the runtime dependencies at their declared floors report **no known advisory on
  Python 3.10–3.13**.
- **Python 3.9 residual — stated plainly.** 3.9 reached end of life in October 2025. The newest
  `requests` (2.32.5) and `urllib3` (2.6.3) installable on 3.9 carry advisories whose fixes require
  Python >= 3.10 (`PYSEC-2026-2275`, `-141`, `-142`, `-4175`, `-4176`, `-4177`). 3.9 is still supported
  and tested, but a 3.9 environment cannot be advisory-free. CI keeps these six IDs on an explicit
  allow-list so a *new* advisory on 3.9 still fails the build. If this matters to you, use 3.10 or later.
- **The optional framework extras on Python 3.9 carry many more advisories** than the core (the LangChain,
  LangGraph and LangSmith maintainers have dropped 3.9, so their fixed releases cannot be installed there). On
  Python 3.10 and 3.12 the core and every extra audit clean at their declared floors, and the integration tests
  pass at those floors. If you use `[langchain]`, `[langgraph]` or `[mcp]`, use Python 3.10 or newer.
- Dependency advisories are published after a release, not before: CI re-runs the audit weekly.
- **Fuzzing and testing**: every function that parses untrusted input (payload validation, policy rules, protocol
  versions, URLs, message content, workflow-command escaping) is property-tested; the client's network path, the MCP
  server and the gate are tested for failure behaviour; the conformance suite is itself mutation-tested.
- This is automated analysis and testing. It is not a penetration test or an independent audit, and "no known
  advisory" is not "no vulnerability". See `docs/THREAT_MODEL.md` for what the SDK does and does not defend against.

## Supported versions
Security fixes target the latest published release and the current release
candidate. Older 2.x releases are not patched.

## Reporting a vulnerability
Email **abuelgasim.hbeval@outlook.com** with: affected version, a minimal
reproduction, and what you believe the impact is. Please do not open a public
issue for an unpatched vulnerability. We will acknowledge receipt and tell you
what we can and cannot confirm; we will not claim a fix we have not verified.
