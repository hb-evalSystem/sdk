"""
HB-Eval SDK — reliable evaluation of agentic AI systems.

This package is the client for the HB-Eval reliability Gateway. It encrypts
agent trajectories, signs them, validates them locally, and submits them for
five-metric reliability evaluation and tier qualification.

Quick start:
    from hb_eval_sdk import HBEvalClient

    client = HBEvalClient(
        api_key="...",          # identifies your project (sent on each request)
        aes_key="...",          # base64 32-byte key (encrypts the payload)
        signing_secret="...",   # base64 signing secret (signs request; never sent)
    )
    result = client.evaluate({
        "trajectory": [...],
        "sub_tasks": 4,
        "constraint_violations": 0,
        "recovery_episodes": [],
        "agent_id": "my-agent",
    })
    print(result.verdict, result.tier, result.metrics)
"""

from .client import HBEvalClient
from .models import EvaluationResult, MemoryMatch, Metrics, Verdict
from .exceptions import (
    HBEvalError,
    ValidationError,
    ConnectionError,
    AuthenticationError,
    EncryptionError,
    SafeHaltError,
)

# Runtime monitoring is part of the core SDK (no third-party dependency).
from .monitoring import MonitorSession, DEFAULT_THRESHOLDS

# Framework integrations are optional: each needs its own third-party package.
# They are imported defensively so the core SDK keeps working for users who
# have installed none of them. Missing names resolve to None rather than
# raising at import time.
try:
    from .langchain_integration import adapt_langchain_agent, HBEvalLangChainCallback
    # Backwards-compatible alias: HBEvalCallback was the name in <=2.2.0.
    HBEvalCallback = HBEvalLangChainCallback
    _HAS_LANGCHAIN = True
except Exception:  # pragma: no cover
    adapt_langchain_agent = None
    HBEvalLangChainCallback = None
    HBEvalCallback = None
    _HAS_LANGCHAIN = False

try:
    from .langgraph_integration import adapt_langgraph_agent, adapt_langgraph_node
    _HAS_LANGGRAPH = True
except Exception:  # pragma: no cover
    adapt_langgraph_agent = None
    adapt_langgraph_node = None
    _HAS_LANGGRAPH = False

try:
    from .crewai_integration import (
        adapt_crewai_agent,
        adapt_crewai_crew,
        HBEvalCrewObserver,
    )
    _HAS_CREWAI = True
except Exception:  # pragma: no cover
    adapt_crewai_agent = None
    adapt_crewai_crew = None
    HBEvalCrewObserver = None
    _HAS_CREWAI = False

# The MCP server is NOT imported here. It requires the optional `mcp` package
# and is a standalone entry point (python -m hb_eval_sdk.mcp_server); importing
# it eagerly would make every `import hb_eval_sdk` pay for a dependency that
# most users of the library itself do not need.

__version__ = "2.11.0"

# ── Real runtime fault injection (new in 2.11.0) ───────────────────────
#
# Guarded, so that a partial install or a future refactor of these two
# modules cannot break `import hb_eval_sdk` for everyone else. If the
# import fails, `fault_context` is None and the rest of the SDK works
# normally.
#
# NOTE ON WHAT IS DELIBERATELY ABSENT.
# RuntimeEvidenceStore and evidence_for_session / evidence_for are NOT
# exported here. evidence.py's module docstring explains why: the
# agent-facing contract is fault_context and its companions, and the
# evidence store is reached only through the trusted dispatch path. An
# earlier draft of this block exported the store anyway, contradicting that
# decision in the one place — the public API — where it would have
# mattered. Caught during API review, before this version number went out.
#
# FaultEvent, InjectionStatus and ObservedOutcome ARE exported: a caller
# inspecting evidence needs the types to compare against.
try:
    from .faults import (
        FaultInjected, FaultPlan, FaultSpec, CascadePlan, CascadeStage,
        FAULT_MODES, MALFORMED_KINDS,
        fault_context, wrap_tool, injection_enabled,
    )
    from .evidence import FaultEvent, InjectionStatus, ObservedOutcome
    _FAULT_INJECTION_AVAILABLE = True
except ImportError:  # pragma: no cover
    fault_context = None
    _FAULT_INJECTION_AVAILABLE = False

__all__ = [
    "HBEvalClient",
    # runtime monitoring
    "MonitorSession",
    "DEFAULT_THRESHOLDS",
    # framework integrations (None when the framework is not installed)
    "adapt_langchain_agent",
    "HBEvalLangChainCallback",
    "HBEvalCallback",
    "adapt_langgraph_agent",
    "adapt_langgraph_node",
    "adapt_crewai_agent",
    "adapt_crewai_crew",
    "HBEvalCrewObserver",
    "EvaluationResult",
    "MemoryMatch",
    "Metrics",
    "Verdict",
    "HBEvalError",
    "ValidationError",
    "ConnectionError",
    "AuthenticationError",
    "EncryptionError",
    "SafeHaltError",
    # real runtime fault injection (2.11.0)
    "fault_context",
    "wrap_tool",
    "injection_enabled",
    "FaultPlan",
    "FaultSpec",
    "CascadePlan",
    "CascadeStage",
    "FaultInjected",
    "FAULT_MODES",
    "MALFORMED_KINDS",
    "FaultEvent",
    "InjectionStatus",
    "ObservedOutcome",
]