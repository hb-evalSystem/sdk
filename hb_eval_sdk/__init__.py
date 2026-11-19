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

# Framework integrations are LAZY. Each integration module is plain Python that talks to its
# framework by duck typing, so importing one never requires the framework; the names below are
# resolved on first access (PEP 562) instead of at `import hb_eval_sdk`. Eager imports made every
# user of the core SDK pay for LangChain/LangGraph/CrewAI whether or not they used them (LangChain's
# callback base class alone cost ~200 ms), and a broken framework install could break an unrelated
# `import hb_eval_sdk`. A framework is needed only when you call into it.
_LAZY_ATTRIBUTES = {
    "adapt_langchain_agent": ("langchain_integration", "adapt_langchain_agent"),
    "HBEvalLangChainCallback": ("langchain_integration", "HBEvalLangChainCallback"),
    # Backwards-compatible alias: HBEvalCallback was the name in <=2.2.0.
    "HBEvalCallback": ("langchain_integration", "HBEvalLangChainCallback"),
    "adapt_langgraph_agent": ("langgraph_integration", "adapt_langgraph_agent"),
    "adapt_langgraph_node": ("langgraph_integration", "adapt_langgraph_node"),
    "adapt_crewai_agent": ("crewai_integration", "adapt_crewai_agent"),
    "adapt_crewai_crew": ("crewai_integration", "adapt_crewai_crew"),
    "HBEvalCrewObserver": ("crewai_integration", "HBEvalCrewObserver"),
}

# Submodules that are part of the public API. Each defines its own `__all__`, which IS the supported
# surface of that module; anything underscore-prefixed or not listed there is private. They are
# reached as `hb_eval_sdk.enrollment` or `from hb_eval_sdk import enrollment` and are deliberately NOT
# flattened into this namespace: several export the same short names (for example `Decision` in both
# `enforcement` and `enforcement_contract`), and a flat namespace would make one silently shadow another.
PUBLIC_SUBMODULES = (
    "policy_document", "topology", "lineage", "readiness_passport", "enrollment", "operational",
    "operational_passport", "enforcement", "enforcement_evidence", "assurance",
    "protocol", "gate", "faults", "evidence", "monitoring", "policy", "contracts", "configuration",
    "validation", "battery", "attestation",
)


def __getattr__(name):
    import importlib
    if name in _LAZY_ATTRIBUTES:
        module, attribute = _LAZY_ATTRIBUTES[name]
        value = getattr(importlib.import_module(f".{module}", __name__), attribute)
        globals()[name] = value           # resolve once
        return value
    if name in PUBLIC_SUBMODULES:
        return importlib.import_module(f".{name}", __name__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | set(_LAZY_ATTRIBUTES) | set(PUBLIC_SUBMODULES))


# The MCP server is NOT imported here. It requires the optional `mcp` package
# and is a standalone entry point (python -m hb_eval_sdk.mcp_server); importing
# it eagerly would make every `import hb_eval_sdk` pay for a dependency that
# most users of the library itself do not need.

__version__ = "2.13.0"

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
    fault_context = None  # type: ignore[assignment]
    _FAULT_INJECTION_AVAILABLE = False

__all__ = [
    "HBEvalClient",
    # runtime monitoring
    "MonitorSession",
    "DEFAULT_THRESHOLDS",
    # framework integrations (lazy: resolved on first access, never at import)
    "adapt_langchain_agent",
    "HBEvalLangChainCallback",
    "HBEvalCallback",
    "adapt_langgraph_agent",
    "adapt_langgraph_node",
    "adapt_crewai_agent",
    "adapt_crewai_crew",
    "HBEvalCrewObserver",
    "PUBLIC_SUBMODULES",
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