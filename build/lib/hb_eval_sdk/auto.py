"""
hb_eval_sdk.auto
=================
Reliability monitoring in one line.

    import hb_eval_sdk.auto

That reads credentials from the environment, attaches a span processor to the
active tracer provider, and starts deriving reliability metrics from the
telemetry the agent already emits. Nothing in the agent loop changes.

    HBEVAL_API_KEY          required
    HBEVAL_AES_KEY          required
    HBEVAL_SIGNING_SECRET   required
    HBEVAL_AGENT_ID         optional, defaults to gen_ai.agent.name per trace
    HBEVAL_HALT_METRIC      optional, e.g. "frr" — enables Safe Halt
    HBEVAL_HALT_BELOW       optional, e.g. "0.5"
    HBEVAL_HALT_FOR_STEPS   optional, defaults to 3

For explicit control, call instrument() instead and pass a client.

WHY IMPORT-TIME SETUP IS SAFE HERE
-----------------------------------
Import side effects are usually a poor idea, so the failure modes are handled
rather than hoped away. Missing credentials, a missing OTel install, or no
tracer provider each log once and leave the application untouched — importing
this module can slow an agent down, but it cannot stop one.

WHAT THIS DOES NOT DO
---------------------
It does not instrument the agent framework itself. OpenTelemetry's own
auto-instrumentation packages already do that, are maintained by the projects
that own those frameworks, and are what every major observability platform
consumes:

    pip install opentelemetry-instrumentation-langchain
    pip install opentelemetry-instrumentation-openai

Reimplementing that would mean tracking the private internals of eight
frameworks and breaking on each of their releases. Consuming the standard
instead means any framework that emits GenAI spans is supported the day it
does, with no adapter written here.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

logger = logging.getLogger("hb_eval_sdk.auto")

_processor = None
_installed = False


def _halt_policy_from_env() -> Optional[dict]:
    """Safe Halt stays off unless explicitly configured.

    Stopping someone's agent is not a default anyone should acquire by
    importing a module.
    """
    metric = os.environ.get("HBEVAL_HALT_METRIC", "").strip().lower()
    below = os.environ.get("HBEVAL_HALT_BELOW", "").strip()
    if not metric or not below:
        return None
    try:
        return {
            "metric": metric,
            "below": float(below),
            "for_steps": int(os.environ.get("HBEVAL_HALT_FOR_STEPS", "3")),
        }
    except ValueError:
        logger.warning(
            "HB-Eval: HALT_BELOW/HALT_FOR_STEPS are not numeric; "
            "Safe Halt stays off."
        )
        return None


def instrument(client: Any = None, *, agent_id: Optional[str] = None,
               halt_policy: Optional[dict] = None,
               tracer_provider: Any = None,
               on_threshold_breach: Any = None,
               thresholds: Optional[dict] = None,
               stream: bool = True):
    """Attach HB-Eval to a tracer provider. Returns the processor, or None.

    Args:
        client: an HBEvalClient. Built from the environment when omitted.
        agent_id: overrides the per-trace gen_ai.agent.name.
        halt_policy: e.g. {"metric": "frr", "below": 0.5, "for_steps": 3}.
        tracer_provider: defaults to the globally configured one.

    Returns None rather than raising when the environment is not ready, so a
    misconfiguration degrades to "no monitoring" instead of a failed startup.
    """
    global _processor, _installed

    if _installed and _processor is not None:
        # Two processors would double-count every step.
        logger.debug("HB-Eval is already instrumented.")
        return _processor

    if client is None:
        api_key = os.environ.get("HBEVAL_API_KEY")
        aes_key = os.environ.get("HBEVAL_AES_KEY")
        signing = os.environ.get("HBEVAL_SIGNING_SECRET")
        if not (api_key and aes_key and signing):
            logger.warning(
                "HB-Eval: HBEVAL_API_KEY, HBEVAL_AES_KEY and "
                "HBEVAL_SIGNING_SECRET must all be set for automatic "
                "instrumentation. Monitoring is disabled."
            )
            return None
        from .client import HBEvalClient
        client = HBEvalClient(api_key=api_key, aes_key=aes_key,
                              signing_secret=signing)

    try:
        from .otel_bridge import build_processor
        processor = build_processor(
            client,
            agent_id=agent_id or os.environ.get("HBEVAL_AGENT_ID"),
            halt_policy=halt_policy or _halt_policy_from_env(),
            on_threshold_breach=on_threshold_breach,
            thresholds=thresholds,
            stream=stream,
        )
    except ImportError as exc:
        logger.warning("HB-Eval: %s", exc)
        return None

    try:
        if tracer_provider is None:
            from opentelemetry import trace
            tracer_provider = trace.get_tracer_provider()

        add = getattr(tracer_provider, "add_span_processor", None)
        if add is None:
            # The default no-op provider has no processors, which means tracing
            # was never configured. Saying so is more useful than appearing to
            # work and reporting nothing.
            logger.warning(
                "HB-Eval: no TracerProvider is configured, so there are no "
                "spans to read. Set one up (opentelemetry-sdk) and install an "
                "instrumentation package for your framework."
            )
            return None
        add(processor)
    except Exception:
        logger.warning("HB-Eval: could not attach to the tracer provider.",
                       exc_info=True)
        return None

    _processor, _installed = processor, True
    logger.info("HB-Eval: reliability monitoring attached to OpenTelemetry.")
    return processor


def current_session():
    """The open monitoring session, or None.

    Useful for checking should_halt inside an agent loop when Safe Halt is
    configured:

        from hb_eval_sdk.auto import current_session
        s = current_session()
        if s is not None and s.should_halt:
            break
    """
    return _processor.active_session if _processor is not None else None


def uninstrument() -> None:
    """Detach and close any open session. Mainly for tests."""
    global _processor, _installed
    if _processor is not None:
        try:
            _processor.shutdown()
        except Exception:
            logger.debug("HB-Eval shutdown failed", exc_info=True)
    _processor, _installed = None, False


# Importing this module is the whole point, so setup runs here. Every failure
# path above returns None after logging, which is what makes that acceptable.
if os.environ.get("HBEVAL_AUTO_DISABLE", "").lower() not in ("1", "true", "yes"):
    instrument()