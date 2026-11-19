"""
hb_eval_sdk.otel_bridge
========================
Connects an OpenTelemetry tracer to HB-Eval monitoring, so reliability is
measured from telemetry the agent already emits.

WHAT THIS REPLACES
------------------
Before: every step annotated by hand, with the agent's own author judging
whether a fault occurred and whether recovery was deliberate.

    with client.monitor(agent_id="a") as m:
        for step in agent.run(task):
            m.record_step(action=..., success=..., had_fault=...,
                          recovered_intentionally=..., traceable=...)

After: one line at startup, and nothing in the agent loop.

    import hb_eval_sdk.auto

THE CONSTRAINT THAT SHAPES THIS FILE
-------------------------------------
on_end runs SYNCHRONOUSLY on the agent's own thread, at the moment each span
closes. Anything slow here is added directly to the latency of the system being
measured — the failure this project spent a release fixing in monitoring.py.

So on_end does three things and no more: build a small record, run pure
derivation, enqueue. Every network call still happens on the monitoring
worker thread, exactly as before. Session close is the one operation that can
block (it joins the worker), so it is moved to a daemon thread rather than
made to wait at the end of the agent's run.

SESSION BOUNDARIES
------------------
Children end before their parent, so the agent's root span is the last to
arrive — which makes it the natural close signal. The root's START opens the
session.

Broken span lineage across async boundaries is the most commonly reported
failure mode with these conventions, so a tool span arriving with no open
session does not get dropped: it opens an implicit session instead. Losing
telemetry silently is worse than an imperfectly bounded one.

OPTIONAL DEPENDENCY
-------------------
opentelemetry-sdk is imported lazily and its absence is reported clearly rather
than crashing the caller's process at import time.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Optional

from .otel_derive import SpanRecord, StepDeriver, derivation_notes

logger = logging.getLogger("hb_eval_sdk.otel")

# How long an implicitly-opened session may run before being closed on its own.
# Without this, a trace whose root span never arrives — a crash, a dropped
# async context — would hold a session open indefinitely.
IMPLICIT_SESSION_MAX_STEPS = 10_000


def _require_otel():
    try:
        from opentelemetry.sdk.trace import SpanProcessor  # noqa: F401
        return True
    except ImportError as exc:
        raise ImportError(
            "OpenTelemetry bridging needs the OTel SDK. Install it with:\n"
            "    pip install 'hb-eval-sdk[otel]'\n"
            "or:\n"
            "    pip install opentelemetry-sdk opentelemetry-api"
        ) from exc


def _to_record(span: Any) -> SpanRecord:
    """Convert an OTel ReadableSpan into the neutral record.

    Everything OTel-specific stops here. Defensive throughout because span
    implementations differ between instrumentation packages, and a malformed
    span must degrade to a partial record rather than raise inside the agent's
    thread.
    """
    try:
        attributes = dict(span.attributes or {})
    except Exception:
        attributes = {}

    status_code = "UNSET"
    try:
        status_code = span.status.status_code.name
    except Exception:
        pass

    events = []
    try:
        for ev in (span.events or []):
            events.append({
                "name": getattr(ev, "name", ""),
                "attributes": dict(getattr(ev, "attributes", {}) or {}),
            })
    except Exception:
        pass

    duration_ms = 0.0
    try:
        if span.end_time and span.start_time:
            duration_ms = (span.end_time - span.start_time) / 1_000_000
    except Exception:
        pass

    return SpanRecord(
        name=getattr(span, "name", "") or "",
        attributes=attributes,
        status_code=status_code,
        events=events,
        is_root=getattr(span, "parent", None) is None,
        duration_ms=duration_ms,
    )


class HBEvalSpanProcessor:
    """Feeds HB-Eval monitoring from a span stream.

    Registered on the caller's TracerProvider. Subclasses OTel's SpanProcessor
    at construction time rather than at import, so this module can be imported
    without the OTel SDK present.
    """

    def __init__(self, client: Any, *, agent_id: Optional[str] = None,
                 halt_policy: Optional[dict] = None,
                 on_threshold_breach: Optional[Any] = None,
                 thresholds: Optional[dict] = None,
                 stream: bool = True) -> None:
        self._client = client
        self._agent_id = agent_id
        self._halt_policy = halt_policy
        self._on_breach = on_threshold_breach
        self._thresholds = thresholds
        self._stream = stream

        self._session = None
        self._deriver: Optional[StepDeriver] = None
        self._root_span_id = None
        # Spans can end on several threads; the session and deriver are not
        # designed for concurrent mutation, so all state changes are serialised.
        self._lock = threading.Lock()

    # ── OTel SpanProcessor interface ────────────────────────────────────────
    def _warn_once(self, key: str, message: str) -> None:
        """A monitoring failure must never reach the agent, but it must not be invisible either:
        a session that silently never opens looks exactly like an agent with nothing to report.
        The first occurrence of each kind is a WARNING; repeats drop to DEBUG so a hot path
        cannot flood the log."""
        warned = self.__dict__.setdefault("_warned", set())
        if key in warned:
            logger.debug(message, exc_info=True)
            return
        warned.add(key)
        logger.warning("%s (further occurrences of this are logged at DEBUG)", message, exc_info=True)

    def on_start(self, span: Any, parent_context: Optional[Any] = None) -> None:
        """Open a session when the agent's root span begins."""
        try:
            rec = _to_record(span)
            if not rec.is_agent_root():
                return
            with self._lock:
                if self._session is not None:
                    # Nested or concurrent agent runs: the first one owns the
                    # session. Merging them would attribute one agent's
                    # failures to another.
                    return
                self._open(rec)
        except Exception:
            # Never let instrumentation break the traced application.
            self._warn_once("on_start", "HB-Eval on_start failed; this span was not observed")

    def on_end(self, span: Any) -> None:
        """Record a step, or close the session when the root span ends.

        Runs on the agent's thread. Kept to a record build, a pure derivation
        and an enqueue — no I/O.
        """
        try:
            rec = _to_record(span)

            with self._lock:
                if rec.is_agent_root():
                    if self._session is not None and (
                        self._root_span_id is None
                        or self._root_span_id == self._span_id(span)
                    ):
                        self._close_async()
                    return

                if self._session is None:
                    # Orphaned span: lineage broken, or instrumentation that
                    # emits tool spans without an agent root. Open a session
                    # rather than discard real telemetry.
                    self._open(rec, implicit=True)

                if self._session is None or self._deriver is None:
                    return

                step = self._deriver.consume(rec)
                if step is not None:
                    self._session.record_step(**step.as_record_step_kwargs())

                if self._deriver.step_count >= IMPLICIT_SESSION_MAX_STEPS:
                    logger.warning(
                        "HB-Eval session reached %d steps without a root span "
                        "ending; closing it.", IMPLICIT_SESSION_MAX_STEPS,
                    )
                    self._close_async()
        except Exception:
            self._warn_once("on_end", "HB-Eval on_end failed; this span was not recorded")

    def shutdown(self) -> None:
        """Close any open monitoring session. Called by the tracer provider on shutdown."""
        with self._lock:
            self._close_async()

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        """Always returns True: this processor buffers nothing, because sessions stream through their own worker."""
        return True

    # ── Internals ───────────────────────────────────────────────────────────
    @staticmethod
    def _span_id(span: Any):
        try:
            return span.get_span_context().span_id
        except Exception:
            return None

    def _open(self, rec: SpanRecord, *, implicit: bool = False) -> None:
        """Start a monitoring session. Caller holds the lock."""
        agent_id = (
            self._agent_id
            or rec.attributes.get("gen_ai.agent.name")
            or "otel-agent"
        )
        try:
            session = self._client.monitor(
                agent_id=str(agent_id),
                halt_policy=self._halt_policy,
                on_threshold_breach=self._on_breach,
                thresholds=self._thresholds,
                stream=self._stream,
                # Carried on the session so a consumer of the results can see
                # that these metrics were derived, by which method, and what
                # that method cannot know. A limitation that does not travel
                # with the data gets reported as fact eventually.
                source="otel",
                derivation=derivation_notes(),
                implicit_session=implicit,
            )
            session.__enter__()
        except Exception:
            self._warn_once("open", "HB-Eval could not open a monitoring session; this run is not monitored")
            return

        self._session = session
        self._deriver = StepDeriver()

    def _close_async(self) -> None:
        """Close the session off the agent's thread. Caller holds the lock.

        Closing joins the streaming worker, which can take up to its timeout.
        That wait belongs on a daemon thread rather than at the end of the
        caller's run: this module must not be the reason an agent finishes
        late, even by a little, even once.
        """
        session, self._session = self._session, None
        self._deriver = None
        self._root_span_id = None
        if session is None:
            return

        def _finish():
            try:
                session.__exit__(None, None, None)
            except Exception:
                self._warn_once("close", "HB-Eval session close failed; its summary may not have been sent")

        threading.Thread(
            target=_finish, name="hbeval-otel-close", daemon=True
        ).start()

    # ── Introspection ───────────────────────────────────────────────────────
    @property
    def active_session(self):
        """The open session, or None. Exposed for should_halt checks."""
        return self._session


def build_processor(client: Any, **kwargs):
    """Construct a processor that satisfies OTel's SpanProcessor interface.

    The OTel base class is mixed in here, at call time, so importing this
    module never requires the OTel SDK to be installed.
    """
    _require_otel()
    from opentelemetry.sdk.trace import SpanProcessor

    class _Bridged(HBEvalSpanProcessor, SpanProcessor):
        pass

    return _Bridged(client, **kwargs)