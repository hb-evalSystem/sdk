"""
hb_eval_sdk.otel_derive
========================
Turns agent telemetry into HB-Eval's reliability signals.

WHY THIS MODULE EXISTS
-----------------------
Until now, monitoring required the caller to judge their own agent:

    m.record_step(had_fault=?, recovered_intentionally=?, traceable=?)

That is two problems in one. It is an adoption barrier — nobody wants to
annotate every step by hand — and it is a measurement problem, because the
metrics then rest on self-assessment by the party being measured. A reviewer
asking "how do you trust FRR when had_fault is set by the agent's own author?"
would be asking a fair question.

This module derives those fields from OpenTelemetry GenAI spans instead:
consistent, reproducible, and not supplied by the subject of the measurement.

NO OPENTELEMETRY IMPORT HERE, ON PURPOSE
-----------------------------------------
Everything below operates on the neutral SpanRecord dataclass. otel_bridge
converts real spans into it. The separation means this logic — the part that
decides what the metrics say — is testable with zero dependencies, and the
core SDK stays stdlib-only.

WHAT IS ACTUALLY IN A SPAN
--------------------------
Verified against opentelemetry-sdk 1.44.0 rather than assumed:

    span.status.status_code        ERROR | OK | UNSET
    span.events                   an "exception" event carries exception.type
    gen_ai.operation.name         chat | execute_tool | invoke_agent | ...
    gen_ai.tool.name              which tool
    gen_ai.tool.call.arguments    the call's arguments
    span.parent                   None for the agent root
    end_time - start_time         duration

Children end before their parent, so tool spans arrive in execution order and
the agent's root span arrives last. That ordering is what makes step-by-step
monitoring possible from a span stream at all.

CONFIDENCE IS PART OF THE OUTPUT
---------------------------------
Not every field is equally knowable, and pretending otherwise is how a
measurement system starts lying. Each derived field carries a confidence level,
and the honest limits are:

  HIGH   — a fault WAS observed. An ERROR status or a recorded exception is
           direct evidence.

  LOW    — a fault was NOT observed. This is the important caveat: an agent can
           fail while returning success. A tool that answers HTTP 200 with
           stale data throws nothing, and the span looks clean. So "no error
           seen" is not "no fault occurred", and FRR derived this way measures
           resilience to DETECTED faults specifically. That distinction belongs
           in any report built on it.

  MEDIUM — intent and traceability. No span carries intent, so
           recovered_intentionally is a behavioural proxy: after a failure, did
           the agent repeat the identical call, or change what it was doing?
           Defensible, and an inference — which is why the agreement harness in
           the tests exists.

  NOT DERIVABLE — resistance and abstention. IRS v2 counts deliberate handling
           in three forms, and spans can show only two. An agent that refuses
           an unsafe instruction, or declines to answer without a reliable
           source, emits no span saying so: it simply does less. From the
           outside that is indistinguishable from an agent that gave up.

           Derived IRS therefore UNDERSTATES an agent that resists or abstains.
           Pass handled_deliberately=True on record_step where that matters —
           it is the one judgement no trace can make on your behalf.

FAULT EPISODES SPAN MORE THAN ONE STEP
---------------------------------------
The manual API assumed one step could both fault and recover, which is what an
internal retry looks like. Spans do not work that way: a failed tool call is one
span and the recovery is a later one.

So a fault EPISODE is tracked, not a fault step. Every step from the failure
until the episode resolves carries had_fault=True, because the fault condition
is present throughout — including during the attempt to recover from it. The
step that finally succeeds carries had_fault=True and success=True, which is
precisely the shape FRR reads as "the agent survived a fault", and is where the
recovery verdict lands so IRS can count it.

Marking only the failing span would make both metrics unreachable from
telemetry: FRR would see failures and never a survival, and IRS would find no
judged episode at all. Measured, not assumed — an end-to-end run produced
IRS=None until this was corrected.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# Operation names, from the GenAI semantic conventions. Isolated here as the
# only place the convention strings appear, because they are still pre-1.0 and
# the June 2026 repository split signals the work is mid-flight. When a name
# changes, it changes here and nowhere else.
OP_INVOKE_AGENT = "invoke_agent"
OP_EXECUTE_TOOL = "execute_tool"
OP_CHAT = "chat"
OP_WORKFLOW = "invoke_workflow"

ATTR_OPERATION = "gen_ai.operation.name"
ATTR_TOOL_NAME = "gen_ai.tool.name"
ATTR_TOOL_ARGS = "gen_ai.tool.call.arguments"
ATTR_AGENT_NAME = "gen_ai.agent.name"
ATTR_ERROR_TYPE = "error.type"

# Span names to fall back on when gen_ai.operation.name is absent. Several
# instrumentations set the name but not the attribute, so relying on the
# attribute alone silently drops their spans.
_NAME_PREFIXES = {
    OP_EXECUTE_TOOL: ("execute_tool", "tool.", "tool "),
    OP_CHAT: ("chat ", "chat.", "llm ", "completion"),
    OP_INVOKE_AGENT: ("invoke_agent", "agent ", "agent."),
}

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"


@dataclass
class SpanRecord:
    """A span, reduced to what reliability derivation actually needs.

    Deliberately not an OTel type. The bridge converts; this stays neutral so
    the logic can be tested without an OpenTelemetry install, and so a second
    telemetry source (OpenInference, a native adapter) can feed the same rules.
    """
    name: str = ""
    attributes: dict = field(default_factory=dict)
    status_code: str = "UNSET"          # ERROR | OK | UNSET
    events: list = field(default_factory=list)   # [{"name":..., "attributes":{...}}]
    is_root: bool = False
    duration_ms: float = 0.0

    # ── Classification ──────────────────────────────────────────────────────
    def operation(self) -> str:
        """The GenAI operation this span represents.

        Prefers the attribute, falls back to the span name. Instrumentations
        vary in which they set, and dropping spans that only carry the name
        would silently lose whole frameworks.
        """
        op = self.attributes.get(ATTR_OPERATION)
        if op:
            return str(op)
        lowered = self.name.lower()
        for canonical, prefixes in _NAME_PREFIXES.items():
            if any(lowered.startswith(p) for p in prefixes):
                return canonical
        return ""

    def is_tool_call(self) -> bool:
        return self.operation() == OP_EXECUTE_TOOL

    def is_model_call(self) -> bool:
        return self.operation() == OP_CHAT

    def is_agent_root(self) -> bool:
        return self.is_root or self.operation() in (OP_INVOKE_AGENT, OP_WORKFLOW)

    def tool_name(self) -> str:
        name = self.attributes.get(ATTR_TOOL_NAME)
        if name:
            return str(name)
        # "execute_tool search" -> "search"
        parts = self.name.split(None, 1)
        return parts[1] if len(parts) == 2 else self.name

    def tool_args(self) -> str:
        """Arguments as a comparable string, for detecting identical retries."""
        args = self.attributes.get(ATTR_TOOL_ARGS)
        return "" if args is None else str(args)

    # ── Fault detection ─────────────────────────────────────────────────────
    def has_exception(self) -> bool:
        return any(
            str(e.get("name", "")).lower() == "exception" for e in self.events
        )

    def observed_fault(self) -> bool:
        """Whether this span carries direct evidence of a fault.

        Three independent signals, any one sufficient: an ERROR status, a
        recorded exception event, or an error.type attribute. Instrumentations
        differ in which they set — some record the exception without setting the
        status — so checking only one loses real failures.
        """
        if self.status_code == "ERROR":
            return True
        if self.has_exception():
            return True
        if self.attributes.get(ATTR_ERROR_TYPE):
            return True
        return False


@dataclass
class DerivedStep:
    """One recorded step, with the confidence of each judgement attached."""
    action: str
    success: bool
    had_fault: bool
    recovered_intentionally: Optional[bool]
    traceable: bool
    replanned: bool
    confidence: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    def as_record_step_kwargs(self) -> dict:
        """Arguments for MonitorSession.record_step."""
        return {
            "action": self.action,
            "success": self.success,
            "had_fault": self.had_fault,
            "recovered_intentionally": self.recovered_intentionally,
            "traceable": self.traceable,
            "replanned": self.replanned,
            "derived": True,
            "confidence": self.confidence,
            **self.metadata,
        }


class StepDeriver:
    """Turns a stream of spans into reliability steps, in arrival order.

    Stateful by necessity: recovery and re-planning are relationships BETWEEN
    steps, not properties of one. Whether a recovery was deliberate depends
    entirely on what the agent did after the failure, so the previous step and
    any intervening model call have to be remembered.

    Feed spans in the order their instrumentation ends them, which for OTel is
    execution order for siblings.
    """

    def __init__(self) -> None:
        self._last_failed: Optional[SpanRecord] = None
        # True from the moment a fault is observed until the episode resolves.
        # Every step in between is part of the episode, which is what lets FRR
        # see a survival and IRS see a judged recovery.
        self._in_fault_episode = False
        self._model_call_since_failure = False
        self._model_call_before_tool = False
        self._steps = 0

    # ── The rules ───────────────────────────────────────────────────────────
    def _derive_recovery(self, span: SpanRecord) -> tuple[Optional[bool], str]:
        """Was this step a deliberate recovery, an accidental one, or neither?

        Returns (verdict, confidence). None means the question does not apply:
        there was no preceding failure to recover from, and IRS is undefined on
        such steps by design rather than scored as zero.

        The proxy for intent: after a failure, an agent that repeats the same
        call with the same arguments has not reasoned about anything — it is
        retrying blindly. One that consults the model first, or changes tool or
        arguments, has changed its approach. That is inference, not observation,
        and is reported as MEDIUM confidence for exactly that reason.
        """
        if self._last_failed is None:
            return None, CONFIDENCE_HIGH   # correctly not applicable

        if span.observed_fault():
            # Still failing. Not yet a recovery of any kind.
            return None, CONFIDENCE_HIGH

        same_tool = span.tool_name() == self._last_failed.tool_name()
        same_args = span.tool_args() == self._last_failed.tool_args()

        if self._model_call_since_failure:
            # The agent went back to the model between the failure and this
            # call: it reconsidered rather than repeated.
            return True, CONFIDENCE_MEDIUM
        if same_tool and same_args:
            # Byte-identical repetition with no reasoning in between.
            return False, CONFIDENCE_MEDIUM
        # Different tool, or different arguments: a changed approach, though
        # arrived at without an observed model call.
        return True, CONFIDENCE_LOW

    def _derive_traceable(self, span: SpanRecord) -> tuple[bool, str]:
        """Whether this step's decision is followable.

        Proxy: a model call preceded this tool call, so there is a recorded
        reasoning step behind the decision. An unexplained tool call — one the
        agent made with no model turn in front of it — is not auditable in the
        sense TI measures.
        """
        return self._model_call_before_tool, CONFIDENCE_MEDIUM

    # ── Entry point ─────────────────────────────────────────────────────────
    def consume(self, span: SpanRecord) -> Optional[DerivedStep]:
        """Process one span. Returns a step to record, or None.

        Model and agent spans return None: they are context that informs the
        judgement of tool calls, not steps in themselves. A step is an ACTION,
        and actions are what have consequences worth measuring.
        """
        if span.is_model_call():
            self._model_call_before_tool = True
            if self._last_failed is not None:
                self._model_call_since_failure = True
            return None

        if not span.is_tool_call():
            return None

        observed = span.observed_fault()
        recovered, rec_conf = self._derive_recovery(span)
        traceable, trace_conf = self._derive_traceable(span)

        # Within a fault episode until it resolves. A recovery attempt happens
        # under a fault condition even though the attempt itself did not throw.
        faulted = observed or self._in_fault_episode

        # Re-planning: the agent consulted the model after a failure and is now
        # trying something else.
        # A re-plan is a NEW attempt after consulting the model — so it keys on
        # whether this step itself threw, not on episode membership (which is
        # true for the recovery attempt by design).
        replanned = bool(self._model_call_since_failure and not observed)

        step = DerivedStep(
            action=span.tool_name(),
            # Success reflects THIS step's outcome. Combined with had_fault
            # above, a recovery step reads as "a fault was present and the
            # step still completed" — exactly what FRR measures.
            success=not observed,
            had_fault=faulted,
            recovered_intentionally=recovered,
            traceable=traceable,
            replanned=replanned,
            confidence={
                # Direct evidence when a fault is seen; absence of evidence is
                # not evidence of absence, so the negative case is LOW.
                # Keyed on what was OBSERVED, not on episode membership: a
                # step marked faulted because the episode is open is an
                # inference, and must not borrow the confidence of a directly
                # observed error.
                "had_fault": CONFIDENCE_HIGH if observed else (
                    CONFIDENCE_MEDIUM if faulted else CONFIDENCE_LOW),
                "success": CONFIDENCE_HIGH if observed else CONFIDENCE_LOW,
                "recovered_intentionally": rec_conf,
                "traceable": trace_conf,
                "replanned": CONFIDENCE_MEDIUM,
            },
            metadata={
                "tool": span.tool_name(),
                "duration_ms": round(span.duration_ms, 3),
            },
        )

        # Advance state for the next span.
        if observed:
            self._last_failed = span
            self._in_fault_episode = True
            self._model_call_since_failure = False
        else:
            # A clean step closes the episode: the agent is functioning again.
            self._last_failed = None
            self._in_fault_episode = False
            self._model_call_since_failure = False
        self._model_call_before_tool = False
        self._steps += 1
        return step

    @property
    def step_count(self) -> int:
        return self._steps


def derivation_notes() -> dict:
    """Machine-readable statement of what this derivation can and cannot know.

    Attached to sessions so a consumer never has to guess whether a metric was
    observed or inferred. A limitation that is not carried with the data will
    eventually be forgotten, and then reported as fact.
    """
    return {
        "method": "otel_genai_v1",
        "observed_directly": [
            "had_fault=True (ERROR status, exception event, or error.type)",
            "step sequence and tool identity",
            "step duration",
        ],
        "inferred": [
            "recovered_intentionally — behavioural proxy: model call between "
            "failure and retry, or changed tool/arguments",
            "traceable — proxy: a model call preceded the tool call",
            "replanned — proxy: model call after a failure",
        ],
        "known_limits": [
            "had_fault=False is LOW confidence: an agent can fail while "
            "returning success, and a silent failure leaves a clean span. FRR "
            "derived this way measures resilience to DETECTED faults.",
            "No span carries intent, so IRS rests on an inference and should "
            "be read as such.",
            "gen_ai.* conventions are pre-1.0; attribute names may shift.",
        ],
    }