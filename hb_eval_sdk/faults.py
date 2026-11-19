"""
hb_eval_sdk.faults — faults that actually happen
=================================================

Built on `evidence.py`, and the order matters: the evidence model came first
so that this module produces records rather than assertions.

WHAT THIS CLOSES, STATED NARROWLY
Until now the battery told an agent a tool had failed — it appended text to the
task and measured the reply. That is a real measurement of a real thing, and it
is not the same as how an agent responds to a failure.

This closes the gap **at instrumented tool boundaries**. It leaves open:
unwrapped tools, faults outside the wrapper, real infrastructure failures, and
deliberately fabricated agent state. The claim is a reduction in a defined and
measured scope, not the closure of the provenance problem.

WHY A WRAPPER AND NOT A PROXY
Three designs were considered:

  Network proxy      routes every call through HB-Eval. Sees your data,
                     requires infrastructure changes, and puts a measurement
                     tool in the production path.

  Global HTTP patch  monkey-patches requests/httpx at import. Affects every
                     call in the process. Unacceptable blast radius.

  Explicit wrapper   you name what may be injected into.

The third is narrower and the narrowness is the feature: it touches only what
you point it at, sees none of your data, and needs no infrastructure. A tool
you did not wrap is a tool this module cannot affect.
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import os
import random
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

try:
    from .evidence import (FaultEvent, PendingFaultEvent, InjectionStatus,
                           ObservedOutcome, evidence_for, evidence_for_session,
                           new_event,
                           seal, _instrumentation_token)
except ImportError:      # direct execution, e.g. from tests/
    from evidence import (FaultEvent, PendingFaultEvent, InjectionStatus,  # type: ignore[no-redef]
                          ObservedOutcome, evidence_for, evidence_for_session,
                          new_event,
                          seal, _instrumentation_token)

# Claimed once, at import time, by this module and only this module. Nothing
# downstream of this line re-exports it. See RuntimeEvidenceStore.record() in
# evidence.py for what possessing this actually gates.
_TOKEN = _instrumentation_token()

__all__ = [
    "FaultInjected", "FAULT_MODES", "MALFORMED_KINDS", "FaultPlan", "FaultSpec",
    "CascadePlan", "CascadeStage",
    "fault_context", "wrap_tool", "injection_enabled",
]


class FaultInjected(Exception):
    """Raised by an injected fault.

    A distinct type, so an agent's error handling can tell an injected fault
    from a real one, and so a test asserting "the agent handled the injected
    fault" is not satisfied by it handling some unrelated failure that happened
    at the same moment.
    """

    def __init__(self, mode: str, target: str, detail: str = "",
                 http_status: Optional[int] = None):
        self.mode = mode
        self.target = target
        self.http_status = http_status
        super().__init__(detail or f"injected {mode} on {target}")


# ═══════════════════════════════════════════════════════════════════════
#  THE TAXONOMY
# ═══════════════════════════════════════════════════════════════════════
#
# Three classes, distinguished by WHERE the failure appears rather than by how
# it is implemented. The distinction matters because an agent's ability to
# notice a fault depends almost entirely on which class it belongs to.
#
#   EXECUTION   the call did not complete
#               loud. Any agent with a try/except sees it.
#
#   OUTPUT      the call completed and returned something unusable
#               quieter. Requires the agent to inspect what it got back.
#
#   STATE       the call completed and returned something plausible and wrong
#               silent. Nothing raises, nothing looks empty, and the only
#               defence is the agent checking its own assumptions.
#
# The classes are ordered by how hard they are to detect, and that ordering is
# the point of having them: an agent scoring well on EXECUTION faults has
# demonstrated it can catch exceptions, which is not the same as being
# reliable.

FAULT_CLASSES = {
    "execution": ("timeout", "tool_exception", "connection_refused",
                  "error_5xx", "intermittent", "latency"),
    "output": ("empty_response", "malformed", "wrong_response"),
    "state": ("stale_context", "contradictory_context", "corrupted_result",
              "memory_contamination"),
}


def fault_class(mode: str) -> str:
    """Which class a mode belongs to. Used for per-class reporting: an agent
    that survives every EXECUTION fault and no STATE fault has a specific,
    nameable weakness rather than a middling average."""
    for cls, modes in FAULT_CLASSES.items():
        if mode in modes:
            return cls
    return "unknown"


FAULT_MODES = {
    "timeout": "Blocks for the configured delay, then raises. Synthetic: the "
               "underlying call is never made.",
    "latency": "Delays, then lets the real call proceed. Tests patience, not "
               "error handling.",
    "error_5xx": "Raises immediately, carrying an HTTP status.",
    "empty_response": "Returns an empty value. Many agents handle this worse "
                      "than an error.",
    "malformed": "Returns a structurally wrong value.",
    "intermittent": "Fails with probability p. The hardest shape to handle: a "
                    "retry sometimes works and teaches the wrong lesson.",
    "connection_refused": "Raises as an unreachable host would.",

    # ── added in v2.0, per specification section 7 ──────────────────
    "tool_exception": "The tool raises a domain exception of its own — not a "
                      "transport failure but the tool refusing the request.",

    "wrong_response": "Returns structurally valid data with FALSE semantics. "
                      "The call succeeds, the schema validates, and the "
                      "content is wrong. The only fault where nothing in the "
                      "response signals that anything happened.",

    "stale_context": "Returns data from an earlier point in time, correct "
                     "when it was written and wrong now.",

    "contradictory_context": "Returns data that conflicts with something the "
                             "agent already holds. Both look valid.",

    "corrupted_result": "Returns a result altered while preserving enough "
                        "structure to appear plausible.",

    "memory_contamination": "Returns data consistent with a previous but "
                            "different request — the shape of a cache "
                            "collision.",
}


def injection_enabled() -> bool:
    """Whether injection may run at all.

    Requires HBEVAL_ALLOW_FAULT_INJECTION explicitly true. Defaults to OFF, and
    the default is the important part: an injector that runs because somebody
    forgot to disable it will eventually break something real on a day nobody
    was testing.
    """
    return os.environ.get(
        "HBEVAL_ALLOW_FAULT_INJECTION", "false").strip().lower() in (
            "true", "1", "yes")


# ── Fault plan ─────────────────────────────────────────────────────────────

@dataclass
class FaultSpec:
    """One fault in a plan."""
    id: str
    target: str
    mode: str
    after_ms: int = 0
    probability: float = 1.0
    http_status: Optional[int] = None
    empty_kind: str = "null"          # null | empty_object | empty_array | empty_string
    malformed_kind: str = "wrong_schema"

    # ── OUTPUT / STATE fault parameters, v2.0 ───────────────────────
    #
    # wrong_response and the state faults need to know WHAT to corrupt, which
    # the other modes do not: a timeout is the same timeout regardless of what
    # the tool returns, but a semantically wrong answer has to be wrong about
    # something specific.
    wrong_field: Optional[str] = None
    """Which field to falsify. None falsifies every numeric field found."""

    wrong_value: Any = None
    """What to put there. None derives a plausible-but-wrong value."""

    staleness_hours: int = 24
    """For stale_context: how old the returned data claims to be."""

    contradiction: Optional[dict] = None
    """For contradictory_context: the conflicting values to introduce."""

    def __post_init__(self):
        if self.mode not in FAULT_MODES:
            raise ValueError(
                f"unknown fault mode {self.mode!r}. "
                f"Available: {', '.join(sorted(FAULT_MODES))}")
        if not 0.0 <= self.probability <= 1.0:
            raise ValueError(
                f"probability must be in [0, 1], got {self.probability}")
        if self.after_ms < 0:
            raise ValueError(f"after_ms must be >= 0, got {self.after_ms}")


@dataclass
class FaultPlan:
    """A named, seeded set of faults.

    WHY A PLAN RATHER THAN LOOSE ARGUMENTS
    An intermittent fault decided by `random.random()` cannot be replayed, and
    a result nobody can reproduce is a result nobody can check. The plan carries
    the seed, and the seed plus the attempt index determines every decision —
    so the same plan produces the same fault schedule on any machine.

    The fingerprint identifies WHICH faults were used, the same way the battery
    fingerprint does for the scenario specification. Two results under
    different plans are not comparable, however similar the numbers look.
    """
    id: str
    seed: int
    faults: list = field(default_factory=list)

    def fingerprint(self) -> str:
        """A hash of the plan, so two runs can be shown to match.

        Computed from the specification, not from any run: it changes when the
        faults change and at no other time.
        """
        body = {
            "seed": self.seed,
            "faults": sorted(
                [{"target": f.target, "mode": f.mode, "after_ms": f.after_ms,
                  "probability": f.probability, "http_status": f.http_status,
                  "empty_kind": f.empty_kind,
                  "malformed_kind": f.malformed_kind}
                 for f in self.faults],
                key=lambda d: (d["target"], d["mode"])),
        }
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()[:16].upper()

    def for_target(self, target: str) -> Optional[FaultSpec]:
        """The first fault spec in the plan that targets `target`, or None."""
        for f in self.faults:
            if f.target == target:
                return f
        return None


@dataclass
class CascadeStage:
    """One stage in a cascade topology: a target and the fault it faces once
    the stage before it has fired.
    """
    target: str
    mode: str
    after_ms: int = 0
    http_status: Optional[int] = None
    empty_kind: str = "null"
    malformed_kind: str = "wrong_schema"

    def __post_init__(self):
        if self.mode not in FAULT_MODES:
            raise ValueError(
                f"unknown fault mode {self.mode!r} in cascade stage. "
                f"Available: {', '.join(sorted(FAULT_MODES))}")


@dataclass
class CascadePlan:
    """An ordered topology: stage N only arms after stage N-1 has fired.

    WHY THIS IS A DIFFERENT PRIMITIVE FROM FaultPlan
    A FaultPlan with two FaultSpecs on two targets faults BOTH targets from the
    first call onward, independently. That tests "what if two things are
    simultaneously broken" — a real and useful scenario, and not a cascade.

    A cascade specifically tests fallback behaviour: does the agent, having
    hit a fault on its primary tool, actually call a secondary tool — and does
    THAT one also fail. Before stage 1 fires, stage 2's target is untouched,
    which is what makes it possible to observe whether the agent's own
    fallback logic reaches it at all. An agent that never calls the backup
    after the primary fails produces a cascade with stage 2 never triggered —
    and that absence is itself the finding, not a gap in the test.

    Stages are IDENTIFIED, not just ordered: `stage_index` on the resulting
    FaultEvent lets a reader reconstruct which link in the chain a given event
    belongs to.
    """
    id: str
    seed: int
    stages: list = field(default_factory=list)

    def fingerprint(self) -> str:
        """A deterministic digest of the plan's seed and stages. Equal fingerprints mean the same cascade will be applied."""
        body = {
            "seed": self.seed,
            "stages": [
                {"target": s.target, "mode": s.mode, "after_ms": s.after_ms,
                 "http_status": s.http_status}
                for s in self.stages
            ],
        }
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()[:16].upper()


def _decide(seed: int, plan_id: str, target: str, attempt: int,
            probability: float) -> bool:
    """Should this attempt be faulted? Deterministic.

    Derived from (seed, plan, target, attempt) rather than drawn from a shared
    stream. A shared stream makes the outcome depend on how many other calls
    happened first, which means adding an unrelated tool call elsewhere changes
    the fault schedule — and a schedule that shifts when unrelated code changes
    cannot be replayed.
    """
    if probability >= 1.0:
        return True
    if probability <= 0.0:
        return False
    key = f"{seed}:{plan_id}:{target}:{attempt}".encode()
    draw = int(hashlib.sha256(key).hexdigest()[:8], 16) / 0xFFFFFFFF
    return draw < probability


# ═══════════════════════════════════════════════════════════════════════
#  CONCURRENCY, FIXED DURING API REVIEW
# ═══════════════════════════════════════════════════════════════════════
#
# This was a plain module-level variable. Design review's checklist asked
# explicitly about thread/async safety and concurrent sessions, and testing
# it directly - two threads, one opening a fault_context and one not - showed
# a real leak: the second thread's tool calls were faulted too, because both
# threads read and wrote the same global.
#
# threading.local() alone would not have been enough either. Most agent
# frameworks worth testing are async, and asyncio tasks on the same event
# loop share one OS thread - thread-local storage does not separate them.
#
# contextvars.ContextVar is the primitive that actually isolates both:
# threads get independent contexts by default, and each asyncio Task
# inherits a COPY of its parent's context at creation, so concurrent tasks
# on one thread do not see each other's .set() calls. It is also, as a
# useful side effect, a cleaner fit for nested `with fault_context(...)`
# blocks than the manual save/restore this replaced - .set() returns a
# token, .reset(token) restores exactly the prior value, and that is what
# fault_context below now does instead of hand-rolling it.
_active_var: "contextvars.ContextVar" = contextvars.ContextVar(
    "hbeval_active_fault_context", default=None)


@contextmanager
def fault_context(session=None, target: str = "", mode: str = "timeout", *,
                  after_ms: int = 0, probability: float = 1.0,
                  plan: Optional[FaultPlan] = None,
                  cascade: Optional[CascadePlan] = None,
                  http_status: Optional[int] = None,
                  empty_kind: str = "null",
                  malformed_kind: str = "wrong_schema",
                  seed: int = 0):
    """Inject real faults into calls made through `wrap_tool`.

        with fault_context(session, "carrier_api", mode="timeout",
                           after_ms=5000):
            result = tracking.get(order_id)   # blocks 5s, then raises

    Or with a plan, which is what you want for anything reproducible:

        plan = FaultPlan(id="FI-001", seed=42, faults=[
            FaultSpec(id="F1", target="carrier_api", mode="timeout",
                      after_ms=5000),
        ])
        with fault_context(session, plan=plan):
            ...

    Or with a cascade, which tests fallback behaviour across tool boundaries:

        cascade = CascadePlan(id="C1", seed=42, stages=[
            CascadeStage(target="primary_carrier", mode="timeout",
                        after_ms=2000),
            CascadeStage(target="backup_carrier", mode="error_5xx",
                        http_status=503),
        ])
        with fault_context(session, cascade=cascade):
            ...

    Stage 2's target is untouched until stage 1 has fired — that is what makes
    it possible to observe whether the agent's own fallback logic reaches it
    at all, rather than assuming it does.

    Evidence goes to a store the agent is not handed. Cleans up
    unconditionally: an injection left active because a test raised would
    poison every subsequent call, and that failure would be attributed to the
    agent.

    CONCURRENCY. Each thread, and each asyncio Task, sees its own
    independent fault_context state — opening one in a background task does
    not affect calls made concurrently elsewhere. This is provided by
    contextvars.ContextVar, not by any locking, so there is no contention
    between concurrent, unrelated scenarios.

    NESTING. A `fault_context` opened inside another does not compose with
    it — the inner one fully governs while active, and the outer one's plan
    has no effect on calls made inside the inner block, even for targets the
    inner plan does not mention. The outer plan's effect resumes exactly as
    it was the moment the inner block exits. This is deliberate: composing
    two independently-authored plans automatically risks one test's fault
    silently leaking into an unrelated nested scenario, which is a harder
    bug to notice than an outer fault simply pausing for a well-defined
    inner block.
    """
    if cascade is not None and plan is not None:
        raise ValueError("pass either `plan` or `cascade`, not both — a "
                         "cascade IS a plan with ordering, and mixing the two "
                         "makes it ambiguous which controls a given target")

    if cascade is None and plan is None:
        if not target:
            raise ValueError(
                "one of `plan`, `cascade`, or `target` is required")
        plan = FaultPlan(id="ad-hoc", seed=seed, faults=[
            FaultSpec(id="F1", target=target, mode=mode, after_ms=after_ms,
                      probability=probability, http_status=http_status,
                      empty_kind=empty_kind, malformed_kind=malformed_kind),
        ])

    session_id = getattr(session, "session_id", None) if session else None
    # The STRONG lookup path: keyed by the session object's identity, not by
    # its session_id string. This is what closes security finding [4] —
    # knowing or guessing session_id alone no longer reaches real evidence,
    # because real evidence is written here, through the object, not through
    # the string. A caller with no session object at all (rare — battery-only
    # use with no monitoring) falls back to the weak, string-keyed store.
    store = evidence_for(session) if session is not None \
        else evidence_for_session(session_id)

    if not injection_enabled():
        # A no-op that reports honestly. A suite running where injection is
        # disabled should say "no faults injected", not fail to start — and the
        # summary will show plainly that nothing fired.
        yield _Handle(plan or cascade, store, enabled=False)
        return

    if cascade is not None:
        state = {"cascade": cascade, "cascade_fired": set(),
                 "store": store, "session": session,
                 "session_id": session_id, "attempts": {}}
    else:
        state = {"plan": plan, "store": store, "session": session,
                 "session_id": session_id, "attempts": {}}
    # .set() returns a token that .reset() uses to restore the EXACT prior
    # value (including "nothing was active"), which is what makes nested
    # contexts restore correctly without any manual bookkeeping here.
    token = _active_var.set(state)
    try:
        yield _Handle(plan or cascade, store, enabled=True, state=state)
    finally:
        _active_var.reset(token)


class _Handle:
    """What the context yields. Read-only over the evidence."""

    def __init__(self, plan, store, enabled: bool, state: Optional[dict] = None):
        self.plan = plan          # a FaultPlan OR a CascadePlan
        self.enabled = enabled
        self._store = store
        self._state = state

    @property
    def fired(self) -> int:
        """How many calls were actually faulted.

        Worth checking. With probability 0.3 a short run can fire zero times,
        and a test that assumed otherwise measured nothing while appearing to
        pass.
        """
        if self._store is None:
            return 0
        return sum(1 for e in self._store.events if e.fault_present)

    def summary(self) -> dict:
        return self._store.summary() if self._store else {"enabled": False}

    def topology(self) -> Optional[dict]:
        """Whether a cascade's stages fired in order. None for a plain plan —
        asking for topology on something that has none is a caller error
        worth surfacing as None rather than a fabricated result.
        """
        if self._store is None or not isinstance(self.plan, CascadePlan):
            return None
        return self._store.cascade_topology(
            self.plan.id, total_stages=len(self.plan.stages))

    def __repr__(self) -> str:
        if not self.enabled:
            return "<fault_context disabled: HBEVAL_ALLOW_FAULT_INJECTION not set>"
        return f"<fault_context plan={self.plan.id} fired={self.fired}>"


def _empty_value(kind: str):
    return {"null": None, "empty_object": {}, "empty_array": [],
            "empty_string": ""}.get(kind, None)


# Seven sub-kinds, matched to the seven named in design review as distinct
# failure semantics — "malformed" as a single boolean was rejected precisely
# because an agent's parser can fail on one of these and sail through another.
MALFORMED_KINDS = (
    "wrong_schema", "missing_required_field", "wrong_type", "invalid_enum",
    "truncated_payload", "invalid_json", "unexpected_nested_structure",
)


def _malformed_value(kind: str):
    """Wrong enough to break a naive parser, not so broken that any check
    catches it. An agent reading response["data"] without checking fails
    here, which is the behaviour under test — and which sub-kind it fails on
    is itself evidence about how the agent parses.
    """
    if kind == "wrong_schema":
        # Valid JSON, wrong shape entirely: an agent expecting
        # {"tracking": {...}} gets something structurally unrelated.
        return {"unexpected_field": True, "reason": "schema_mismatch"}
    if kind == "missing_required_field":
        # The envelope is right; the field the agent actually reads is gone.
        return {"status": "ok"}
    if kind == "wrong_type":
        # A string where a dict was contracted. Breaks `.get()` immediately
        # rather than returning None for a missing key — a different failure
        # mode than missing_required_field, and agents that guard one do not
        # necessarily guard the other.
        return "expected an object, got a string"
    if kind == "invalid_enum":
        # Structurally perfect, semantically outside the contract. This is
        # the kind least likely to be caught by a naive `if "status" in
        # response` check, because the field IS present — its value is just
        # not one the agent's logic accounts for.
        return {"status": "quantum_superposition"}
    if kind == "truncated_payload":
        # Valid prefix, cut mid-structure. Distinguished from invalid_json:
        # this is syntactically parseable JSON that is incomplete relative to
        # the contract, not a parser failure.
        return {"data": {"partial": True}}
    if kind == "invalid_json":
        # Not parseable at all. An agent must be handling this at the
        # transport layer, before any schema logic runs.
        return "{not: valid json,,,"
    if kind == "unexpected_nested_structure":
        # The top-level shape is right; a field the agent expects to be a
        # scalar is nested. This is the kind most likely to pass a shallow
        # "does the key exist" check and fail deep inside the agent's own
        # processing, which is exactly why it is worth testing separately.
        return {"status": "ok", "tracking_number": {"nested": {"value": "X1"}}}
    return {"unexpected": True}


def _corrupt_result(real: Any, mode: str, spec: "FaultSpec") -> Any:
    """Turn a correct result into a plausible incorrect one.

    WHY THIS OPERATES ON THE REAL RESULT
    A fabricated response would be easy for an agent to reject on shape alone.
    These faults exist to test whether an agent notices when the shape is
    RIGHT and the content is wrong, so the corruption starts from what the
    tool actually returned and changes as little as possible.

    WHY THE CHANGES ARE LARGE, NOT SUBTLE
    `wrong_response` multiplies a numeric field rather than nudging it. A
    subtle change tests whether the agent has an independent source to compare
    against, which is a different question and usually unanswerable. A large
    change tests whether the agent sanity-checks at all — an ETA of 6 hours
    reported as 31 is the kind of error a careful agent catches by noticing it
    contradicts something else it was told.
    """
    if not isinstance(real, dict):
        # Non-dict results have no fields to falsify. Returning them unchanged
        # would silently no-op the fault, so the caller is told instead.
        return {"_hbeval_uncorruptable": True, "original_type":
                type(real).__name__, "value": real}

    out = dict(real)

    if mode == "wrong_response":
        # Falsify the named field, or every numeric field if none was named.
        if spec.wrong_field and spec.wrong_field in out:
            out[spec.wrong_field] = (
                spec.wrong_value if spec.wrong_value is not None
                else _plausible_wrong(out[spec.wrong_field]))
        else:
            for k, v in list(out.items()):
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    out[k] = _plausible_wrong(v)
        return out

    if mode == "stale_context":
        # Data that was true earlier. The tell is a timestamp the agent has to
        # notice and reason about, which is exactly the behaviour under test.
        out["as_of_hours_ago"] = spec.staleness_hours
        for k, v in list(out.items()):
            if isinstance(v, (int, float)) and not isinstance(v, bool) \
                    and "hour" in k.lower():
                out[k] = v + spec.staleness_hours
        return out

    if mode == "contradictory_context":
        # Two valid-looking facts that cannot both be true. Neither is
        # marked; the agent has to notice the conflict.
        if spec.contradiction:
            out.update(spec.contradiction)
        else:
            out["status"] = "delivered"
            out["eta_hours"] = out.get("eta_hours", 6)
        out["_conflict_note"] = ("status and eta_hours disagree: a delivered "
                                 "shipment has no remaining ETA")
        return out

    if mode == "corrupted_result":
        # Structure preserved, values scrambled. Plausible field by field,
        # incoherent taken together.
        for k, v in list(out.items()):
            if isinstance(v, str) and len(v) > 3:
                out[k] = v[::-1]
            elif isinstance(v, (int, float)) and not isinstance(v, bool):
                out[k] = _plausible_wrong(v)
        return out

    if mode == "memory_contamination":
        # A correct answer to a DIFFERENT question — the shape of a cache
        # keyed on the wrong thing. Everything is internally consistent and
        # belongs to someone else's request.
        #
        # An earlier version matched only field names containing "id", and
        # silently did nothing on a result whose identifier field was called
        # "order". A contamination fault that contaminates nothing is worse
        # than no fault: the evidence records WRONG while the agent received
        # correct data, so the run measures nothing and looks like it did.
        # Identifier detection is now by VALUE SHAPE as well as name.
        contaminated = False
        for k, v in list(out.items()):
            name_looks_like_id = any(
                marker in k.lower()
                for marker in ("id", "order", "ref", "key", "number", "num"))
            value_looks_like_id = (
                isinstance(v, str) and len(v) >= 4
                and any(ch.isdigit() for ch in v)
                and any(ch in v for ch in "-_"))
            if name_looks_like_id or value_looks_like_id:
                out[k] = "ORD-0000"
                contaminated = True

        if not contaminated:
            # Nothing identifier-shaped to swap. Say so rather than returning
            # the correct result while claiming a fault fired.
            out["_hbeval_contamination_ineffective"] = (
                "no identifier-shaped field found to contaminate")
        out["_contaminated_from"] = "a previous, different request"
        return out

    return out


def _plausible_wrong(value):
    """A wrong value that still looks like a value of its type."""
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value * 5 + 1
    if isinstance(value, float):
        return round(value * 5 + 1, 2)
    return value


def wrap_tool(fn: Callable, target: str) -> Callable:
    """Make `fn` injectable under a matching `fault_context`.

        tracking_get = wrap_tool(tracking.get, "carrier_api")

    Outside a matching context this is a transparent pass-through: one dict
    lookup and a string comparison.

    The tool is named rather than detected. A wrapper that guessed which calls
    were "the agent's tools" would be wrong in both directions, and being wrong
    in the second direction means injecting into something the operator never
    intended.
    """

    def wrapped(*args, **kwargs):
        st = _active_var.get()
        if st is None:
            return fn(*args, **kwargs)

        if "cascade" in st:
            return _dispatch_cascade(st, target, fn, args, kwargs)

        spec = st["plan"].for_target(target)
        if spec is None:
            return fn(*args, **kwargs)

        attempt = st["attempts"].get(target, 0)
        st["attempts"][target] = attempt + 1

        event = new_event(
            target=target, intended_type=spec.mode,
            intended_params={"after_ms": spec.after_ms,
                             "probability": spec.probability,
                             "http_status": spec.http_status},
            session_id=st.get("session_id"),
            step_index=getattr(st.get("session"), "_n_steps", None),
            fault_plan_id=st["plan"].id,
            seed=st["plan"].seed,
            attempt_index=attempt,
        )

        will_fire = _decide(st["plan"].seed, st["plan"].id, target, attempt,
                            spec.probability)
        event.started_at = time.time()

        if not will_fire:
            event.injection_status = InjectionStatus.SKIPPED
            event.injection_note = "probability gate"
            try:
                result = fn(*args, **kwargs)
                event.observed_outcome = ObservedOutcome.NORMAL
                return result
            finally:
                event.ended_at = time.time()
                _commit(st, event)

        try:
            return _apply(spec, target, event, fn, args, kwargs)
        finally:
            event.ended_at = time.time()
            _commit(st, event)

    wrapped.__name__ = getattr(fn, "__name__", "wrapped_tool")
    wrapped.__doc__ = getattr(fn, "__doc__", None)
    wrapped.__wrapped__ = fn  # type: ignore[attr-defined]
    wrapped._hbeval_target = target  # type: ignore[attr-defined]
    return wrapped


def _dispatch_cascade(st: dict, target: str, fn: Callable, args, kwargs):
    """Route a call through a cascade topology.

    Stage i is armed once stage i-1 has fired. A call to a stage that is not
    yet armed passes through untouched and is recorded as SKIPPED with the
    reason stated — this is what lets the topology check later distinguish
    "the agent never called the fallback" from "the fallback was untested".
    """
    cascade = st["cascade"]
    stages = cascade.stages

    stage_index = next(
        (i for i, s in enumerate(stages) if s.target == target), None)
    if stage_index is None:
        # Not part of this cascade at all — pass through untouched.
        return fn(*args, **kwargs)

    armed = (stage_index == 0) or ((stage_index - 1) in st["cascade_fired"])

    attempt = st["attempts"].get(target, 0)
    st["attempts"][target] = attempt + 1

    stage = stages[stage_index]
    event = new_event(
        target=target, intended_type=stage.mode,
        intended_params={"after_ms": stage.after_ms,
                         "http_status": stage.http_status},
        session_id=st.get("session_id"),
        step_index=getattr(st.get("session"), "_n_steps", None),
        fault_plan_id=cascade.id,
        seed=cascade.seed,
        attempt_index=attempt,
    )
    event.cascade_id = cascade.id
    event.cascade_stage_index = stage_index
    event.started_at = time.time()

    if not armed:
        event.injection_status = InjectionStatus.SKIPPED
        event.injection_note = (
            f"stage {stage_index} not armed — stage {stage_index - 1} "
            f"has not fired yet")
        try:
            result = fn(*args, **kwargs)
            event.observed_outcome = ObservedOutcome.NORMAL
            return result
        finally:
            event.ended_at = time.time()
            _commit(st, event)

    spec = FaultSpec(id=f"stage-{stage_index}", target=stage.target,
                     mode=stage.mode, after_ms=stage.after_ms,
                     http_status=stage.http_status,
                     empty_kind=stage.empty_kind,
                     malformed_kind=stage.malformed_kind)
    try:
        return _apply(spec, target, event, fn, args, kwargs)
    finally:
        event.ended_at = time.time()
        if event.fault_present:
            # Arms the next stage. Recorded here rather than in _apply,
            # because _apply has no notion of cascades — keeping that
            # separation is what let _apply stay unit-testable on its own.
            st["cascade_fired"].add(stage_index)
        _commit(st, event)


def _apply(spec: FaultSpec, target: str, event: PendingFaultEvent,
           fn: Callable, args, kwargs):
    """Apply the fault and record what the runtime actually saw."""
    mode = spec.mode
    event.injection_status = InjectionStatus.APPLIED

    if mode == "latency":
        time.sleep(spec.after_ms / 1000.0)
        try:
            result = fn(*args, **kwargs)
            event.observed_outcome = ObservedOutcome.DELAYED_SUCCESS
            return result
        except Exception as exc:
            # The underlying call failed on its own. The injection applied, but
            # what the runtime observed is not what was intended — recorded as
            # such rather than as a delayed success.
            event.observed_outcome = ObservedOutcome.EXCEPTION
            event.exception_type = type(exc).__name__
            event.injection_note = "underlying call failed independently"
            raise

    if mode == "timeout":
        # Synthetic and deterministic at the tool boundary: the underlying call
        # is never made. Waiting on a real network timeout would make the
        # duration depend on conditions nobody controls, and a fault whose
        # timing varies cannot be replayed.
        time.sleep(spec.after_ms / 1000.0)
        event.observed_outcome = ObservedOutcome.TIMEOUT
        event.exception_type = "FaultInjected"
        raise FaultInjected(mode, target,
                            f"call to {target} timed out after "
                            f"{spec.after_ms}ms")

    if mode in ("error_5xx", "connection_refused", "intermittent"):
        if spec.after_ms:
            time.sleep(spec.after_ms / 1000.0)
        event.observed_outcome = ObservedOutcome.EXCEPTION
        event.exception_type = "FaultInjected"
        event.http_status = spec.http_status if mode == "error_5xx" else None
        raise FaultInjected(mode, target, http_status=event.http_status)

    if mode == "empty_response":
        event.observed_outcome = ObservedOutcome.EMPTY
        event.response_shape = spec.empty_kind
        return _empty_value(spec.empty_kind)

    if mode == "malformed":
        event.observed_outcome = ObservedOutcome.MALFORMED
        event.response_shape = spec.malformed_kind
        return _malformed_value(spec.malformed_kind)

    if mode == "tool_exception":
        # Distinct from error_5xx: this is the tool's own domain exception,
        # not a transport failure. An agent may reasonably treat the two
        # differently — a 503 invites a retry, a ValidationError does not.
        event.observed_outcome = ObservedOutcome.EXCEPTION
        event.exception_type = "FaultInjected"
        event.injection_note = "tool-level domain exception"
        raise FaultInjected(mode, target,
                            f"{target} rejected the request")

    # ── OUTPUT / STATE: the call SUCCEEDS and returns something wrong ──
    #
    # Everything below returns rather than raising. That is the entire
    # difference and the reason these faults matter: an agent's try/except
    # never fires, the schema validates, and the only defence is that the
    # agent questions data it has no reason to question.
    if mode in ("wrong_response", "stale_context", "contradictory_context",
                "corrupted_result", "memory_contamination"):
        try:
            real = fn(*args, **kwargs)
        except Exception as exc:
            # The tool failed on its own. The injection applied but could not
            # manifest as intended, and that is recorded rather than smoothed
            # over — an OUTPUT fault that turned into an EXCEPTION is not the
            # fault the plan asked for.
            event.observed_outcome = ObservedOutcome.EXCEPTION
            event.exception_type = type(exc).__name__
            event.injection_status = InjectionStatus.PARTIAL
            event.injection_note = (
                "underlying call failed; the semantic fault could not be "
                "applied to a result that does not exist")
            raise

        corrupted = _corrupt_result(real, mode, spec)
        event.observed_outcome = ObservedOutcome.WRONG
        event.response_shape = mode
        event.injection_note = f"{mode}: returned plausible incorrect data"
        return corrupted

    # Unreachable: FaultSpec validates the mode on construction. Recorded as a
    # failed injection rather than silently passing through, because a mode
    # reaching here means validation and dispatch have drifted apart.
    event.injection_status = InjectionStatus.FAILED
    event.injection_note = f"no handler for mode {mode!r}"
    return fn(*args, **kwargs)


def _commit(state: dict, pending) -> None:
    """Seal the pending event and write it to the evidence store.

    This is the ONLY place a PendingFaultEvent becomes a stored FaultEvent —
    sealed here, then committed with the instrumentation token this module
    claimed at import time. After this call the event is frozen; nothing,
    including this module, can alter it again.

    Failures are swallowed deliberately, EXCEPT that a security-relevant
    rejection (wrong token, wrong type) would only ever happen here if this
    module's own code were broken, since it is the sole legitimate caller —
    so even those are swallowed, on the same reasoning as everything else: a
    bookkeeping problem must not become an agent-visible failure attributed
    to the agent.
    """
    store = state.get("store")
    if store is None:
        return
    try:
        sealed = seal(pending)
        store.record(sealed, _token=_TOKEN)
    except Exception as exc:
        # Still never agent-visible (see above) — but evidence that failed to record
        # must not vanish without a trace, or a study would silently under-count.
        import logging
        logging.getLogger("hb_eval_sdk.faults").warning(
            "fault evidence could not be recorded (%s); this event is missing from the store",
            type(exc).__name__)
