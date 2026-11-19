"""
hb_eval_sdk/operational.py — R6: runtime operational evidence
THE QUESTION R6 IS HELD TO
    Can the SDK produce operational evidence that is AUTOMATICALLY bound to
    runtime identity and execution/session topology, without the developer
    writing an attribution for every event?
THE ANSWER, STATED PRECISELY RATHER THAN FLATTERINGLY
    Per EVENT: yes. Every event recorded inside an acting scope is attributed
    automatically — participant, agent instance, execution, session, the
    relationship being acted under, the enrollment and its passport.
    Per SCOPE: something must say who is acting. An in-process SDK cannot
    infer which agent is running from nothing. The declaration moves from
    once-per-event (R3 as delivered) to once-per-HANDOFF:
        with runtime.acting_as(B, via=delegation):
            ... every event here is B's, under that delegation ...
    Framework adapters can make even that automatic, because they already
    know the node or role that is executing (`acting_as_name`). The
    LangGraph and CrewAI adapters are NOT yet wired to call it; until they
    are, the per-handoff scope is declared by the caller. That limit is
    recorded, not hidden behind EvidenceAttribution.
    An event recorded with NO acting scope is recorded as UNATTRIBUTED. It is
    never defaulted to the system, the enrolled subject, or the last actor.
    It is kept — observation is not discarded — counted, and excluded from
    lineage, because lineage asserts a producer and none is known.
MONITORING OBSERVES; IT DOES NOT REFUSE TO OBSERVE
    Events are recorded whatever the enrollment state, each marked with the
    state in force when it happened. An agent running while SUSPENDED or
    NOT_ENROLLED is exactly the evidence R7 and R8 need; dropping it would
    hide the most important observation. Nothing is blocked here — that is
    R8.
MonitorSession IS NOT MODIFIED
    `observe_step` calls the existing `record_step` unchanged, so V1 live
    metrics behave exactly as before, and emits the operational event
    alongside it.
INTEGRITY, AND ITS LIMIT
    Events form a hash chain: each carries the previous event's hash, so a
    deleted, reordered or altered event breaks verification. This proves the
    LOG is internally consistent. It does not prove the events happened —
    the same authorship boundary as 9B T5 and DW-032.
"""
from __future__ import annotations
import hashlib
import json
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Optional
from .lineage import EvidenceAttribution, EvidenceLineage
__all__ = ["OperationalEvent", "OperationalRecorder", "OperationalLog",
           "OperationalError", "EventKind", "ATTRIBUTED", "UNATTRIBUTED",
           "LEDGER",
           "OPERATIONAL_VERSION"]
OPERATIONAL_VERSION = "hb-eval-operational/v1"
ATTRIBUTED = "ATTRIBUTED"
"""Produced by a known agent instance, inside an acting scope."""
UNATTRIBUTED = "UNATTRIBUTED"
"""An agent-level event with no known producer. Kept, never defaulted."""
LEDGER = "LEDGER"
"""Produced by the enrollment ledger, not by an agent. Provenance known."""
_GENESIS = "sha256:" + "0" * 64
class OperationalError(Exception):
    """Raised when an operational event or log is malformed, or an event is recorded by a path that is not allowed to record it."""
    pass
class EventKind:
    """The kinds of event an operational log records: STEP, FAULT, ALERT, POLICY_DIRECTIVE and CONTEXT_CHANGE
    (recorded by the agent's instrumentation), and ENROLLMENT_CHANGE and ENFORCEMENT, which can only be
    emitted from a sealed ledger or enforcement record, never recorded directly.
    """
    STEP = "STEP"
    FAULT = "FAULT"
    ALERT = "ALERT"
    POLICY_DIRECTIVE = "POLICY_DIRECTIVE"
    CONTEXT_CHANGE = "CONTEXT_CHANGE"
    ENROLLMENT_CHANGE = "ENROLLMENT_CHANGE"
    ENFORCEMENT = "ENFORCEMENT"
    ALL = (STEP, FAULT, ALERT, POLICY_DIRECTIVE, CONTEXT_CHANGE,
           ENROLLMENT_CHANGE, ENFORCEMENT)
def _h(obj) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        default=str).encode()).hexdigest()
@dataclass(frozen=True)
class OperationalEvent:
    """One event in a hash-chained operational log: its sequence number, kind, time, payload, who it is attributed to, and the hash that chains it to the previous event."""
    sequence: int
    kind: str
    at: float
    payload: dict
    # automatic attribution
    attribution: str                  # "ATTRIBUTED" | UNATTRIBUTED
    participant_id: Optional[str]
    agent_instance_id: Optional[str]
    execution_id: str
    session_id: Optional[str]
    relation_ids: tuple
    # the operational chain: enrollment -> passport
    enrollment_hash: str
    enrollment_state: str
    passport_hash: Optional[str]
    prev_hash: str
    event_hash: str = ""
    def __post_init__(self):
        if self.kind not in EventKind.ALL:
            raise OperationalError(f"unknown event kind {self.kind!r}")
        if not self.event_hash:
            object.__setattr__(self, "event_hash", _h(self._content()))
    def _content(self) -> dict:
        d = {k: getattr(self, k) for k in self.__dataclass_fields__
             if k != "event_hash"}
        d["relation_ids"] = list(self.relation_ids)
        return d
    @property
    def evidence_ref(self) -> str:
        """A stable reference of the form `OPS:<sequence>:<hash prefix>` that other artefacts can cite."""
        return f"OPS:{self.sequence}:{self.event_hash[7:23]}"
    def to_dict(self) -> dict:
        """The JSON-serialisable form, including `event_hash`."""
        return {**self._content(), "event_hash": self.event_hash}
@dataclass(frozen=True)
class OperationalLog:
    """A sealed, hash-chained snapshot of a recorder's events."""
    topology_hash: str
    execution_id: str
    session_id: Optional[str]
    events: tuple
    operational_version: str = OPERATIONAL_VERSION
    log_hash: str = ""
    def __post_init__(self):
        if not self.log_hash:
            object.__setattr__(self, "log_hash", _h(self._canonical()))
    def _canonical(self) -> dict:
        return {"topology_hash": self.topology_hash,
                "execution_id": self.execution_id,
                "session_id": self.session_id,
                "operational_version": self.operational_version,
                "events": [e.to_dict() for e in self.events]}
    def verify(self) -> dict:
        """Walk the chain and report every break: an event removed or reordered, an event that does not chain to its predecessor, or a hash that does not match its content. Returns `{"valid": bool, "problems": [...]}`."""
        problems, prev = [], _GENESIS
        for i, e in enumerate(self.events):
            if e.sequence != i:
                problems.append(f"event {i} has sequence {e.sequence}: an "
                                f"event was removed or reordered")
            if e.prev_hash != prev:
                problems.append(f"event {i} does not chain to its "
                                f"predecessor")
            if e.event_hash != _h(e._content()):
                problems.append(f"event {i} was altered")
            prev = e.event_hash
        if self.log_hash != _h(self._canonical()):
            problems.append("log content was altered")
        return {"valid": not problems, "problems": problems}
    @property
    def unattributed_count(self) -> int:
        """How many events could not be attributed to a participant."""
        return sum(1 for e in self.events if e.attribution == UNATTRIBUTED)
class OperationalRecorder:
    """Binds runtime observation to identity, topology, enrollment and
    passport, for one execution and session."""
    def __init__(self, *, topology, enrollment, execution_id: str,
                 session_id: Optional[str] = None,
                 clock: Callable[[], float] = time.time):
        if not topology.verify()["valid"]:
            raise OperationalError("the topology does not verify")
        if not enrollment.verify()["valid"]:
            raise OperationalError("the enrollment ledger does not verify")
        if enrollment.system_id != topology.system_id:
            raise OperationalError(
                f"enrollment is for system {enrollment.system_id}, topology "
                f"is {topology.system_id}")
        if not execution_id:
            raise OperationalError("an execution_id is required")
        self._topology = topology
        self._enrollment = enrollment
        self._execution_id = execution_id
        self._session_id = session_id
        self._clock = clock
        self._stack: list = []
        self._events: list = []
    # ── who is acting ────────────────────────────────────────────────
    @contextmanager
    def acting_as(self, participant_id: str, *, via: Optional[str] = None):
        """Declare ONCE, for a scope, who is acting. Every event inside is
        attributed automatically."""
        t = self._topology
        p = t.participant(participant_id)
        if p is None:
            raise OperationalError(f"{participant_id} is not in the topology")
        if not p.agent_instance_id:
            raise OperationalError(
                f"{p.name} is a {p.kind} with no agent instance; events are "
                f"attributed to the acting agent, which reaches a tool or "
                f"memory through a relation")
        if via is not None:
            rel = next((r for r in t.relations if r.relation_id == via), None)
            if rel is None:
                raise OperationalError(f"relation {via} is not in the "
                                       f"topology")
            if participant_id not in (rel.source_id, rel.target_id):
                raise OperationalError(
                    f"{p.name} is not an endpoint of {rel.kind} {via}")
            if rel.execution_id and rel.execution_id != self._execution_id:
                raise OperationalError(
                    f"{rel.kind} {via} is bound to execution "
                    f"{rel.execution_id}, not {self._execution_id}")
        self._stack.append((p, via))
        try:
            yield p
        finally:
            self._stack.pop()
    def acting_as_name(self, name: str, *, via: Optional[str] = None):
        """For framework adapters, which know the executing node or role by
        name. Resolves through the topology — the name is looked up, never
        trusted as an identity on its own."""
        matches = [p for p in self._topology.participants if p.name == name]
        if len(matches) != 1:
            raise OperationalError(
                f"{name!r} resolves to {len(matches)} participants")
        return self.acting_as(matches[0].participant_id, via=via)
    # ── recording ────────────────────────────────────────────────────
    def set_enrollment(self, enrollment):
        """Enrollments are immutable; a transition yields a new one. It must
        be the same subject."""
        old = self._enrollment
        for f in ("system_id", "subject_participant_id",
                  "configuration_fingerprint", "enrollment_policy_hash"):
            if getattr(old, f) != getattr(enrollment, f):
                raise OperationalError(f"a different enrollment ({f} differs)")
        if not enrollment.verify()["valid"]:
            raise OperationalError("the enrollment ledger does not verify")
        prev_state = old.state
        self._enrollment = enrollment
        if enrollment.state != prev_state:
            # Produced by the enrollment LEDGER, not by an agent. Its
            # provenance is known, so it is neither ATTRIBUTED to an agent nor
            # UNATTRIBUTED. Labelling it UNATTRIBUTED — as R6 first did —
            # inflated "no known producer" with events whose producer is
            # known. Found while building R7.
            self._record(EventKind.ENROLLMENT_CHANGE,
                         dict(attribution=LEDGER, participant_id=None,
                              agent_instance_id=None, relation_ids=()),
                         from_state=prev_state, to_state=enrollment.state,
                         ledger_ref=f"LEDGER:{len(enrollment.events) - 1}")
    def record(self, kind: str, **payload) -> OperationalEvent:
        """Record an agent-side event. ENROLLMENT_CHANGE and ENFORCEMENT cannot be recorded here: they are emitted by `set_enrollment` and `record_enforcement` from sealed artefacts, so an agent cannot fabricate them."""
        if kind == EventKind.ENROLLMENT_CHANGE:
            raise OperationalError(
                "ENROLLMENT_CHANGE is emitted by set_enrollment from the "
                "ledger; it cannot be recorded as an agent event")
        if kind == EventKind.ENFORCEMENT:
            raise OperationalError(
                "ENFORCEMENT is emitted by record_enforcement from a sealed "
                "boundary event; an agent cannot author its own enforcement "
                "evidence")
        if self._stack:
            p, via = self._stack[-1]
            attrib = dict(attribution=ATTRIBUTED,
                          participant_id=p.participant_id,
                          agent_instance_id=p.agent_instance_id,
                          relation_ids=(via,) if via else ())
        else:
            attrib = dict(attribution=UNATTRIBUTED, participant_id=None,
                          agent_instance_id=None, relation_ids=())
        return self._record(kind, attrib, **payload)
    def _record(self, kind: str, attrib: dict, **payload) -> OperationalEvent:
        enr = self._enrollment
        approval = enr.approval
        ev = OperationalEvent(
            sequence=len(self._events), kind=kind, at=self._clock(),
            payload=dict(payload), execution_id=self._execution_id,
            session_id=self._session_id,
            enrollment_hash=enr.enrollment_hash,
            enrollment_state=enr.state,
            passport_hash=approval.passport_hash if approval else None,
            prev_hash=(self._events[-1].event_hash if self._events
                       else _GENESIS),
            **attrib)
        self._events.append(ev)
        return ev
    def observe_step(self, session, **step) -> OperationalEvent:
        """Record through the existing MonitorSession, unchanged, and emit
        the operational event alongside it."""
        session.record_step(**step)
        kind = EventKind.FAULT if step.get("had_fault") else EventKind.STEP
        return self.record(kind, **step)
    def record_enforcement(self, enforcement_event) -> OperationalEvent:
        """Record a SEALED boundary event as operational evidence.
        The request's attempt belongs to the requesting agent, so the event
        is attributed to it when its identity resolves — but the decision and
        the result belong to the boundary and are carried verbatim. The agent
        cannot reach this path: only a verified boundary event can.
        """
        if not enforcement_event.verify()["valid"]:
            raise OperationalError("the enforcement event was altered")
        req = enforcement_event.request
        if req["execution_id"] != self._execution_id:
            raise OperationalError(
                f"the enforcement event is for execution "
                f"{req['execution_id']}, this recorder is "
                f"{self._execution_id}")
        if enforcement_event.decision["enrollment_hash"] not in (
                "", self._enrollment.enrollment_hash):
            raise OperationalError(
                "the enforcement event was decided under a different "
                "enrollment than the one in force")
        p = self._topology.participant(req["participant_id"])
        if p is not None and p.agent_instance_id == req["agent_instance_id"]:
            attrib = dict(attribution=ATTRIBUTED,
                          participant_id=p.participant_id,
                          agent_instance_id=p.agent_instance_id,
                          relation_ids=())
        else:
            attrib = dict(attribution=UNATTRIBUTED, participant_id=None,
                          agent_instance_id=None, relation_ids=())
        return self._record(EventKind.ENFORCEMENT, attrib,
                            enforcement_event=enforcement_event.to_dict())
    def observe_context(self, assessment) -> OperationalEvent:
        """Record a CONTEXT_CHANGE event from a context assessment: its state, the invalidating differences and the attestation hash."""
        return self.record(EventKind.CONTEXT_CHANGE, state=assessment.state,
                           invalidating=list(assessment.invalidating),
                           attestation_hash=assessment.attestation_hash)
    # ── export ───────────────────────────────────────────────────────
    def log(self) -> OperationalLog:
        """Produce the sealed, hash-chained OperationalLog of everything recorded so far, bound to the topology and execution."""
        return OperationalLog(topology_hash=self._topology.topology_hash,
                              execution_id=self._execution_id,
                              session_id=self._session_id,
                              events=tuple(self._events))
    def lineage(self) -> EvidenceLineage:
        """R3 lineage built from the automatic attributions. It goes through
        R3's own validation, so an automatic attribution that R3 would
        reject cannot be exported."""
        attrs = tuple(
            EvidenceAttribution(
                evidence_ref=e.evidence_ref, participant_id=e.participant_id,
                agent_instance_id=e.agent_instance_id,
                execution_id=e.execution_id, session_id=e.session_id,
                relation_ids=e.relation_ids)
            for e in self._events if e.attribution == ATTRIBUTED)
        return EvidenceLineage(self._topology, attrs)
