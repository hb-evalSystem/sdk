"""
hb_eval_sdk/enforcement.py — R8, SDK half: the enforcement CONTRACT
WHAT THIS IS, AND WHAT IT CANNOT BE
    This module defines the semantics of runtime enforcement:
        EnforcementRequest -> EnforcementDecision -> EnforcementResult
                           -> EnforcementEvent
    It does NOT enforce anything. The SDK runs inside the agent's process,
    so any control point here is cooperative by construction: an agent that
    ignores it is not stopped. §31: the control point must sit OUTSIDE the
    agent's reasoning authority — a gateway, tool proxy, sidecar, credential
    or workload layer. Those are platform components.
    R8 IS NOT CLOSED BY THIS MODULE. It closes when a boundary outside the
    agent process implements this contract and is shown to block an action
    the agent did not cooperate in stopping.
THE MECHANISM IS PART OF THE RECORD
    Every EnforcementResult names the mechanism that produced it, and whether
    that mechanism is independent of the agent. IN_PROCESS_COOPERATIVE is
    always recorded as NOT independent. So a result produced by the SDK can
    never be read as forced enforcement — the evidence itself says so.
A CLOSED WORLD
    An action not explicitly allowed is DENIED. The absence of a permission is
    not permission — the same rule as SLO policy (no default thresholds) and
    enrollment (no default acceptance).
    And nothing is allowed unless the enrollment is ACTIVE and the request is
    bound to the CURRENT ledger. A request prepared under an earlier ledger
    state — before a suspension, say — is denied as stale.
DIVERGENCE IS EVIDENCE, NOT AN ERROR
    A boundary may report an outcome that contradicts the decision: DENY but
    EXECUTED (a breach), or ALLOW but BLOCKED (over-enforcement). These are
    RECORDED with their conformance, never refused — a breach is the most
    important thing an enforcement record can contain.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from typing import Optional
__all__ = [
    "ActionKind", "Decision", "Mechanism", "Outcome", "Conformance",
    "EnforcementPolicy", "EnforcementRequest", "EnforcementDecision",
    "EnforcementResult", "EnforcementEvent", "EnforcementError",
    "decide_enforcement", "record_result", "ENFORCEMENT_VERSION",
    "SDK_PROVIDES_INDEPENDENT_BOUNDARY",
]
ENFORCEMENT_VERSION = "hb-eval-enforcement/v1"
SDK_PROVIDES_INDEPENDENT_BOUNDARY = False
"""Stated as a constant so it can be asserted. The SDK implements no
mechanism independent of the agent. R8 cannot close from the SDK alone."""
class EnforcementError(Exception):
    """Raised when an enforcement artefact is malformed or breaks the enforcement contract."""
    pass
class ActionKind:
    """The kinds of action an enforcement boundary can govern: tool calls, API calls, memory reads and writes, delegation, spawning a sub-agent, and credential use."""
    TOOL_CALL = "TOOL_CALL"
    API_CALL = "API_CALL"
    MEMORY_READ = "MEMORY_READ"
    MEMORY_WRITE = "MEMORY_WRITE"
    DELEGATE = "DELEGATE"
    SPAWN = "SPAWN"
    CREDENTIAL_USE = "CREDENTIAL_USE"
    ALL = (TOOL_CALL, API_CALL, MEMORY_READ, MEMORY_WRITE, DELEGATE, SPAWN,
           CREDENTIAL_USE)
class Decision:
    """What the enforcement policy decided for a request: ALLOW, DENY, or HALT."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    HALT = "HALT"
    ALL = (ALLOW, DENY, HALT)
class Mechanism:
    """The kind of boundary that enforced (or only observed) an action.

    Everything except IN_PROCESS_COOPERATIVE runs outside the agent's own process. A cooperative
    mechanism relies on the agent honouring it, so its blocks are not independent enforcement.
    """
    GATEWAY = "GATEWAY"
    TOOL_PROXY = "TOOL_PROXY"
    SIDECAR = "SIDECAR"
    CREDENTIAL_LAYER = "CREDENTIAL_LAYER"
    WORKLOAD_CONTROLLER = "WORKLOAD_CONTROLLER"
    MCP_BOUNDARY = "MCP_BOUNDARY"
    IN_PROCESS_COOPERATIVE = "IN_PROCESS_COOPERATIVE"
    ALL = (GATEWAY, TOOL_PROXY, SIDECAR, CREDENTIAL_LAYER,
           WORKLOAD_CONTROLLER, MCP_BOUNDARY, IN_PROCESS_COOPERATIVE)
    INDEPENDENT = frozenset(ALL) - {IN_PROCESS_COOPERATIVE}
    """Independence is a property of WHERE the mechanism runs. Declaring an
    external mechanism is a claim the platform must substantiate; this
    contract records it, it cannot prove it."""
class Outcome:
    """What the boundary observed happen to the action: EXECUTED, BLOCKED, HALTED, or ERROR when the boundary itself failed."""
    EXECUTED = "EXECUTED"
    BLOCKED = "BLOCKED"
    HALTED = "HALTED"
    ERROR = "ERROR"
    ALL = (EXECUTED, BLOCKED, HALTED, ERROR)
class Conformance:
    """Whether what happened matched what the policy decided.

    CONFORMANT: it matched. BREACH: denied or halted, yet executed. OVER_ENFORCEMENT: allowed, yet
    blocked or halted. INDETERMINATE: the boundary reported an error, so conformance cannot be judged.
    """
    CONFORMANT = "CONFORMANT"
    BREACH = "BREACH"                  # denied or halted, yet executed
    OVER_ENFORCEMENT = "OVER_ENFORCEMENT"  # allowed, yet blocked or halted
    INDETERMINATE = "INDETERMINATE"    # the boundary reported an error
def _h(obj) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        default=str).encode()).hexdigest()
class _Sealed:
    """Content-addressing shared by every artefact in the contract.

    A mixin: every concrete subclass is a dataclass that defines a `hash` field, which is what the
    two annotations below tell the type checker (they create no runtime attributes)."""
    _prefix = ""
    _id_field = ""
    hash: str
    __dataclass_fields__: "dict[str, object]"
    def _canonical(self) -> dict:
        skip = {self._id_field, "hash"}
        d = {}
        for k in self.__dataclass_fields__:
            if k in skip:
                continue
            v = getattr(self, k)
            d[k] = list(v) if isinstance(v, tuple) else v
        return d
    def _seal(self):
        c = self._canonical()
        if not getattr(self, self._id_field):
            object.__setattr__(self, self._id_field,
                               self._prefix + _h(c)[7:23])
        if not self.hash:
            object.__setattr__(self, "hash", _h(c))
    def verify(self) -> dict:
        c = self._canonical()
        ok = (self.hash == _h(c) and
              getattr(self, self._id_field) == self._prefix + _h(c)[7:23])
        return {"valid": ok,
                "problems": [] if ok else [f"{type(self).__name__} altered"]}
@dataclass(frozen=True)
class EnforcementPolicy(_Sealed):
    """Declared, versioned, content-addressed (the R1 properties)."""
    enforcement_policy_version: str
    allowed_actions: tuple
    denied_targets: tuple = ()
    halt_on: tuple = ()
    enforcement_policy_id: str = ""
    hash: str = ""
    _prefix = "EFP-"
    _id_field = "enforcement_policy_id"
    def __post_init__(self):
        if not self.enforcement_policy_version:
            raise EnforcementError("an enforcement policy must be versioned")
        for a in self.allowed_actions + self.halt_on:
            if a not in ActionKind.ALL:
                raise EnforcementError(f"unknown action kind {a!r}")
        object.__setattr__(self, "allowed_actions",
                           tuple(sorted(self.allowed_actions)))
        object.__setattr__(self, "denied_targets",
                           tuple(sorted(self.denied_targets)))
        object.__setattr__(self, "halt_on", tuple(sorted(self.halt_on)))
        self._seal()
@dataclass(frozen=True)
class EnforcementRequest(_Sealed):
    """What the agent asked to do, as seen by the boundary.
    Arguments are carried as a HASH, never raw: the record must identify the
    action without becoming a copy of whatever data it touched.
    """
    correlation_id: str
    action: str
    target: str
    arguments_hash: str
    participant_id: str
    agent_instance_id: str
    execution_id: str
    session_id: Optional[str]
    enrollment_hash: str
    requested_at: float
    request_id: str = ""
    hash: str = ""
    _prefix = "ERQ-"
    _id_field = "request_id"
    def __post_init__(self):
        if self.action not in ActionKind.ALL:
            raise EnforcementError(f"unknown action kind {self.action!r}")
        for f in ("correlation_id", "target", "participant_id",
                  "agent_instance_id", "execution_id", "enrollment_hash"):
            if not getattr(self, f):
                raise EnforcementError(f"a request requires {f}")
        self._seal()
    @classmethod
    def create(cls, *, arguments=None, **fields) -> "EnforcementRequest":
        """Build a request from keyword fields; `arguments` are hashed into `arguments_hash` so the request is content-addressed without carrying the raw arguments."""
        return cls(arguments_hash=_h(arguments if arguments is not None
                                     else {}), **fields)
@dataclass(frozen=True)
class EnforcementDecision(_Sealed):
    """A sealed decision: which request (by id and hash) it answers, what was decided, which rule decided it in the fixed evaluation order, why, and under which enforcement policy."""
    request_id: str
    request_hash: str
    decision: str
    rule: str
    """Which rule decided, in the fixed evaluation order."""
    reason: str
    enforcement_policy_id: str
    enforcement_policy_hash: str
    enforcement_policy_version: str
    enrollment_hash: str
    enrollment_state: str
    passport_hash: Optional[str]
    decision_id: str = ""
    hash: str = ""
    _prefix = "EDC-"
    _id_field = "decision_id"
    def __post_init__(self):
        self._seal()
@dataclass(frozen=True)
class EnforcementResult(_Sealed):
    """What the BOUNDARY reports actually happened."""
    decision_id: str
    decision_hash: str
    mechanism: str
    outcome: str
    observed_at: float
    detail: str = ""
    independent_of_agent: bool = False
    result_id: str = ""
    hash: str = ""
    _prefix = "ERS-"
    _id_field = "result_id"
    def __post_init__(self):
        if self.mechanism not in Mechanism.ALL:
            raise EnforcementError(f"unknown mechanism {self.mechanism!r}")
        if self.outcome not in Outcome.ALL:
            raise EnforcementError(f"unknown outcome {self.outcome!r}")
        # Independence follows from the mechanism, never from a caller's say.
        object.__setattr__(self, "independent_of_agent",
                           self.mechanism in Mechanism.INDEPENDENT)
        self._seal()
@dataclass(frozen=True)
class EnforcementEvent(_Sealed):
    """The auditable record: who, what, when, why, under which policy and
    context, which action, which mechanism, what resulted."""
    event_type: str
    conformance: str
    request: dict
    decision: dict
    result: dict
    event_id: str = ""
    hash: str = ""
    _prefix = "EEV-"
    _id_field = "event_id"
    def __post_init__(self):
        self._seal()
    def to_dict(self) -> dict:
        """The JSON-serialisable form, including `event_id` and `hash`."""
        return {**self._canonical(), "event_id": self.event_id,
                "hash": self.hash}
    @classmethod
    def from_dict(cls, d: dict) -> "EnforcementEvent":
        """Rebuild and VERIFY. A record is never taken from the payload's
        word: if the content does not reproduce the sealed hash, it is
        refused."""
        ev = cls(event_type=d["event_type"], conformance=d["conformance"],
                 request=d["request"], decision=d["decision"],
                 result=d["result"])
        if ev.hash != d.get("hash") or ev.event_id != d.get("event_id"):
            raise EnforcementError("the enforcement event does not reproduce "
                                   "its sealed identity")
        return ev
    @property
    def forced(self) -> bool:
        """True only when the action was stopped by an independent
        mechanism. Never true for anything the SDK produces on its own."""
        return (self.result["independent_of_agent"]
                and self.result["outcome"] in (Outcome.BLOCKED,
                                               Outcome.HALTED))
def decide_enforcement(request: EnforcementRequest, *, policy:
                       EnforcementPolicy, enrollment, topology
                       ) -> EnforcementDecision:
    """Pure and deterministic. Rules evaluated in a fixed order; the first
    that applies decides, and its name is recorded."""
    if not request.verify()["valid"]:
        raise EnforcementError("the request was altered")
    if not policy.verify()["valid"]:
        raise EnforcementError("the enforcement policy was altered")
    enr_ok = enrollment.verify()["valid"]
    state = enrollment.state if enr_ok else "UNVERIFIABLE"
    approval = enrollment.approval if enr_ok else None
    p = topology.participant(request.participant_id)
    if not enr_ok:
        d, rule, why = Decision.DENY, "R1_ledger", \
            "the enrollment ledger does not verify"
    elif request.enrollment_hash != enrollment.enrollment_hash:
        d, rule, why = Decision.DENY, "R2_stale", \
            "the request is bound to an earlier state of the ledger"
    elif state != "ACTIVE":
        d, rule, why = Decision.DENY, "R3_not_active", \
            f"enrollment is {state}"
    elif enrollment.system_id != topology.system_id or p is None or \
            p.kind not in ("AGENT", "SUB_AGENT") or \
            p.agent_instance_id != request.agent_instance_id:
        d, rule, why = Decision.DENY, "R4_identity", \
            "the requesting instance is not an agent of this system"
    elif request.action in policy.halt_on:
        d, rule, why = Decision.HALT, "R5_halt_on", \
            f"{request.action} is a halt condition"
    elif request.target in policy.denied_targets:
        d, rule, why = Decision.DENY, "R6_denied_target", \
            f"{request.target} is denied"
    elif request.action in policy.allowed_actions:
        d, rule, why = Decision.ALLOW, "R7_allowed", \
            f"{request.action} is allowed"
    else:
        d, rule, why = Decision.DENY, "R8_closed_world", \
            f"{request.action} is not permitted; the absence of a " \
            f"permission is not permission"
    return EnforcementDecision(
        request_id=request.request_id, request_hash=request.hash,
        decision=d, rule=rule, reason=why,
        enforcement_policy_id=policy.enforcement_policy_id,
        enforcement_policy_hash=policy.hash,
        enforcement_policy_version=policy.enforcement_policy_version,
        enrollment_hash=enrollment.enrollment_hash if enr_ok else "",
        enrollment_state=state,
        passport_hash=approval.passport_hash if approval else None)
def _conformance(decision: str, outcome: str) -> str:
    if outcome == Outcome.ERROR:
        return Conformance.INDETERMINATE
    if decision == Decision.ALLOW:
        return (Conformance.CONFORMANT if outcome == Outcome.EXECUTED
                else Conformance.OVER_ENFORCEMENT)
    if outcome == Outcome.EXECUTED:
        return Conformance.BREACH
    return Conformance.CONFORMANT
def _event_type(req, dec, res, conf) -> str:
    if conf == Conformance.BREACH:
        return "ENFORCEMENT_BREACH"
    if res.outcome == Outcome.HALTED:
        return "SESSION_HALTED"
    if res.outcome == Outcome.BLOCKED:
        return ("TOOL_BLOCKED" if req.action == ActionKind.TOOL_CALL
                else "ACTION_DENIED")
    if res.outcome == Outcome.ERROR:
        return "ENFORCEMENT_ERROR"
    return "ACTION_ALLOWED"
def record_result(request: EnforcementRequest, decision: EnforcementDecision,
                  result: EnforcementResult) -> EnforcementEvent:
    """Seal request, decision and result into one event. Divergence is
    recorded with its conformance, not refused."""
    for a in (request, decision, result):
        if not a.verify()["valid"]:
            raise EnforcementError(f"{type(a).__name__} was altered")
    if decision.request_hash != request.hash:
        raise EnforcementError("the decision is for another request")
    if result.decision_hash != decision.hash:
        raise EnforcementError("the result is for another decision")
    if result.observed_at < request.requested_at:
        raise EnforcementError("the result predates the request")
    conf = _conformance(decision.decision, result.outcome)
    return EnforcementEvent(
        event_type=_event_type(request, decision, result, conf),
        conformance=conf,
        request={**request._canonical(), "request_id": request.request_id,
                 "hash": request.hash},
        decision={**decision._canonical(),
                  "decision_id": decision.decision_id, "hash": decision.hash},
        result={**result._canonical(), "result_id": result.result_id,
                "hash": result.hash})
