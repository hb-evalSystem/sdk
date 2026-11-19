"""
hb_eval_sdk/enforcement_evidence.py — R9: enforcement as operational evidence
THE QUESTION R9 MUST ANSWER FOR EVERY ENFORCEMENT
    what did the agent request · under which policy · which agent/instance ·
    which execution/session · what enrollment state · who decided · which
    mechanism acted · DID THE TOOL ACTUALLY EXECUTE · where is the evidence
TWO SOURCES, KEPT DISTINCT
    The boundary REPORTS an outcome. That is one source, and in R8's proof it
    was not the one trusted: the verdict came from the TOOL's own execution
    log. R9 keeps both and compares them:
        CORROBORATED    the tool's log agrees with the boundary
        CONTRADICTED    the tool's log disagrees — e.g. the boundary says
                        BLOCKED and the tool executed. The strongest breach
                        evidence there is, because it does not depend on the
                        boundary telling the truth.
        UNCORROBORATED  no tool-side log covers it; the outcome rests on the
                        boundary's report alone, and the passport says so
    A missing entry corroborates non-execution only in a log the tool
    operator declares COMPLETE for the window. An incomplete log's silence
    proves nothing.
WHAT THIS DOES NOT ESTABLISH
    Tool logs are the tool operator's records, independent of the agent and
    the Sidecar but unsigned (DW-009). Corroboration means two independent
    records agree, not that either is externally attested.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from typing import Optional
from .enforcement import EnforcementEvent, Outcome, Conformance
__all__ = ["Corroboration", "ToolExecutionLog", "EnforcementEvidenceError",
           "summarise_enforcement", "TOOL_LOG_VERSION"]
TOOL_LOG_VERSION = "hb-eval-tool-log/v1"
class EnforcementEvidenceError(Exception):
    """Raised when enforcement evidence is malformed or cannot be combined honestly."""
    pass
class Corroboration:
    """Whether an enforcement claim was backed by an independent record.

    CORROBORATED: an independent tool log agrees. CONTRADICTED: it disagrees. UNCORROBORATED: only
    the enforcing boundary reported it.
    """
    CORROBORATED = "CORROBORATED"
    CONTRADICTED = "CONTRADICTED"
    UNCORROBORATED = "UNCORROBORATED"
def _h(obj) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        default=str).encode()).hexdigest()
@dataclass(frozen=True)
class ToolExecutionLog:
    """The tool operator's own record of what reached the tool."""
    tool: str
    window_start: float
    window_end: float
    observations: tuple
    """({request_id|None, authorized, executed, at}, ...)"""
    complete: bool
    """Declared by the tool operator: every request in the window is here."""
    tool_log_version: str = TOOL_LOG_VERSION
    log_id: str = ""
    hash: str = ""
    def __post_init__(self):
        if self.window_end < self.window_start:
            raise EnforcementEvidenceError("window ends before it starts")
        for o in self.observations:
            if not self.window_start <= o["at"] <= self.window_end:
                raise EnforcementEvidenceError("observation outside window")
        c = self._canonical()
        if not self.log_id:
            object.__setattr__(self, "log_id", "TLG-" + _h(c)[7:23])
        if not self.hash:
            object.__setattr__(self, "hash", _h(c))
    def _canonical(self) -> dict:
        return {"tool": self.tool, "window_start": self.window_start,
                "window_end": self.window_end,
                "observations": [dict(o) for o in self.observations],
                "complete": self.complete,
                "tool_log_version": self.tool_log_version}
    def verify(self) -> dict:
        """Recompute the log's hash and id. Returns `{"valid": bool, "problems": [...]}`; `valid` is False if the log was altered."""
        c = self._canonical()
        ok = self.hash == _h(c) and self.log_id == "TLG-" + _h(c)[7:23]
        return {"valid": ok, "problems": [] if ok else ["tool log altered"]}
    def covers(self, t: float) -> bool:
        """True if time `t` falls inside this log's coverage window, inclusive. Outside the window the log cannot say whether anything happened."""
        return self.window_start <= t <= self.window_end
def summarise_enforcement(ops_events, *, tool_logs=(), prefix_hashes,
                          readiness_passport_hash):
    """Turn ENFORCEMENT operational events into answerable records.
    Returns (records, claims, not_observed). Every record is rebuilt from the
    sealed enforcement event carried in the operational log and verified —
    a record is never taken from the payload's word.
    """
    for log in tool_logs:
        if not log.verify()["valid"]:
            raise EnforcementEvidenceError(f"tool log {log.log_id} altered")
    records, claims, not_obs = [], [], []
    uncorroborated = 0
    for op in ops_events:
        if op.kind != "ENFORCEMENT":
            continue
        ev = EnforcementEvent.from_dict(op.payload["enforcement_event"])
        req, dec, res = ev.request, ev.decision, ev.result
        if dec["enrollment_hash"] not in prefix_hashes:
            raise EnforcementEvidenceError(
                f"{op.evidence_ref}: decided under an enrollment that is not "
                f"a prefix of this ledger")
        if dec["passport_hash"] not in (None, readiness_passport_hash):
            raise EnforcementEvidenceError(
                f"{op.evidence_ref}: belongs to another readiness passport")
        boundary_executed = res["outcome"] == Outcome.EXECUTED
        tool_refs, corroboration = (), Corroboration.UNCORROBORATED
        for log in tool_logs:
            if log.tool != req["target"] or not log.covers(req["requested_at"]):
                continue
            mine = [o for o in log.observations
                    if o.get("request_id") == req["request_id"]]
            if not mine and not log.complete:
                continue
            tool_executed = any(o["executed"] for o in mine)
            corroboration = (Corroboration.CORROBORATED
                             if tool_executed == boundary_executed
                             else Corroboration.CONTRADICTED)
            tool_refs = (f"TOOL:{log.log_id}",)
            break
        if corroboration == Corroboration.UNCORROBORATED:
            uncorroborated += 1
        refs = (op.evidence_ref, f"ENF:{ev.event_id}") + tool_refs
        record = {
            "evidence_refs": refs,
            "requested": {"action": req["action"], "target": req["target"],
                          "arguments_hash": req["arguments_hash"]},
            "policy": {"id": dec["enforcement_policy_id"],
                       "hash": dec["enforcement_policy_hash"],
                       "version": dec["enforcement_policy_version"]},
            "agent": {"participant_id": req["participant_id"],
                      "agent_instance_id": req["agent_instance_id"],
                      "attributed": op.attribution == "ATTRIBUTED"},
            "execution": {"execution_id": req["execution_id"],
                          "session_id": req["session_id"]},
            "enrollment_state": dec["enrollment_state"],
            "decided": {"decision": dec["decision"], "rule": dec["rule"],
                        "reason": dec["reason"]},
            "mechanism": {"name": res["mechanism"],
                          "independent_of_agent": res["independent_of_agent"]},
            "boundary_outcome": res["outcome"],
            "conformance": ev.conformance,
            "forced": ev.forced,
            "tool_executed": ("NOT_EXECUTED" if corroboration ==
                              Corroboration.CORROBORATED and not
                              boundary_executed else
                              "EXECUTED" if corroboration ==
                              Corroboration.CORROBORATED else
                              "EXECUTED_CONTRARY_TO_BOUNDARY" if
                              corroboration == Corroboration.CONTRADICTED
                              and not boundary_executed else
                              "NOT_EXECUTED_CONTRARY_TO_BOUNDARY" if
                              corroboration == Corroboration.CONTRADICTED
                              else "UNKNOWN_BOUNDARY_REPORT_ONLY"),
            "corroboration": corroboration,
        }
        records.append(record)
        if ev.forced and corroboration == Corroboration.CORROBORATED:
            claims.append((f"{req['action']} {req['target']} blocked by an "
                           f"independent boundary; the tool's own log "
                           f"confirms it did not execute", refs))
        elif ev.forced:
            claims.append((f"{req['action']} {req['target']} blocked by an "
                           f"independent boundary (boundary report)", refs))
        elif res["outcome"] in (Outcome.BLOCKED, Outcome.HALTED):
            claims.append((f"{req['action']} {req['target']} blocked "
                           f"cooperatively only — NOT forced", refs))
        if corroboration == Corroboration.CONTRADICTED:
            claims.append(("the boundary's report is contradicted by the "
                           "tool's own log", refs))
        if ev.conformance == Conformance.BREACH:
            claims.append(("a denied action was executed", refs))
        if ev.conformance == Conformance.OVER_ENFORCEMENT:
            claims.append(("an allowed action was blocked", refs))
    for log in tool_logs:
        refused = [o for o in log.observations if not o["authorized"]]
        if refused:
            claims.append((f"{len(refused)} unauthorised direct attempt(s) "
                           f"reached {log.tool} and were refused by the tool",
                           (f"TOOL:{log.log_id}",)))
    if uncorroborated:
        not_obs.append(f"{uncorroborated} enforcement outcome(s) rest on the "
                       f"boundary's report alone; no tool-side log "
                       f"corroborates them")
    return tuple(records), tuple(claims), tuple(not_obs)
