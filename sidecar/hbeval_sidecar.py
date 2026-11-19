"""
sidecar/hbeval_sidecar.py — the R8 enforcement boundary
A SEPARATE DEPLOYABLE, outside the hb_eval_sdk package.
It is independent of the agent ONLY when deployed per R8_DESIGN.md:
    I-1  the tool credential exists only in this process's environment
    I-2  the agent runs as a different OS identity
    I-3  this process forwards only to its fixed registry of upstreams
Standard library only (http.server, urllib): a boundary should carry as few
dependencies as possible, because each one is attack surface.
"""
from __future__ import annotations
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from hb_eval_sdk.enforcement import ActionKind, Decision, Mechanism, Outcome
MAX_RESPONSE_BYTES = 64 * 1024
UPSTREAM_TIMEOUT_S = 10
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would let an upstream bounce the credential elsewhere."""
    def redirect_request(self, *a, **kw):
        return None
_OPENER = urllib.request.build_opener(_NoRedirect)
class SidecarRuntime:
    """R11-C.6: the Sidecar no longer decides.
    It asks the Gateway, which asks the SDK. A second copy of
    decide_enforcement living here would be a second reliability model in the
    place hardest to audit — inside the customer's own deployment.
        Agent -> Sidecar -> Gateway /api/v1/enforce/decide -> SDK
                         -> ALLOW: forward to the tool with the credential
                         -> DENY : the tool is never called
                         -> Gateway /api/v1/enforce/result -> sealed event
    """
    def __init__(self, *, gateway_url: str, agent_id: str, registry: dict,
                 tool_credential: str, clock=time.time):
        if not tool_credential:
            raise ValueError("the Sidecar must hold the tool credential (I-1)")
        if not gateway_url:
            raise ValueError("the Sidecar must be told where to ask; it does "
                             "not decide on its own")
        self.gateway_url = gateway_url.rstrip("/")
        self.agent_id = agent_id
        self.registry = dict(registry)            # tool name -> fixed URL (I-3)
        self._credential = tool_credential
        self.clock = clock
        self.events = []
        self.lock = threading.Lock()
    def _ask_gateway(self, path: str, body: dict):
        req = urllib.request.Request(
            f"{self.gateway_url}{path}", data=json.dumps(body).encode(),
            method="POST", headers={"Content-Type": "application/json"})
        with _OPENER.open(req, timeout=UPSTREAM_TIMEOUT_S) as r:
            return json.loads(r.read(MAX_RESPONSE_BYTES))
    def _forward(self, tool: str, arguments: dict, request_id: str):
        url = self.registry[tool]
        req = urllib.request.Request(
            url, data=json.dumps(arguments).encode(), method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self._credential}",
                     "X-HBEval-Request-Id": request_id})
        with _OPENER.open(req, timeout=UPSTREAM_TIMEOUT_S) as r:
            return r.status, r.read(MAX_RESPONSE_BYTES).decode(errors="replace")
    def act(self, body: dict):
        with self.lock:
            ask = {"agent_id": self.agent_id,
                   "correlation_id": body.get("correlation_id") or "none",
                   "action": body.get("action", ActionKind.TOOL_CALL),
                   "target": body.get("tool", ""),
                   "arguments": body.get("arguments", {}),
                   "participant_id": body.get("participant_id", ""),
                   "agent_instance_id": body.get("agent_instance_id", ""),
                   "execution_id": body.get("execution_id", ""),
                   "session_id": body.get("session_id"),
                   "requested_at": self.clock()}
            try:
                dec = self._ask_gateway("/api/v1/enforce/decide", ask)
            except (urllib.error.URLError, OSError) as exc:
                # The Sidecar cannot decide for itself, so an unreachable
                # Gateway means the action is refused. Failing open here
                # would make the boundary disappear exactly when it is most
                # needed.
                # NOT a DENY. A denial is a decision the SDK made; this is
                # the ABSENCE of a decision. Conflating them would let an
                # outage be recorded as a policy verdict, and the whole
                # architecture rests on not doing that.
                #
                # No EnforcementEvent exists for this: there is no decision
                # to seal. What is recorded is that the action was refused
                # because no decision could be obtained.
                return 503, {"decision": "NOT_OBTAINED",
                             "reason": "gateway_unavailable",
                             "outcome": "NOT_EXECUTED",
                             "fail_closed": True,
                             "enforcement_event": None,
                             "detail": f"no decision could be obtained "
                                       f"({type(exc).__name__}); the Sidecar "
                                       f"does not decide on its own, and "
                                       f"refuses rather than proceed"}
            status, payload, detail = 403, None, dec.get("reason", "")
            if dec["decision"] == Decision.HALT:
                outcome, status = Outcome.HALTED, 409
            elif dec["decision"] == Decision.DENY:
                outcome = Outcome.BLOCKED
            elif ask["target"] not in self.registry:
                outcome = Outcome.BLOCKED
                detail = "not a registered tool: the Sidecar forwards only " \
                         "to fixed upstreams (I-3)"
            else:
                try:
                    status, payload = self._forward(
                        ask["target"], ask["arguments"], dec["decision_id"])
                    outcome = Outcome.EXECUTED if status < 400 else \
                        Outcome.ERROR
                    detail = f"upstream {status}"
                except (urllib.error.URLError, OSError) as exc:
                    outcome, status = Outcome.ERROR, 502
                    detail = f"upstream unreachable: {type(exc).__name__}"
            ev = self._ask_gateway("/api/v1/enforce/result", {
                "agent_id": self.agent_id, "decision_id": dec["decision_id"],
                "mechanism": Mechanism.SIDECAR, "outcome": outcome,
                "observed_at": max(self.clock(), ask["requested_at"]),
                "detail": detail})
            self.events.append(ev)
            return status, {"decision": dec["decision"], "rule": dec["rule"],
                            "outcome": outcome,
                            "event_type": ev["event_type"],
                            "enforcement_event": ev["event_id"],
                            "forced": ev["forced"], "response": payload}
    def evidence(self):
        """The Sidecar holds no evidence of its own: the sealed events and
        the operational log live where the SDK is, behind the Gateway. It
        returns only what it was told, so a customer-side component can never
        become an alternative source of truth."""
        with self.lock:
            return {"gateway": self.gateway_url,
                    "events_reported_by_gateway": list(self.events)}
def make_handler(rt: SidecarRuntime):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass
        def _send(self, code, obj):
            b = json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        def do_POST(self):
            if self.path not in ("/v1/act", "/v1/evidence"):
                return self._send(404, {"error": "not found"})
            n = min(int(self.headers.get("Content-Length", 0)), 512 * 1024)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
                code, out = ((200, rt.evidence())
                             if self.path == "/v1/evidence"
                             else rt.act(body))
            except Exception as exc:                       # noqa: BLE001
                code, out = 400, {"error": type(exc).__name__,
                                  "detail": str(exc)[:200]}
            self._send(code, out)
        def do_GET(self):
            if self.path != "/v1/evidence":
                return self._send(404, {"error": "not found"})
            self._send(200, rt.evidence())
    return H
def serve(rt: SidecarRuntime, host="127.0.0.1", port=18802):
    srv = ThreadingHTTPServer((host, port), make_handler(rt))
    srv.serve_forever()
# R8_DESIGN.md — Sidecar enforcement boundary
