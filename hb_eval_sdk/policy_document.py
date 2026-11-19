"""
hb_eval_sdk/policy_document.py — R1: unified policy identity
WHAT THIS UNIFIES, AND WHAT IT DELIBERATELY DOES NOT
    HB-Eval has two policy concepts, and they answer different questions:
        PolicyEngine   what should the agent do NEXT, during a run?
                       retry · escalate · halt
                       per-step, stateful, acts inside the loop
        SLOPolicy      does the evidence support a verdict AFTER a run?
                       PASS · FAIL · INCONCLUSIVE
                       per-decision, stateless, acts on baselines
    Collapsing those two evaluation semantics into one engine would destroy
    both. A runtime directive is not a verdict, and a verdict is not an
    instruction.
    So R1 unifies IDENTITY AND PROVENANCE, not evaluation. Both concepts get
    the same four properties the architecture requires of any policy
    (instruction section 12):
        versioned · identifiable · hashable · attachable to evidence
    Measured before building: PolicyEngine had none of the four; SLOPolicy
    had all four. This module gives the missing three to the runtime engine
    without changing a line of how it decides anything.
WHY A NEW ARTEFACT RATHER THAN A FIELD ON THE EXISTING ONES
    `hb-eval-evidence/v1` is FROZEN (Phase 9A). Adding a policy field to
    ConfigurationFingerprint or EvaluationIdentity would change a canonical
    form, move every existing fingerprint, and reopen DW-008 the moment it
    closed.
    A PolicyDocument is therefore a SEPARATE artefact that REFERENCES frozen
    artefacts by hash. The freeze never moves; the reference is one-way.
    This is the same shape the architecture prescribes for the relationship
    plane in R2, and choosing it here keeps both extensions consistent.
WHAT A POLICY DOCUMENT IS NOT
    Not an enforcement mechanism. It records WHICH policy governed a
    decision, so an evidence chain can name it. Enforcement is R8.
    Not a merge of the two engines. Each keeps its own evaluation code,
    untouched.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional
__all__ = [
    "PolicyDocument",
    "PolicyKind",
    "POLICY_DOCUMENT_VERSION",
    "policy_document_from_engine",
    "policy_document_from_slo",
]
POLICY_DOCUMENT_VERSION = "hb-eval-policy/v1"
"""The policy document's own format version.
Versioned SEPARATELY from hb-eval-evidence/v1, exactly as the storage
container is. A change to how policy is represented must never be able to
move an evidence artefact's identity.
"""
class PolicyKind:
    """Which kind of policy a document holds. RUNTIME acts during a run (retry, escalate, halt; PolicyEngine). SLO acts on evidence after a run (PASS, FAIL, INCONCLUSIVE; SLOPolicy)."""
    RUNTIME = "RUNTIME"
    """Acts during a run: retry, escalate, halt. PolicyEngine."""
    SLO = "SLO"
    """Acts on evidence after a run: PASS, FAIL, INCONCLUSIVE. SLOPolicy."""
    ALL = (RUNTIME, SLO)
@dataclass(frozen=True)
class PolicyDocument:
    """A versioned, content-addressed record of which policy governed
    something.
    Frozen and content-addressed for the same reason ReliabilityBaseline is:
    two documents describing the same policy ARE the same policy, and an
    assigned id would let one policy be referenced under two names.
    """
    kind: str
    policy_version: str
    content: dict
    """The policy's own parameters, as declared. Never interpreted here."""
    policy_id: str = ""
    policy_hash: str = ""
    document_version: str = POLICY_DOCUMENT_VERSION
    # References to frozen artefacts. One-way: this document points at them,
    # they never point back, so the freeze is untouched.
    references: dict = field(default_factory=dict)
    def __post_init__(self):
        if self.kind not in PolicyKind.ALL:
            raise ValueError(
                f"unknown policy kind {self.kind!r}; expected one of "
                f"{PolicyKind.ALL}")
        if not self.policy_version:
            raise ValueError(
                "a policy document must carry a version: a decision made "
                "under an unversioned policy cannot be compared with one "
                "made under any other")
        if not self.policy_id:
            object.__setattr__(self, "policy_id", self._derive_id())
        if not self.policy_hash:
            object.__setattr__(self, "policy_hash", self._compute_hash())
    # ── identity and integrity ──────────────────────────────────────
    def _identity_content(self) -> dict:
        """What this is a policy OF. References are excluded deliberately:
        the same policy applied to two different evaluations is the same
        policy."""
        return {
            "kind": self.kind,
            "policy_version": self.policy_version,
            "content": self.content,
        }
    def _derive_id(self) -> str:
        blob = json.dumps(self._identity_content(), sort_keys=True,
                          separators=(",", ":"), default=str)
        return "POL-" + hashlib.sha256(blob.encode()).hexdigest()[:16]
    def _canonical(self) -> dict:
        return {
            **self._identity_content(),
            "document_version": self.document_version,
            "references": self.references,
        }
    def _compute_hash(self) -> str:
        blob = json.dumps(self._canonical(), sort_keys=True,
                          separators=(",", ":"), default=str)
        return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()
    def verify(self) -> dict:
        """Check that `policy_id` and `policy_hash` match the content. A policy whose id was assigned rather than derived, or whose content changed, is reported. Returns `{"valid": bool, "problems": [...]}`."""
        problems = []
        if self.policy_id != self._derive_id():
            problems.append(
                "policy_id does not match its content: it was assigned or "
                "altered rather than derived")
        if self.policy_hash != self._compute_hash():
            problems.append("policy document content was altered")
        return {"valid": not problems, "problems": problems}
    # ── attaching to evidence, without touching the freeze ──────────
    def referencing(self, **artefact_hashes) -> "PolicyDocument":
        """Return a copy that points at frozen artefacts by hash.
        The reference is ONE-WAY. Nothing is written into the evidence
        artefact, so `hb-eval-evidence/v1` and every existing fingerprint are
        untouched — which is what lets a policy be attached to evidence at
        all without a new freeze cycle.
        """
        return PolicyDocument(
            kind=self.kind, policy_version=self.policy_version,
            content=self.content, references=dict(artefact_hashes),
            document_version=self.document_version)
    def to_dict(self) -> dict:
        """The JSON-serialisable form, including `policy_id` and `policy_hash`."""
        d = self._canonical()
        d["policy_id"] = self.policy_id
        d["policy_hash"] = self.policy_hash
        return d
    @classmethod
    def from_dict(cls, data: dict) -> "PolicyDocument":
        """Reconstruct a document from `to_dict()` output. Raises ValueError naming any missing field. The result should be passed to `verify()`: reconstruction does not by itself prove the content is unaltered."""
        required = ("kind", "policy_version", "content", "policy_id",
                    "policy_hash")
        missing = [k for k in required if k not in data]
        if missing:
            raise ValueError(f"cannot reconstruct a policy document: "
                             f"{missing} absent")
        doc = cls(kind=data["kind"], policy_version=data["policy_version"],
                  content=data["content"],
                  references=data.get("references", {}),
                  document_version=data.get("document_version",
                                            POLICY_DOCUMENT_VERSION))
        if doc.policy_id != data["policy_id"]:
            raise ValueError(
                f"policy_id mismatch: stored {data['policy_id']}, derived "
                f"{doc.policy_id}")
        if doc.policy_hash != data["policy_hash"]:
            raise ValueError("the policy document does not round-trip")
        return doc
    def __repr__(self) -> str:
        return (f"<PolicyDocument {self.policy_id} {self.kind} "
                f"v={self.policy_version}>")
# ── adapters: identity for the two existing concepts ────────────────
def policy_document_from_engine(engine, policy_version: str
                                ) -> PolicyDocument:
    """Give a PolicyEngine the identity it does not carry.
    Reads the engine's DECLARED configuration — its normalised policies and
    its tool policy — and nothing about its running state. Two engines
    configured identically produce the same policy_id even mid-run, because
    identity is about the policy, not about how far a session has got.
    `policy_version` is supplied by the caller. It is deliberately not
    invented here: a version the SDK made up would be unversioned in
    practice.
    """
    content = {
        "policies": getattr(engine, "policies", None),
        "tool_policy": getattr(engine, "tool_policy", None),
    }
    return PolicyDocument(kind=PolicyKind.RUNTIME,
                          policy_version=policy_version, content=content)
def policy_document_from_slo(slo_policy) -> PolicyDocument:
    """Give an SLOPolicy the same document shape.
    SLOPolicy already carries a version and an optional id, so nothing is
    added — this only expresses it in the shared form so both kinds can be
    attached to evidence the same way.
    """
    content = {
        "policy_id_declared": getattr(slo_policy, "policy_id", None),
        "conditions": [
            {"metric_name": c.metric_name, "comparator": c.comparator,
             "threshold": c.threshold, "applies_to": c.applies_to,
             "decision_eligible": c.decision_eligible}
            for c in getattr(slo_policy, "conditions", ())
        ],
    }
    return PolicyDocument(kind=PolicyKind.SLO,
                          policy_version=slo_policy.policy_version,
                          content=content)
