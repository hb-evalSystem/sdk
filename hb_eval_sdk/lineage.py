"""
hb_eval_sdk/lineage.py — R3: relationship <-> evidence binding
WHAT R3 ADDS
    R2 said: here is the structure and the relationships.
    R3 makes that structure PROVABLE inside evidence lineage.
    A reviewer must be able to walk, for any piece of evidence:
        Evidence
           -> Agent Instance
           -> Execution / Session
           -> Relationship
           -> Topology
           -> System
    That walk is `EvidenceLineage.trace(evidence_ref)`.
WHY A THIRD ARTEFACT, AND WHY NOT A FIELD
    `hb-eval-evidence/v1` is FROZEN. Writing `produced_by` into an envelope
    or a step would change a canonical form and move every fingerprint.
    So attribution lives in a SEPARATE artefact that points at evidence by
    reference and at a topology by hash. Nothing is written into evidence.
    This is the third use of the same one-way shape, after PolicyDocument
    (R1) and SystemTopology (R2).
ON parent_agent_id — decided, not overlooked
    It is not a field on Participant. Parentage is ONE `PARENT_OF` relation,
    resolved by `SystemTopology.parent_of()`. A field AND a relation could
    disagree; one relation cannot. The parent is therefore authoritative from
    the topology alone, with no external inference and no metadata.
RELATIONSHIP IS NOT CAUSALITY
    An attribution records that evidence was produced BY agent B, WHILE
    acting under a DELEGATED_TO relation from A. It does not record, and must
    not be read as recording, that A caused B's outcome.
        A DELEGATED_TO B        is declared structure
        A caused B's failure    is causal attribution
    The second is outside R2/R3 and falls under DW-015. No field here
    expresses it, and the traversal returns the context, never a cause.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:                      # annotation only: no import cycle at runtime
    from .topology import SystemTopology
__all__ = [
    "EvidenceAttribution",
    "EvidenceLineage",
    "LineageTrace",
    "LineageError",
    "LINEAGE_VERSION",
]
LINEAGE_VERSION = "hb-eval-lineage/v1"
"""The fifth independent format version, separate from evidence/v1,
container/v2, policy/v1 and topology/v1."""
class LineageError(Exception):
    """An attribution does not resolve against its topology."""
@dataclass(frozen=True)
class EvidenceAttribution:
    """One piece of evidence, bound to who produced it and under what.
    `evidence_ref` points INTO the frozen core — a typed provenance ref
    (`STEP:3`, `FAULT_EVENT:fe-1`) or an artefact hash. It is never copied
    in; the evidence stays where it is.
    """
    evidence_ref: str
    participant_id: str
    """The authoritative producer. Must resolve in the topology."""
    agent_instance_id: str
    """Required, not optional. agent_id alone cannot distinguish two
    concurrent instances of the same agent, and the directive requires the
    instance."""
    execution_id: str
    session_id: Optional[str] = None
    relation_ids: tuple = ()
    """The relationships the producer was acting UNDER. Context, not cause."""
    attribution_id: str = ""
    def __post_init__(self):
        for name in ("evidence_ref", "participant_id", "agent_instance_id",
                     "execution_id"):
            if not getattr(self, name):
                raise LineageError(
                    f"an attribution requires {name}: evidence without it "
                    f"cannot be traced to a specific producer")
        if not self.attribution_id:
            object.__setattr__(self, "attribution_id", self._derive_id())
    def _identity(self) -> dict:
        return {"evidence_ref": self.evidence_ref,
                "participant_id": self.participant_id,
                "agent_instance_id": self.agent_instance_id,
                "execution_id": self.execution_id,
                "session_id": self.session_id,
                "relation_ids": sorted(self.relation_ids)}
    def _derive_id(self) -> str:
        blob = json.dumps(self._identity(), sort_keys=True,
                          separators=(",", ":"), default=str)
        return "ATR-" + hashlib.sha256(blob.encode()).hexdigest()[:16]
    def to_dict(self) -> dict:
        """The JSON-serialisable form, including the derived `attribution_id`."""
        return {**self._identity(), "attribution_id": self.attribution_id}
@dataclass(frozen=True)
class LineageTrace:
    """The result of walking one piece of evidence back to its system.
    Every level is filled from resolved references, never from strings the
    caller supplied at trace time.
    """
    evidence_ref: str
    participant_id: str
    participant_name: str
    participant_kind: str
    agent_id: Optional[str]
    agent_instance_id: str
    execution_id: str
    session_id: Optional[str]
    relationships: tuple
    """(kind, source_name, target_name, delegation_id, handoff_id,
    relation_id) — the declared context. Not a causal chain."""
    parent_name: Optional[str]
    topology_id: str
    topology_hash: str
    system_id: str
    def as_path(self) -> tuple:
        """Evidence -> Agent Instance -> Execution/Session -> Relationship
        -> Topology -> System, in that order."""
        return (
            ("evidence", self.evidence_ref),
            ("agent_instance", f"{self.participant_name}"
                               f"[{self.agent_instance_id}]"),
            ("execution", self.execution_id),
            ("session", self.session_id),
            ("relationships", tuple(r[0] for r in self.relationships)),
            ("topology", self.topology_id),
            ("system", self.system_id),
        )
@dataclass(frozen=True)
class EvidenceLineage:
    """Attributions bound to one SystemTopology, content-addressed.
    Validated at construction against the topology it references: every
    participant, instance and relation must resolve. A lineage with a
    dangling reference cannot be built, so it cannot be relied on.
    """
    topology: "SystemTopology"
    attributions: tuple = ()
    lineage_version: str = LINEAGE_VERSION
    lineage_id: str = ""
    lineage_hash: str = ""
    def __post_init__(self):
        if not self.topology.verify()["valid"]:
            raise LineageError(
                "the referenced topology does not verify; attributions "
                "bound to an altered topology would resolve against content "
                "nobody declared")
        self._validate()
        if not self.lineage_id:
            object.__setattr__(self, "lineage_id", self._derive_id())
        if not self.lineage_hash:
            object.__setattr__(self, "lineage_hash", self._compute_hash())
    def _validate(self):
        t = self.topology
        relation_ids = {r.relation_id for r in t.relations}
        seen = set()
        for a in self.attributions:
            if a.attribution_id in seen:
                raise LineageError(f"duplicate attribution {a.attribution_id}")
            seen.add(a.attribution_id)
            p = t.participant(a.participant_id)
            if p is None:
                raise LineageError(
                    f"{a.evidence_ref} is attributed to {a.participant_id}, "
                    f"which is not in topology {t.topology_id}")
            if p.agent_instance_id and p.agent_instance_id != \
                    a.agent_instance_id:
                raise LineageError(
                    f"{a.evidence_ref} names instance {a.agent_instance_id} "
                    f"but {p.name} is declared as {p.agent_instance_id}")
            for rid in a.relation_ids:
                if rid not in relation_ids:
                    raise LineageError(
                        f"{a.evidence_ref} cites relation {rid}, which does "
                        f"not exist in the topology — a dangling relationship "
                        f"context cannot be verified")
                rel = next(r for r in t.relations if r.relation_id == rid)
                if a.participant_id not in (rel.source_id, rel.target_id):
                    raise LineageError(
                        f"{a.evidence_ref} cites {rel.kind} {rid}, but its "
                        f"producer is neither endpoint of that relation")
                if rel.execution_id and rel.execution_id != a.execution_id:
                    raise LineageError(
                        f"{a.evidence_ref} is in execution {a.execution_id} "
                        f"but cites a relation bound to {rel.execution_id}")
    # ── identity ────────────────────────────────────────────────────
    def _canonical(self) -> dict:
        return {
            "lineage_version": self.lineage_version,
            "topology_id": self.topology.topology_id,
            "topology_hash": self.topology.topology_hash,
            "attributions": sorted((a.to_dict() for a in self.attributions),
                                   key=lambda d: d["attribution_id"]),
        }
    def _derive_id(self) -> str:
        blob = json.dumps(self._canonical(), sort_keys=True,
                          separators=(",", ":"), default=str)
        return "LIN-" + hashlib.sha256(blob.encode()).hexdigest()[:16]
    def _compute_hash(self) -> str:
        blob = json.dumps(self._canonical(), sort_keys=True,
                          separators=(",", ":"), default=str)
        return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()
    def verify(self) -> dict:
        """Check that the lineage id and hash match its content and that the topology it references still verifies. Returns `{"valid": bool, "problems": [...]}`."""
        problems = []
        if self.lineage_id != self._derive_id():
            problems.append("lineage_id does not match its content")
        if self.lineage_hash != self._compute_hash():
            problems.append("lineage content was altered")
        if not self.topology.verify()["valid"]:
            problems.append("the referenced topology no longer verifies")
        return {"valid": not problems, "problems": problems}
    # ── the traversal the directive requires ─────────────────────────
    def trace(self, evidence_ref: str) -> LineageTrace:
        """Evidence -> Agent Instance -> Execution/Session -> Relationship
        -> Topology -> System.
        Raises rather than returning a partial trace: a lineage that could
        silently skip a level would answer "which agent produced this?" with
        less than it appears to.
        """
        matches = [a for a in self.attributions
                   if a.evidence_ref == evidence_ref]
        if not matches:
            raise LineageError(
                f"{evidence_ref} has no attribution in lineage "
                f"{self.lineage_id}")
        if len(matches) > 1:
            raise LineageError(
                f"{evidence_ref} is attributed {len(matches)} times; a single "
                f"producer cannot be determined")
        a = matches[0]
        t = self.topology
        # A lineage whose hash no longer verifies can name a participant or relation the topology
        # does not contain. Say so, rather than dying on an AttributeError or a bare StopIteration
        # that gives no hint the cause is a corrupted artefact.
        p = t.participant(a.participant_id)
        if p is None:
            raise LineageError(
                f"{evidence_ref} is attributed to {a.participant_id}, which is not a participant "
                f"of topology {t.topology_id}; the lineage has been altered or mismatched")
        parent = t.parent_of(a.participant_id)
        rels = []
        for rid in a.relation_ids:
            r = next((x for x in t.relations if x.relation_id == rid), None)
            src = t.participant(r.source_id) if r is not None else None
            dst = t.participant(r.target_id) if r is not None else None
            if r is None or src is None or dst is None:
                raise LineageError(
                    f"{evidence_ref} cites relation {rid}, which is not a complete relation of "
                    f"topology {t.topology_id}; the lineage has been altered or mismatched")
            rels.append((r.kind, src.name, dst.name, r.delegation_id,
                         r.handoff_id, r.relation_id))
        return LineageTrace(
            evidence_ref=a.evidence_ref, participant_id=p.participant_id,
            participant_name=p.name, participant_kind=p.kind,
            agent_id=p.agent_id, agent_instance_id=a.agent_instance_id,
            execution_id=a.execution_id, session_id=a.session_id,
            relationships=tuple(rels),
            parent_name=parent.name if parent else None,
            topology_id=t.topology_id, topology_hash=t.topology_hash,
            system_id=t.system_id)
    def evidence_produced_by(self, participant_id: str) -> tuple:
        """The evidence references attributed to `participant_id`."""
        return tuple(a.evidence_ref for a in self.attributions
                     if a.participant_id == participant_id)
    def to_dict(self) -> dict:
        """The JSON-serialisable form, including `lineage_id` and `lineage_hash`."""
        d = self._canonical()
        d["lineage_id"] = self.lineage_id
        d["lineage_hash"] = self.lineage_hash
        return d
