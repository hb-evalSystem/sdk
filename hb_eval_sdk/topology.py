"""
hb_eval_sdk/topology.py — R2: multi-agent identity and the relationship plane
THE PROBLEM THIS SOLVES, MEASURED BEFORE BUILDING
    The evidence core is single-agent by construction:
        ConfigurationFingerprint   one agent_id. No system, no parent,
                                   no peers.
        ExecutionBinding           one configuration_fingerprint per
                                   execution.
        record_step(...)           no field says WHICH agent acted.
    So a delegation chain
        System -> Agent A -> delegates to B -> B calls Tool X
               -> X writes Memory Y -> B reports to A -> A acts
    is recorded today as a flat sequence under one agent_id. The system can
    say "a step failed"; it cannot say "Agent B's tool call failed".
    And `record_step(metadata=...)` is a free dict. A caller could put agent
    names in it, but nothing types it, nothing validates it, and no metric,
    provenance reference, comparability rule or decision consumes it.
    ATTRIBUTION THROUGH AN UNVALIDATED DICT IS NOT ATTRIBUTION, and this
    module exists because that distinction is the whole point.
WHY A PARALLEL PLANE RATHER THAN NEW FIELDS
    `hb-eval-evidence/v1` is FROZEN (Phase 9A), and `ce481b32763df1ca` has
    not moved since Phase 0. Adding `agent_id` to a step, or `system_id` to
    ConfigurationFingerprint, would change a canonical form, move every
    existing fingerprint, and reopen DW-008 the moment it closed.
    So topology is a SEPARATE artefact that REFERENCES frozen artefacts by
    hash and by execution/session id. The reference is ONE-WAY: nothing is
    written into evidence. This is the same shape PolicyDocument established
    in R1, deliberately.
WHAT THIS MODULE DOES NOT DO
    No causal attribution. A relation records that B was DELEGATED_TO by A,
    because the caller declared it and evidence can be bound to it. It does
    NOT claim that A caused B's outcome. DW-015 stands: a difference is
    reported, never explained.
    No evaluation. Topology carries structure. Metrics, comparability and
    decisions are untouched.
    No enforcement. That is R8.
READY FOR R3
    Every Relation can carry `execution_id`, `session_id` and evidence
    references, so R3 can bind "which agent produced which evidence" without
    this module needing to change.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional
__all__ = [
    "ParticipantKind",
    "RelationKind",
    "Participant",
    "Relation",
    "SystemTopology",
    "TopologyError",
    "TOPOLOGY_VERSION",
]
TOPOLOGY_VERSION = "hb-eval-topology/v1"
"""Versioned separately from hb-eval-evidence/v1 and hb-eval-policy/v1.
A change to how topology is represented must never be able to move an
evidence artefact's identity.
"""
class TopologyError(Exception):
    """The declared structure is not coherent."""
class ParticipantKind:
    """The kinds of participant in a system: SYSTEM, AGENT, SUB_AGENT, TOOL and MEMORY."""
    SYSTEM = "SYSTEM"
    AGENT = "AGENT"
    SUB_AGENT = "SUB_AGENT"
    TOOL = "TOOL"
    MEMORY = "MEMORY"
    ALL = (SYSTEM, AGENT, SUB_AGENT, TOOL, MEMORY)
class RelationKind:
    """The eleven declared relation types. Closed set, by design.
    An open vocabulary would be free-form metadata wearing a type's clothes:
    a consumer could not know what a relation means, and R3 could not bind
    evidence to it reliably.
    """
    PARENT_OF = "PARENT_OF"
    SUB_AGENT_OF = "SUB_AGENT_OF"
    DELEGATED_TO = "DELEGATED_TO"
    HANDOFF_TO = "HANDOFF_TO"
    PEER_OF = "PEER_OF"
    MEMBER_OF = "MEMBER_OF"
    USES_TOOL = "USES_TOOL"
    READS_MEMORY = "READS_MEMORY"
    WRITES_MEMORY = "WRITES_MEMORY"
    SPAWNS = "SPAWNS"
    TERMINATES = "TERMINATES"
    ALL = (PARENT_OF, SUB_AGENT_OF, DELEGATED_TO, HANDOFF_TO, PEER_OF,
           MEMBER_OF, USES_TOOL, READS_MEMORY, WRITES_MEMORY, SPAWNS,
           TERMINATES)
    SYMMETRIC = (PEER_OF,)
    """PEER_OF holds in both directions. Every other relation is directed,
    and the direction carries meaning: PARENT_OF is not SUB_AGENT_OF
    reversed by accident — one is declared by the parent's side."""
    TARGET_KIND = {
        USES_TOOL: (ParticipantKind.TOOL,),
        READS_MEMORY: (ParticipantKind.MEMORY,),
        WRITES_MEMORY: (ParticipantKind.MEMORY,),
    }
    """Where the target's kind is fixed by the relation's meaning. Checked,
    so USES_TOOL cannot silently point at another agent."""
@dataclass(frozen=True)
class Participant:
    """A typed, content-addressed identity in a multi-agent system.
    `participant_id` is DERIVED, following R1 and 5D-B: two participants
    with identical declared identity ARE the same participant, and an
    assigned id would let one actor appear under two names in the same
    topology.
    """
    kind: str
    name: str
    """The caller's stable name for this participant, e.g. "researcher"."""
    system_id: Optional[str] = None
    agent_id: Optional[str] = None
    agent_instance_id: Optional[str] = None
    team_id: Optional[str] = None
    configuration_fingerprint: Optional[str] = None
    """A one-way reference into the frozen evidence core. Nothing is written
    back; this only records which configuration this participant ran."""
    participant_id: str = ""
    def __post_init__(self):
        if self.kind not in ParticipantKind.ALL:
            raise TopologyError(
                f"unknown participant kind {self.kind!r}; expected one of "
                f"{ParticipantKind.ALL}")
        if not self.name:
            raise TopologyError("a participant must have a name")
        if not self.participant_id:
            object.__setattr__(self, "participant_id", self._derive_id())
    def _identity(self) -> dict:
        return {"kind": self.kind, "name": self.name,
                "system_id": self.system_id, "agent_id": self.agent_id,
                "agent_instance_id": self.agent_instance_id,
                "team_id": self.team_id,
                "configuration_fingerprint": self.configuration_fingerprint}
    def _derive_id(self) -> str:
        blob = json.dumps(self._identity(), sort_keys=True,
                          separators=(",", ":"), default=str)
        return "PT-" + hashlib.sha256(blob.encode()).hexdigest()[:16]
    def to_dict(self) -> dict:
        """The JSON-serialisable form, including the derived `participant_id`."""
        return {**self._identity(), "participant_id": self.participant_id}
@dataclass(frozen=True)
class Relation:
    """A typed, directed edge between two participants.
    EVIDENCE-BINDABLE BY CONSTRUCTION. `execution_id`, `session_id` and
    `evidence_refs` exist so R3 can answer "which agent produced which
    evidence" without this module changing.
    TEMPORAL. `occurred_at_step` and `sequence` let a delegation chain be
    ordered, which a flat set of edges could not express.
    """
    kind: str
    source_id: str
    target_id: str
    delegation_id: Optional[str] = None
    handoff_id: Optional[str] = None
    execution_id: Optional[str] = None
    session_id: Optional[str] = None
    occurred_at_step: Optional[int] = None
    sequence: Optional[int] = None
    evidence_refs: tuple = ()
    """One-way references to frozen artefacts, by hash or typed ref."""
    relation_id: str = ""
    def __post_init__(self):
        if self.kind not in RelationKind.ALL:
            raise TopologyError(
                f"unknown relation kind {self.kind!r}; the vocabulary is "
                f"closed by design — an open one would be free-form metadata "
                f"wearing a type's clothes. Expected one of "
                f"{RelationKind.ALL}")
        if not self.source_id or not self.target_id:
            raise TopologyError("a relation needs both endpoints")
        if self.source_id == self.target_id:
            raise TopologyError(
                f"{self.kind} points a participant at itself")
        if self.kind == RelationKind.DELEGATED_TO and not self.delegation_id:
            raise TopologyError(
                "DELEGATED_TO requires a delegation_id: an untraceable "
                "delegation cannot be bound to evidence in R3")
        if self.kind == RelationKind.HANDOFF_TO and not self.handoff_id:
            raise TopologyError("HANDOFF_TO requires a handoff_id")
        if not self.relation_id:
            object.__setattr__(self, "relation_id", self._derive_id())
    def _identity(self) -> dict:
        return {"kind": self.kind, "source_id": self.source_id,
                "target_id": self.target_id,
                "delegation_id": self.delegation_id,
                "handoff_id": self.handoff_id,
                "execution_id": self.execution_id,
                "session_id": self.session_id,
                "occurred_at_step": self.occurred_at_step,
                "sequence": self.sequence}
    def _derive_id(self) -> str:
        blob = json.dumps(self._identity(), sort_keys=True,
                          separators=(",", ":"), default=str)
        return "RL-" + hashlib.sha256(blob.encode()).hexdigest()[:16]
    def to_dict(self) -> dict:
        """The JSON-serialisable form, including the derived `relation_id` and the evidence references."""
        return {**self._identity(), "relation_id": self.relation_id,
                "evidence_refs": list(self.evidence_refs)}
@dataclass(frozen=True)
class SystemTopology:
    """The declared structure of a multi-agent system, content-addressed.
    A single-agent system is expressible here without ceremony: one AGENT
    participant and no relations. The advanced case and the simple case use
    the same model, which §12 of the directive requires.
    """
    system_id: str
    participants: tuple = ()
    relations: tuple = ()
    topology_version: str = TOPOLOGY_VERSION
    topology_id: str = ""
    topology_hash: str = ""
    def __post_init__(self):
        if not self.system_id:
            raise TopologyError("a topology must declare a system_id")
        self._validate()
        if not self.topology_id:
            object.__setattr__(self, "topology_id", self._derive_id())
        if not self.topology_hash:
            object.__setattr__(self, "topology_hash", self._compute_hash())
    # ── validation: this is what makes it authoritative ─────────────
    def _validate(self):
        ids = [p.participant_id for p in self.participants]
        if len(ids) != len(set(ids)):
            raise TopologyError(
                "the same participant appears twice; identity is derived "
                "from declared content, so a duplicate means the same actor "
                "was declared twice")
        by_id = {p.participant_id: p for p in self.participants}
        for r in self.relations:
            for endpoint, label in ((r.source_id, "source"),
                                    (r.target_id, "target")):
                if endpoint not in by_id:
                    raise TopologyError(
                        f"{r.kind} names a {label} {endpoint} that is not a "
                        f"participant in this topology — a dangling relation "
                        f"cannot be bound to evidence")
            expected = RelationKind.TARGET_KIND.get(r.kind)
            if expected and by_id[r.target_id].kind not in expected:
                raise TopologyError(
                    f"{r.kind} must target {expected}, but "
                    f"{by_id[r.target_id].name} is a "
                    f"{by_id[r.target_id].kind}")
    # ── identity and integrity ──────────────────────────────────────
    def _canonical(self) -> dict:
        return {
            "system_id": self.system_id,
            "topology_version": self.topology_version,
            "participants": sorted(
                (p.to_dict() for p in self.participants),
                key=lambda d: d["participant_id"]),
            "relations": sorted(
                (r.to_dict() for r in self.relations),
                key=lambda d: d["relation_id"]),
        }
    def _derive_id(self) -> str:
        blob = json.dumps(self._canonical(), sort_keys=True,
                          separators=(",", ":"), default=str)
        return "TOP-" + hashlib.sha256(blob.encode()).hexdigest()[:16]
    def _compute_hash(self) -> str:
        blob = json.dumps(self._canonical(), sort_keys=True,
                          separators=(",", ":"), default=str)
        return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()
    def verify(self) -> dict:
        """Check that `topology_id` and `topology_hash` match the content. Returns `{"valid": bool, "problems": [...]}`."""
        problems = []
        if self.topology_id != self._derive_id():
            problems.append("topology_id does not match its content")
        if self.topology_hash != self._compute_hash():
            problems.append("topology content was altered")
        return {"valid": not problems, "problems": problems}
    # ── queries the directive requires the model to answer ──────────
    def participant(self, participant_id: str) -> Optional[Participant]:
        """The participant with this id, or None if the topology has none."""
        for p in self.participants:
            if p.participant_id == participant_id:
                return p
        return None
    def relations_from(self, participant_id: str, kind: Optional[str] = None
                       ) -> tuple:
        """Relations whose source is `participant_id`, optionally only of one kind."""
        return tuple(r for r in self.relations
                     if r.source_id == participant_id
                     and (kind is None or r.kind == kind))
    def relations_to(self, participant_id: str, kind: Optional[str] = None
                     ) -> tuple:
        """Relations whose target is `participant_id`, optionally only of one kind."""
        return tuple(r for r in self.relations
                     if r.target_id == participant_id
                     and (kind is None or r.kind == kind))
    def who_delegated_to(self, participant_id: str) -> tuple:
        """'Who delegated the task?' — §9."""
        return tuple(self.participant(r.source_id)
                     for r in self.relations_to(participant_id,
                                                RelationKind.DELEGATED_TO))
    def parent_of(self, participant_id: str) -> Optional[Participant]:
        """The participant that is the PARENT_OF source for `participant_id`, or None if it has no parent."""
        edges = self.relations_to(participant_id, RelationKind.PARENT_OF)
        return self.participant(edges[0].source_id) if edges else None
    def delegation_chain(self, delegation_id: str) -> tuple:
        """The ordered chain for one delegation — the temporal semantics a
        flat edge set could not express."""
        chain = [r for r in self.relations
                 if r.delegation_id == delegation_id]
        return tuple(sorted(chain, key=lambda r: (
            r.sequence if r.sequence is not None else 0,
            r.occurred_at_step if r.occurred_at_step is not None else 0)))
    def relations_for_execution(self, execution_id: str) -> tuple:
        """R3's entry point: every relation bound to one execution."""
        return tuple(r for r in self.relations
                     if r.execution_id == execution_id)
    # ── serialisation ───────────────────────────────────────────────
    def to_dict(self) -> dict:
        """The JSON-serialisable form, including `topology_id` and `topology_hash`."""
        d = self._canonical()
        d["topology_id"] = self.topology_id
        d["topology_hash"] = self.topology_hash
        return d
    @classmethod
    def from_dict(cls, data: dict) -> "SystemTopology":
        """Reconstruct a topology from `to_dict()` output. Raises TopologyError naming any missing field. Call `verify()` on the result: reconstruction does not by itself prove the content is unaltered."""
        required = ("system_id", "participants", "relations", "topology_id",
                    "topology_hash")
        missing = [k for k in required if k not in data]
        if missing:
            raise TopologyError(
                f"cannot reconstruct a topology: {missing} absent")
        participants = tuple(
            Participant(kind=p["kind"], name=p["name"],
                        system_id=p.get("system_id"),
                        agent_id=p.get("agent_id"),
                        agent_instance_id=p.get("agent_instance_id"),
                        team_id=p.get("team_id"),
                        configuration_fingerprint=p.get(
                            "configuration_fingerprint"))
            for p in data["participants"])
        relations = tuple(
            Relation(kind=r["kind"], source_id=r["source_id"],
                     target_id=r["target_id"],
                     delegation_id=r.get("delegation_id"),
                     handoff_id=r.get("handoff_id"),
                     execution_id=r.get("execution_id"),
                     session_id=r.get("session_id"),
                     occurred_at_step=r.get("occurred_at_step"),
                     sequence=r.get("sequence"),
                     evidence_refs=tuple(r.get("evidence_refs", ())))
            for r in data["relations"])
        topo = cls(system_id=data["system_id"], participants=participants,
                   relations=relations,
                   topology_version=data.get("topology_version",
                                             TOPOLOGY_VERSION))
        if topo.topology_id != data["topology_id"]:
            raise TopologyError(
                f"topology_id mismatch: stored {data['topology_id']}, "
                f"derived {topo.topology_id}")
        if topo.topology_hash != data["topology_hash"]:
            raise TopologyError("the topology does not round-trip")
        return topo
    def __repr__(self) -> str:
        return (f"<SystemTopology {self.topology_id} "
                f"{len(self.participants)} participants, "
                f"{len(self.relations)} relations>")
