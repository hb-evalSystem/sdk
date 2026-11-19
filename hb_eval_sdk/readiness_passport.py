"""
hb_eval_sdk/readiness_passport.py — R4: the V2 Readiness Passport
WHAT A READINESS PASSPORT IS
    An evidence-backed readiness record under a declared scope, policy and
    identity. It answers ONE question:
        Is this agent or system supported by sufficient pre-production
        evidence for the declared policy and scope?
THE RULE THIS MODULE IS BUILT AROUND
    A PASSPORT DOES NOT CREATE EVIDENCE.
    It references artefacts that already exist — an attestation, the
    baseline it attests, a policy document, a topology, a lineage, optionally
    a context assessment — checks that they are about the same thing, and
    makes the combination verifiable. Nothing in a passport is computed here
    that was not already decided upstream.
    Concretely, there is:
        no score, no grade, no overall number
        no new decision — the decision is the attestation's
        no assurance tier — tiers belong to the verified path and their
                            requirements are not yet implemented, so the
                            field is NOT_ASSIGNED, with the reason
        no signature — DW-009; verification is by content hash and by
                       re-resolving every reference
WHY THIS IS NOT THE V1 PASSPORT RENAMED
    The V1 Passport is a platform record of reported metrics. This one is
    DERIVED: issue() refuses unless the attestation verifies against its
    subject, the policy document is the policy the decision was made under,
    the lineage is bound to the topology, the subject is in the topology,
    and the declared scope is actually covered by attributed evidence.
SCOPE IS CHECKED, NOT DECLARED
    AGENT                  the subject is an agent, and evidence is
                           attributed to it
    SYSTEM                 EVERY agent in the topology has attributed
                           evidence. A system-level passport issued on one
                           agent's evidence would claim a whole system was
                           observed when one part was.
    INTERACTION            the named relations exist, and evidence is
                           attributed under them
    SHARED_INFRASTRUCTURE  the subject is a tool or memory, and evidence
                           touches it through a relation
    §6 of the directive requires the passport to say which of these the
    evidence applies to. Stating it without checking it would let the
    passport's most important claim be its least verified one.
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from typing import Optional
__all__ = [
    "ReadinessPassport",
    "PassportError",
    "ScopeLevel",
    "EvaluationPath",
    "issue_readiness_passport",
    "PASSPORT_VERSION",
]
PASSPORT_VERSION = "hb-eval-passport/v1"
class PassportError(Exception):
    """The artefacts offered do not support the passport requested."""
class ScopeLevel:
    """What a readiness passport covers: a single AGENT, a whole SYSTEM, an INTERACTION between participants, or SHARED_INFRASTRUCTURE."""
    AGENT = "AGENT"
    SYSTEM = "SYSTEM"
    INTERACTION = "INTERACTION"
    SHARED_INFRASTRUCTURE = "SHARED_INFRASTRUCTURE"
    ALL = (AGENT, SYSTEM, INTERACTION, SHARED_INFRASTRUCTURE)
class EvaluationPath:
    """How the evidence behind a passport was produced: LOCAL (the battery ran in the user's process) or VERIFIED (the Gateway called the agent itself). VERIFIED needs platform-mediated provenance that the SDK cannot establish, so the SDK refuses to issue it (PassportError); only the platform issues VERIFIED passports."""
    LOCAL = "LOCAL"
    VERIFIED = "VERIFIED"
    ALL = (LOCAL, VERIFIED)
_STANDING_NOT_OBSERVED = (
    "attribution is declared by the caller and validated for coherence; it "
    "was not observed at runtime",
    "no external signature or trust anchor (DW-009): verification is by "
    "content hash and reference resolution only",
    "relationship context is not causal attribution (DW-015)",
    "pre-production evidence only: nothing here describes behaviour after "
    "deployment",
)
@dataclass(frozen=True)
class ReadinessPassport:
    """Content-addressed. Two passports over the same references ARE the
    same passport."""
    # what was evaluated, and by which decision
    attestation_id: str
    attestation_hash: str
    decision_state: str
    decided_metrics: tuple
    """Per-metric, as the decision recorded them. No aggregate exists."""
    # under what
    configuration_fingerprint: str
    evaluation_fingerprint: str
    battery_spec_fingerprint: str
    battery_slot_id: str
    baseline_hash: str
    reference_baseline_hash: Optional[str]
    envelope_hash: str
    policy_id: str
    policy_hash: str
    policy_version: str
    # who
    system_id: str
    subject_participant_id: str
    subject_name: str
    subject_kind: str
    topology_id: str
    topology_hash: str
    lineage_id: str
    lineage_hash: str
    attributed_evidence: tuple
    # scope and limits
    scope_level: str
    scope_relations: tuple
    evaluation_path: str
    context_state: str
    not_observed: tuple
    assurance_tier: str = "NOT_ASSIGNED"
    assurance_tier_reason: str = (
        "tiers belong to the verified evaluation path and their evidence "
        "requirements are not yet implemented; no tier is displayed until "
        "they are")
    lifecycle_state: str = "CREATED"
    """R4 issues. Enrollment (R5) and operational transitions (R7) move it."""
    passport_version: str = PASSPORT_VERSION
    passport_id: str = ""
    passport_hash: str = ""
    def __post_init__(self):
        if not self.passport_id:
            object.__setattr__(self, "passport_id", self._derive_id())
        if not self.passport_hash:
            object.__setattr__(self, "passport_hash", self._compute_hash())
    def _canonical(self) -> dict:
        d = {k: getattr(self, k) for k in self.__dataclass_fields__
             if k not in ("passport_id", "passport_hash")}
        for k, v in d.items():
            if isinstance(v, tuple):
                d[k] = [list(x) if isinstance(x, tuple) else x for x in v]
        return d
    def _blob(self) -> bytes:
        return json.dumps(self._canonical(), sort_keys=True,
                          separators=(",", ":"), default=str).encode()
    def _derive_id(self) -> str:
        return "PP-" + hashlib.sha256(self._blob()).hexdigest()[:16]
    def _compute_hash(self) -> str:
        return "sha256:" + hashlib.sha256(self._blob()).hexdigest()
    def verify(self, attestation=None, policy_document=None, topology=None,
               lineage=None) -> dict:
        """Integrity of the passport itself, and — for each artefact
        supplied — that it is still the one the passport names."""
        problems = []
        if self.passport_id != self._derive_id():
            problems.append("passport_id does not match its content")
        if self.passport_hash != self._compute_hash():
            problems.append("passport content was altered")
        if attestation is not None and \
                attestation.attestation_hash != self.attestation_hash:
            problems.append("the attestation is not the one this passport "
                            "was issued on")
        if policy_document is not None and \
                policy_document.policy_hash != self.policy_hash:
            problems.append("the policy document is not the one named")
        if topology is not None and \
                topology.topology_hash != self.topology_hash:
            problems.append("the topology is not the one named")
        if lineage is not None and lineage.lineage_hash != self.lineage_hash:
            problems.append("the lineage is not the one named")
        return {"valid": not problems, "problems": problems}
    def to_dict(self) -> dict:
        """The JSON-serialisable form, including `passport_id` and `passport_hash`."""
        d = self._canonical()
        d["passport_id"] = self.passport_id
        d["passport_hash"] = self.passport_hash
        return d
def _agents(topology):
    return [p for p in topology.participants
            if p.kind in ("AGENT", "SUB_AGENT")]
def issue_readiness_passport(*, attestation, subject_baseline,
                             policy_document, topology, lineage,
                             subject_participant_id: str,
                             scope_level: str,
                             scope_relations: tuple = (),
                             evaluation_path: str = EvaluationPath.LOCAL,
                             context_assessment=None,
                             declared_not_observed: tuple = ()
                             ) -> ReadinessPassport:
    """Issue a Readiness Passport, or refuse with the reason.
    Every check below is a way the combination could be about different
    things while each part is individually valid. A passport assembled from
    a real attestation, a real policy and a real topology that do not refer
    to one another would verify piece by piece and mean nothing.
    """
    # ── the decision ────────────────────────────────────────────────
    v = attestation.verify(subject_baseline)
    if not v.get("valid"):
        raise PassportError(
            f"the attestation does not verify against its subject: "
            f"{v.get('problems')}")
    if attestation.decision_state != "PASS":
        raise PassportError(
            f"a readiness passport requires a PASS decision; got "
            f"{attestation.decision_state}")
    # ── the policy is the policy the decision was made under ────────
    if not policy_document.verify()["valid"]:
        raise PassportError("the policy document does not verify")
    if policy_document.kind != "SLO":
        raise PassportError(
            f"readiness is decided under an SLO policy; a {policy_document.kind}"
            f" policy governs runtime directives, not verdicts")
    if policy_document.policy_version != attestation.policy_version:
        raise PassportError(
            f"the decision was made under policy {attestation.policy_version}"
            f", but the policy document is {policy_document.policy_version}")
    # ── identity: topology and lineage agree ────────────────────────
    if not topology.verify()["valid"]:
        raise PassportError("the topology does not verify")
    if not lineage.verify()["valid"]:
        raise PassportError("the lineage does not verify")
    if lineage.topology.topology_hash != topology.topology_hash:
        raise PassportError(
            "the lineage is bound to a different topology; attributions "
            "would resolve against a structure this passport does not name")
    subject = topology.participant(subject_participant_id)
    if subject is None:
        raise PassportError(
            f"{subject_participant_id} is not a participant in "
            f"{topology.topology_id}")
    if subject.configuration_fingerprint and \
            subject.configuration_fingerprint != \
            attestation.configuration_fingerprint:
        raise PassportError(
            f"{subject.name} is declared with configuration "
            f"{subject.configuration_fingerprint}, but the attestation is "
            f"for {attestation.configuration_fingerprint}")
    # ── scope: checked against attributed evidence ──────────────────
    if scope_level not in ScopeLevel.ALL:
        raise PassportError(f"unknown scope level {scope_level!r}")
    attributed = {a.participant_id for a in lineage.attributions}
    if scope_level == ScopeLevel.AGENT:
        if subject.kind not in ("AGENT", "SUB_AGENT"):
            raise PassportError(
                f"AGENT scope needs an agent subject; {subject.name} is a "
                f"{subject.kind}")
        if subject.participant_id not in attributed:
            raise PassportError(
                f"no evidence is attributed to {subject.name}")
    elif scope_level == ScopeLevel.SYSTEM:
        unobserved = [p.name for p in _agents(topology)
                      if p.participant_id not in attributed]
        if unobserved:
            raise PassportError(
                f"a SYSTEM-scope passport requires attributed evidence from "
                f"every agent; none for {unobserved}. Issuing it would claim "
                f"a whole system was observed when part of it was not")
    elif scope_level == ScopeLevel.INTERACTION:
        if not scope_relations:
            raise PassportError("INTERACTION scope must name its relations")
        known = {r.relation_id for r in topology.relations}
        missing = [r for r in scope_relations if r not in known]
        if missing:
            raise PassportError(f"relations not in the topology: {missing}")
        cited = {rid for a in lineage.attributions for rid in a.relation_ids}
        uncovered = [r for r in scope_relations if r not in cited]
        if uncovered:
            raise PassportError(
                f"no evidence is attributed under relations {uncovered}")
    elif scope_level == ScopeLevel.SHARED_INFRASTRUCTURE:
        if subject.kind not in ("TOOL", "MEMORY"):
            raise PassportError(
                f"SHARED_INFRASTRUCTURE scope needs a tool or memory subject;"
                f" {subject.name} is a {subject.kind}")
        touching = {r.relation_id for r in topology.relations
                    if r.target_id == subject.participant_id}
        cited = {rid for a in lineage.attributions for rid in a.relation_ids}
        if not touching & cited:
            raise PassportError(
                f"no attributed evidence touches {subject.name}")
    # ── path: the SDK cannot establish verified provenance ──────────
    if evaluation_path not in EvaluationPath.ALL:
        raise PassportError(f"unknown evaluation path {evaluation_path!r}")
    if evaluation_path == EvaluationPath.VERIFIED:
        raise PassportError(
            "VERIFIED requires platform-mediated provenance, which the SDK "
            "cannot establish on its own. Issue as LOCAL; the verified path "
            "is issued by the platform")
    # ── context ─────────────────────────────────────────────────────
    if context_assessment is None:
        context_state = "NOT_ASSESSED"
    else:
        if context_assessment.attestation_hash != attestation.attestation_hash:
            raise PassportError(
                "the context assessment is for a different attestation")
        if context_assessment.state == "RECERTIFICATION_REQUIRED":
            raise PassportError(
                f"context changed since the decision "
                f"({list(context_assessment.invalidating)}); re-evaluate "
                f"before issuing")
        context_state = context_assessment.state
    not_observed = tuple(attestation.limitations) + _STANDING_NOT_OBSERVED \
        + tuple(declared_not_observed)
    if context_state == "NOT_ASSESSED":
        not_observed += ("context was not assessed at issuance",)
    return ReadinessPassport(
        attestation_id=attestation.attestation_id,
        attestation_hash=attestation.attestation_hash,
        decision_state=attestation.decision_state,
        decided_metrics=tuple(attestation.decided_metrics),
        configuration_fingerprint=attestation.configuration_fingerprint,
        evaluation_fingerprint=attestation.evaluation_fingerprint,
        battery_spec_fingerprint=attestation.battery_spec_fingerprint,
        battery_slot_id=attestation.battery_slot_id,
        baseline_hash=attestation.baseline_hash,
        reference_baseline_hash=attestation.reference_baseline_hash,
        envelope_hash=attestation.envelope_hash,
        policy_id=policy_document.policy_id,
        policy_hash=policy_document.policy_hash,
        policy_version=policy_document.policy_version,
        system_id=topology.system_id,
        subject_participant_id=subject.participant_id,
        subject_name=subject.name, subject_kind=subject.kind,
        topology_id=topology.topology_id,
        topology_hash=topology.topology_hash,
        lineage_id=lineage.lineage_id, lineage_hash=lineage.lineage_hash,
        attributed_evidence=tuple(sorted(
            a.evidence_ref for a in lineage.attributions)),
        scope_level=scope_level,
        scope_relations=tuple(sorted(scope_relations)),
        evaluation_path=evaluation_path,
        context_state=context_state,
        not_observed=not_observed,
    )
