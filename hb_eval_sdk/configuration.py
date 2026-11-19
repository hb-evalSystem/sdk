"""
hb_eval_sdk/configuration.py — what was running, and how it was tested
=======================================================================

THE GAP THIS CLOSES
The Phase 4 audit found it precisely: evidence records **what happened**, and
does not record **what was running when it happened**.

A FaultEvent today can prove a timeout fired on `carrier_lookup` at a given
moment. It cannot say which model produced the agent's decisions, which prompt
shaped them, which tools were available, or which policy was in force. Two
runs producing different numbers therefore cannot be compared, because nothing
establishes they were runs of the same thing.

Every downstream phase depends on closing this. A baseline is a comparison
point only if what it is a baseline OF is identified; a diff attributes change
only if it can name which component moved; a certificate asserts reliability
of something only if that something has an identity.

TWO IDENTITIES, DELIBERATELY SEPARATE

    ConfigurationFingerprint    what the agent IS
                                model, prompt, tools, memory, policy

    EvaluationIdentity          how it was TESTED
                                protocol, battery, environment, seeds

They are separate because they change for different reasons and invalidate
different evidence. Swapping the model changes what the agent is; upgrading
Python changes how it was tested. Conflating them means every environment
change looks like an agent change, and recertification fires on noise until
somebody switches it off.

HASHES, NOT CONTENTS
A prompt hash proves two runs used the same prompt without putting the prompt
into an artefact that will travel further than the prompt would have. The same
applies to tool manifests and policy documents.

WHAT THIS FILE IS NOT
Not a certificate, and not evidence. A fingerprint answers "what configuration
was this?" and nothing else. What was tested and what happened is the
envelope's job; what may be concluded from it is certification's. The four
stay separate.
"""
from __future__ import annotations

import hashlib
import json
import platform
import sys
from dataclasses import dataclass, asdict
from typing import Any, Optional


__all__ = [
    "ConfigurationFingerprint", "EvaluationIdentity",
    "hash_content", "hash_manifest", "environment_fingerprint",
    "ConfigurationError",
]


class ConfigurationError(Exception):
    """Raised when an identity cannot be constructed.

    Deliberately an error rather than a default. A fingerprint with a
    placeholder for the model is worse than no fingerprint: it is a claim of
    identity that identifies nothing, and everything downstream treats it as
    though it did.
    """


# ═══════════════════════════════════════════════════════════════════════
#  HASHING
# ═══════════════════════════════════════════════════════════════════════

def hash_content(content: str, *, label: str = "") -> str:
    """SHA-256 of text, prefixed so a reader can tell what it is.

    EXACT, INCLUDING WHITESPACE. A prompt differing only in trailing spaces is
    a different prompt: tokenisation differs and the model may behave
    differently. Normalising here would let a changed prompt keep the identity
    of the one it replaced, which is failure case 3.
    """
    if content is None:
        raise ConfigurationError(
            f"cannot hash None{' for ' + label if label else ''}. An absent "
            f"component must be declared absent explicitly, not passed as "
            f"None - otherwise two different absences hash alike.")
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()


def hash_manifest(items: Any, *, label: str = "") -> str:
    """Hash a structured manifest - tools, MCP servers, memory policy.

    Canonicalised with sorted keys, so dict ordering (which Python does not
    guarantee across constructions) cannot change the identity of an unchanged
    manifest.

    Order within a LIST is preserved, because tool order can matter: a model
    presented with tools in a different sequence may choose differently, and
    that is a real difference rather than a formatting one.
    """
    if items is None:
        raise ConfigurationError(
            f"cannot hash None{' for ' + label if label else ''}")
    canonical = json.dumps(items, sort_keys=True, separators=(",", ":"),
                           default=str, ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def environment_fingerprint(*, include_packages: tuple = ()) -> dict:
    """Identify the environment a run happened in.

    Answers failure case 7: the same test re-run elsewhere must not be treated
    as the same evidence. A result produced under Python 3.9 and one under
    3.12 are two results, and a comparison ignoring that is comparing
    environments while believing it compares agents.

    `include_packages` is explicit rather than a full pip freeze. A freeze
    changes when anything moves, including packages the agent never imports,
    and an identity that changes for irrelevant reasons produces
    recertification on noise.
    """
    env = {
        "python_version": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
    }

    if include_packages:
        versions = {}
        for name in include_packages:
            try:
                import importlib.metadata as md
                versions[name] = md.version(name)
            except Exception:
                versions[name] = "unavailable"
        env["packages"] = versions  # type: ignore[assignment]

    canonical = json.dumps(env, sort_keys=True, separators=(",", ":"))
    env["fingerprint"] = (
        "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()[:32])
    return env


# ═══════════════════════════════════════════════════════════════════════
#  CONFIGURATION IDENTITY - what the agent IS
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ConfigurationFingerprint:
    """An immutable identity for one agent configuration.

    Frozen for the reason FaultEvent is: an identity editable after the fact
    is not an identity. If a field was wrong when it was built, the
    fingerprint is wrong and a new one is needed - the correct failure mode,
    because the alternative is evidence silently re-attributed to a
    configuration that did not produce it.
    """

    agent_id: str
    agent_version: str

    model_id: str
    model_version: Optional[str]

    prompt_hash: str
    tool_manifest_hash: str

    mcp_manifest_hash: Optional[str] = None
    memory_policy_hash: Optional[str] = None
    policy_version: str = "none"

    declared_absent: tuple = ()
    """Components deliberately not in use, named explicitly.

    Answers failure case 8: a valid hash with insufficient provenance. An
    agent with no MCP servers and an agent whose MCP manifest was never
    captured both yield mcp_manifest_hash=None, and they are not the same
    situation. Declaring absence separates 'this agent has none' from 'nobody
    recorded it'."""

    def __post_init__(self):
        required = {
            "agent_id": self.agent_id,
            "agent_version": self.agent_version,
            "model_id": self.model_id,
            "prompt_hash": self.prompt_hash,
            "tool_manifest_hash": self.tool_manifest_hash,
        }
        missing = [k for k, v in required.items() if not v]
        if missing:
            raise ConfigurationError(
                f"configuration identity requires {', '.join(missing)}. A "
                f"reliability result attached to an agent of unknown version "
                f"cannot be compared to anything, which is the failure this "
                f"class exists to prevent.")

        for name, value in (("mcp_manifest_hash", self.mcp_manifest_hash),
                            ("memory_policy_hash", self.memory_policy_hash)):
            if value is None and name not in self.declared_absent:
                raise ConfigurationError(
                    f"{name} is None and not in declared_absent. Add it there "
                    f"if this agent genuinely has none. An unrecorded "
                    f"component and an absent one look identical in the hash "
                    f"and mean different things.")

    def components(self) -> dict:
        """The fields constituting identity. `declared_absent` is not one: it
        documents why a field is None and does not change what the
        configuration IS."""
        return {
            "agent_id": self.agent_id,
            "agent_version": self.agent_version,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "prompt_hash": self.prompt_hash,
            "tool_manifest_hash": self.tool_manifest_hash,
            "mcp_manifest_hash": self.mcp_manifest_hash,
            "memory_policy_hash": self.memory_policy_hash,
            "policy_version": self.policy_version,
        }

    def fingerprint(self) -> str:
        """Stable across processes and machines, because it derives only from
        declared components and never from anything ambient."""
        canonical = json.dumps(self.components(), sort_keys=True,
                               separators=(",", ":"))
        return "CFP-" + hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def diff(self, other: "ConfigurationFingerprint") -> dict:
        """Which components differ, named individually.

        Component-level rather than changed/unchanged, because Phase 5's diff
        and Phase 8's recertification both need to know WHICH component moved.
        A model change and a policy change invalidate different evidence and
        warrant different responses; a boolean cannot express that.
        """
        mine, theirs = self.components(), other.components()
        changed = {k: {"from": mine[k], "to": theirs[k]}
                   for k in mine if mine[k] != theirs[k]}
        return {
            "identical": not changed,
            "changed_components": sorted(changed),
            "changes": changed,
            "from_fingerprint": self.fingerprint(),
            "to_fingerprint": other.fingerprint(),
        }

    def to_dict(self) -> dict:
        """The JSON-serialisable form of the configuration, with its computed `fingerprint` added."""
        d = asdict(self)
        d["fingerprint"] = self.fingerprint()
        return d


# ═══════════════════════════════════════════════════════════════════════
#  EVALUATION IDENTITY - how it was TESTED
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class EvaluationIdentity:
    """How an evaluation was conducted, as distinct from what it evaluated.

    Separate from ConfigurationFingerprint because these change for different
    reasons and invalidate different things. A new fault battery means the
    agent was tested differently; a new model means a different agent was
    tested.
    """

    evaluation_protocol_version: str
    fault_battery_id: str
    fault_battery_fingerprint: str
    scoring_version: str
    metric_versions: dict

    environment: dict
    seeds: tuple = ()

    judge_method: Optional[str] = None
    judge_version: Optional[str] = None
    """Both None while no judge is validated.

    Deliberately nullable. Phase 3 selected no judge, and Phase 3B admitted
    tool_relationship to the input contract without settling the judge itself.
    Recording a judge_version before one is validated is how a provisional
    choice becomes settled without anyone deciding."""

    def __post_init__(self):
        for name in ("evaluation_protocol_version", "fault_battery_id",
                     "scoring_version"):
            if not getattr(self, name):
                raise ConfigurationError(
                    f"evaluation identity requires {name}. Results produced "
                    f"under an unidentified protocol cannot be compared to "
                    f"results produced under any other.")
        if "fingerprint" not in self.environment:
            raise ConfigurationError(
                "environment must carry a fingerprint. Use "
                "environment_fingerprint(). Without it, the same test re-run "
                "elsewhere is indistinguishable from the original run.")

    def fingerprint(self) -> str:
        """A `sha256:` digest over the evaluation protocol, battery fingerprint, scoring version, metric versions, environment fingerprint and seeds. Two evaluations with different fingerprints were not run under the same conditions."""
        canonical = json.dumps({
            "protocol": self.evaluation_protocol_version,
            "battery": self.fault_battery_fingerprint,
            "scoring": self.scoring_version,
            "metrics": self.metric_versions,
            "environment": self.environment.get("fingerprint"),
            "seeds": list(self.seeds),
            "judge": [self.judge_method, self.judge_version],
        }, sort_keys=True, separators=(",", ":"))
        return "EVI-" + hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def diff(self, other: "EvaluationIdentity") -> dict:
        """Compare this identity with another field by field and return the fields that differ, so a refusal to compare can say exactly why."""
        def flat(e):
            return {
                "evaluation_protocol_version": e.evaluation_protocol_version,
                "fault_battery_fingerprint": e.fault_battery_fingerprint,
                "scoring_version": e.scoring_version,
                "environment_fingerprint": e.environment.get("fingerprint"),
                "judge_method": e.judge_method,
                "judge_version": e.judge_version,
            }
        mine, theirs = flat(self), flat(other)
        changed = {k: {"from": mine[k], "to": theirs[k]}
                   for k in mine if mine[k] != theirs[k]}
        return {
            "identical": not changed,
            "changed_components": sorted(changed),
            "changes": changed,
        }

    def to_dict(self) -> dict:
        """The JSON-serialisable form of the identity, with its computed `fingerprint` added."""
        d = asdict(self)
        d["fingerprint"] = self.fingerprint()
        return d
