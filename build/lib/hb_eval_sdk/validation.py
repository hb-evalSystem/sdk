"""
HB-Eval SDK — payload validation (Protocol §5 and §6).

This module is new in v2.1.0. It enforces the structural and logical
constraints of the evaluation contract BEFORE a payload is encrypted and
sent. This is the client half of defense in depth: the SDK refuses to
transmit malformed data, and the Gateway independently refuses to trust it.

Why validate on the client at all, if the Gateway also validates? Two
reasons. First, it gives the developer an immediate, clear error at the call
site instead of an opaque 400 from the network. Second, and more importantly
for a certification system, it closes the door on a class of manipulation
where a crafted payload (sub_tasks = 0, a missing trajectory, an impossible
recovery count) is used to coax a falsely high score. The validation rules
here are the same rules the Gateway enforces, by design.
"""

from typing import Any
from .exceptions import ValidationError


# Protocol §5 — agent_id length bound.
MAX_AGENT_ID_LENGTH = 128


def validate_payload(payload: dict[str, Any]) -> None:
    """
    Validate an evaluation payload against the canonical contract.

    Raises ValidationError with a precise message on the first violation.
    Returns None if the payload is valid. Does not mutate the payload.
    """
    if not isinstance(payload, dict):
        raise ValidationError("Payload must be a dictionary.")

    # ── trajectory: required, non-empty list of objects ──
    trajectory = payload.get("trajectory")
    if not isinstance(trajectory, list) or len(trajectory) == 0:
        raise ValidationError(
            "Field 'trajectory' is required and must be a non-empty list of step objects."
        )
    if not all(isinstance(step, dict) for step in trajectory):
        raise ValidationError("Every element of 'trajectory' must be an object (dict).")

    # ── sub_tasks: required int >= 1 (the oracle minimum step count) ──
    sub_tasks = payload.get("sub_tasks")
    if not isinstance(sub_tasks, int) or isinstance(sub_tasks, bool) or sub_tasks < 1:
        raise ValidationError(
            "Field 'sub_tasks' is required and must be an integer >= 1 "
            "(it is the oracle-minimum step count and cannot be zero or negative)."
        )

    # ── constraint_violations: int >= 0 ──
    violations = payload.get("constraint_violations", 0)
    if not isinstance(violations, int) or isinstance(violations, bool) or violations < 0:
        raise ValidationError("Field 'constraint_violations' must be an integer >= 0.")

    # ── recovery_episodes: list (may be empty); each episode validated ──
    episodes = payload.get("recovery_episodes", [])
    if not isinstance(episodes, list):
        raise ValidationError("Field 'recovery_episodes' must be a list (it may be empty).")
    for i, ep in enumerate(episodes):
        _validate_episode(ep, i)

    # ── ti_score: optional, but if present must be a number in [1.0, 5.0] ──
    ti = payload.get("ti_score")
    if ti is not None:
        if isinstance(ti, bool) or not isinstance(ti, (int, float)):
            raise ValidationError("Field 'ti_score' must be a number between 1.0 and 5.0, or null.")
        if not (1.0 <= float(ti) <= 5.0):
            raise ValidationError("Field 'ti_score' must be between 1.0 and 5.0 (the judge scale).")

    # ── agent_id: required non-empty string, bounded length ──
    agent_id = payload.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id.strip():
        raise ValidationError("Field 'agent_id' is required and must be a non-empty string.")
    if len(agent_id) > MAX_AGENT_ID_LENGTH:
        raise ValidationError(f"Field 'agent_id' must be at most {MAX_AGENT_ID_LENGTH} characters.")


def _validate_episode(episode: Any, index: int) -> None:
    """
    Validate a single recovery episode (Protocol §6).

    The logical constraint that matters most: an episode cannot claim it
    recovered in a negative number of steps, and the memory query (if present)
    cannot occur before the fault it responds to. These checks block the
    construction of physically impossible episodes designed to game IRS/FRR.
    """
    if not isinstance(episode, dict):
        raise ValidationError(f"recovery_episodes[{index}] must be an object (dict).")

    fault_onset = episode.get("fault_onset_step", 0)
    if not isinstance(fault_onset, int) or isinstance(fault_onset, bool) or fault_onset < 0:
        raise ValidationError(f"recovery_episodes[{index}].fault_onset_step must be an integer >= 0.")

    if "recovered" in episode and not isinstance(episode["recovered"], bool):
        raise ValidationError(f"recovery_episodes[{index}].recovered must be a boolean.")

    steps = episode.get("steps_to_recovery")
    if steps is not None:
        if not isinstance(steps, int) or isinstance(steps, bool) or steps < 0:
            raise ValidationError(
                f"recovery_episodes[{index}].steps_to_recovery must be an integer >= 0."
            )

    query_step = episode.get("memory_query_step")
    if query_step is not None:
        if not isinstance(query_step, int) or isinstance(query_step, bool):
            raise ValidationError(
                f"recovery_episodes[{index}].memory_query_step must be an integer or null."
            )
        # A memory query cannot logically precede the fault it responds to.
        if query_step < fault_onset:
            raise ValidationError(
                f"recovery_episodes[{index}].memory_query_step ({query_step}) cannot be "
                f"earlier than fault_onset_step ({fault_onset})."
            )

    for bool_field in ("approach_correct", "memory_similarity_met", "modification_verified"):
        if bool_field in episode and not isinstance(episode[bool_field], bool):
            raise ValidationError(f"recovery_episodes[{index}].{bool_field} must be a boolean.")
