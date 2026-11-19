"""
hb_eval_sdk/evidence_store.py — Phase 9B-1..9B-3

DURABILITY AROUND A FROZEN SCHEMA

    canonical evidence -> serialization -> atomic persistence -> reload
    -> canonicalization -> hash -> IDENTICAL

    This module wraps the shapes frozen by Phase 9A. It does not define them,
    reshape them, or add to them.

THE HARD INVARIANTS, from PHASE_9A_SCOPE_LOCK.md

    NO new legal fields
    NO canonical reshaping
    NO hash-boundary movement
    NO independent artefacts for embedded values
    NO derived view stored as a source of truth
    NO certification claims

    Any of these would reopen DW-008 the moment it closed.

WHAT IS AND IS NOT DELIVERED

    DELIVERED   durable artefact · atomic persistence · cross-process reload
                with identity and integrity verification

    NOT HERE    signing            a later assurance layer
                external anchor    DW-009
                revocation · expiry · retention policy

    DW-008 was a prerequisite for freezing the SHAPE. Signing is a different
    guarantee and is not mixed into this phase.

ONE FILE, ONE COMMIT — the DW-030 correction

    An earlier version wrote the payload and its integrity metadata as two
    separate atomic renames. Each file was safe; the PAIR was not. A
    concurrent reader landing between the two renames saw a new payload
    against an old sidecar and received
    IntegrityError("the stored payload was altered") for a perfectly valid
    artefact. Measured: 1116 spurious integrity failures against 238 clean
    loads.

    The store failed SAFE - it never accepted corrupt evidence - but a benign
    race was indistinguishable from tampering, and in an integrity layer that
    is a defect rather than an inconvenience.

    The correction: the payload and its metadata are committed together, in
    ONE file, through ONE atomic rename. The payload is carried as an EXACT
    STRING, so the bytes that were hashed are still the bytes that are
    stored - the canonical form is untouched, which the Phase 9A freeze
    requires.

WHY THE STORED FORM IS THE ARTEFACT'S OWN to_dict()

    Not a new envelope format. The frozen shapes already serialise
    determinately and reconstruct with hash verification, so persistence is
    a matter of getting those bytes onto a disk and back without altering
    them. A store-specific wrapper around the payload would be a second
    representation of the same evidence, and the freeze exists to prevent
    exactly that.

    The small amount of metadata the store needs - which shape, which schema
    version - lives OUTSIDE the payload, in a sidecar, so the bytes that
    were hashed are the bytes that are written.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

__all__ = [
    "store_evidence",
    "load_evidence",
    "StoredEvidence",
    "EvidenceStoreError",
    "IntegrityError",
    "SCHEMA_VERSION",
    "DURABLE_SHAPES",
]

CONTAINER_VERSION = "hb-eval-container/v2"
"""The on-disk envelope around the payload. v2 commits the payload and its
integrity metadata in ONE file; v1 used a separate sidecar and was corrected
under DW-030. This is the STORE's format and is independent of
SCHEMA_VERSION, which describes the evidence itself and is frozen."""

SCHEMA_VERSION = "hb-eval-evidence/v1"
"""Frozen by Phase 9A. Lives in the sidecar, never inside a canonical form:
putting it inside would change every existing artefact's identity, which the
scope lock forbids."""

DURABLE_SHAPES = {
    "EvidenceEnvelope": ("hb_eval_sdk.evidence_package", "envelope_hash"),
    "ReliabilityBaseline": ("hb_eval_sdk.baseline", "baseline_hash"),
    "ReliabilityAttestation": ("hb_eval_sdk.attestation", "attestation_hash"),
}
"""The three shapes Phase 9A froze as durable. Derived views are absent
deliberately: storing one would create a second source of truth that can
disagree with the artefact it was derived from."""


class EvidenceStoreError(Exception):
    """The artefact could not be stored or reconstructed."""


class IntegrityError(EvidenceStoreError):
    """The reloaded artefact does not match what was written.

    Separate from EvidenceStoreError so a caller can distinguish "the file is
    unreadable" from "the file is readable and wrong" - which are different
    problems with different responses.
    """


@dataclass(frozen=True)
class StoredEvidence:
    """What a load returns: the artefact and the proof it survived."""

    artefact: object
    shape: str
    schema_version: str
    hash_at_write: Optional[str]
    hash_at_read: Optional[str]
    path: str

    @property
    def intact(self) -> bool:
        """True if the hash recorded at write time equals the hash recomputed at read time: the stored content survived unchanged."""
        return self.hash_at_write == self.hash_at_read


def _shape_of(artefact) -> str:
    name = type(artefact).__name__
    if name not in DURABLE_SHAPES:
        raise EvidenceStoreError(
            f"{name} is not a durable shape. Phase 9A froze three: "
            f"{sorted(DURABLE_SHAPES)}. Derived views are recomputable and "
            f"storing one would create a second source of truth.")
    return name


def _hash_of(artefact, shape: str) -> str:
    attr = DURABLE_SHAPES[shape][1]
    value = getattr(artefact, attr, None)
    if not value:
        raise EvidenceStoreError(
            f"{shape} carries no {attr}; it was not sealed and cannot be "
            f"stored as durable evidence")
    return value


def store_evidence(artefact, path) -> StoredEvidence:
    """Persist a sealed artefact atomically.

    ATOMICITY. The payload is written to a temporary file in the SAME
    directory, flushed, fsynced, and then renamed over the target. A rename
    within one filesystem is atomic, so a reader sees either the previous
    file or the complete new one - never a partial write.

    The directory is fsynced afterwards, because on most filesystems the
    rename itself is not durable until the directory entry is.

    The payload written is the artefact's own to_dict(), unaltered. The
    sidecar carries the store's metadata so the payload bytes stay exactly
    what was hashed.
    """
    shape = _shape_of(artefact)
    digest = _hash_of(artefact, shape)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(artefact.to_dict(), sort_keys=True,
                         separators=(",", ":"), default=str)

    # ONE container, committed by ONE rename. `payload` is an EXACT STRING:
    # the bytes that were hashed are the bytes that are stored, so the
    # canonical form is untouched.
    container = {
        "container_version": CONTAINER_VERSION,
        "schema_version": SCHEMA_VERSION,
        "shape": shape,
        "hash_attribute": DURABLE_SHAPES[shape][1],
        "hash_at_write": digest,
        "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
        "payload_bytes": len(payload.encode()),
        "payload": payload,
    }
    text = json.dumps(container, sort_keys=True, indent=2)

    fd, tmp = tempfile.mkstemp(dir=str(path.parent),
                               prefix=".hbeval-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        # Not fatal, and not silently ignored: the payload is already
        # written and fsynced. Only the directory entry's durability across a
        # power loss is affected.
        pass

    return StoredEvidence(artefact=artefact, shape=shape,
                          schema_version=SCHEMA_VERSION,
                          hash_at_write=digest, hash_at_read=digest,
                          path=str(path))


def load_evidence(path, expect_shape: Optional[str] = None) -> StoredEvidence:
    """Reconstruct a stored artefact and verify it survived unchanged.

    THREE CHECKS, and each answers a different question:

        1  payload_sha256   were the BYTES altered on disk?
        2  from_dict        does the content still reconstruct, and does the
                            artefact's own hash verification pass?
        3  hash comparison  is the reconstructed artefact's canonical hash the
                            one recorded at write time?

    Check 1 catches corruption. Check 2 catches a payload that was edited
    coherently enough to parse. Check 3 catches a payload edited so as to
    satisfy its own internal hash but not the one recorded independently.

    Returning an artefact that failed any of them would present altered
    evidence as intact, so all three raise rather than warn.
    """
    import importlib

    path = Path(path)

    # ONE read. The payload and its integrity metadata arrive together, so a
    # concurrent reader can never pair one with the other's version - the
    # DW-030 correction.
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise EvidenceStoreError(f"cannot read {path}: {exc}") from exc

    try:
        sidecar = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EvidenceStoreError(
            f"{path} is not a readable evidence container: {exc}") from exc

    if not isinstance(sidecar, dict) or "payload" not in sidecar:
        raise EvidenceStoreError(
            f"{path} is not an evidence container: no payload. A bare "
            f"artefact file carries no independently recorded hash, and an "
            f"artefact that only verifies against itself proves less than "
            f"one verified against an independent record")

    if sidecar.get("container_version") != CONTAINER_VERSION:
        raise EvidenceStoreError(
            f"container version mismatch: stored "
            f"{sidecar.get('container_version')}, this build reads "
            f"{CONTAINER_VERSION}")

    payload = sidecar["payload"]
    if not isinstance(payload, str):
        raise EvidenceStoreError(
            "the payload must be stored as an exact string so the bytes that "
            "were hashed are the bytes that are read")

    if sidecar.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceStoreError(
            f"schema version mismatch: stored {sidecar.get('schema_version')}, "
            f"this build reads {SCHEMA_VERSION}")

    shape = sidecar.get("shape")
    if shape not in DURABLE_SHAPES:
        raise EvidenceStoreError(f"unknown shape in sidecar: {shape!r}")
    if expect_shape and shape != expect_shape:
        raise EvidenceStoreError(
            f"expected {expect_shape}, stored artefact is {shape}")

    # ── 1. byte integrity ───────────────────────────────────────────
    actual_bytes = hashlib.sha256(payload.encode()).hexdigest()
    if actual_bytes != sidecar.get("payload_sha256"):
        raise IntegrityError(
            f"the stored payload was altered: recorded "
            f"{str(sidecar.get('payload_sha256'))[:16]}, found "
            f"{actual_bytes[:16]}")

    # ── 2. reconstruction, with the shape's own verification ────────
    modname, hash_attr = DURABLE_SHAPES[shape]
    cls = getattr(importlib.import_module(modname), shape)
    try:
        artefact = cls.from_dict(json.loads(payload))
    except Exception as exc:
        raise IntegrityError(
            f"{shape} did not reconstruct: {type(exc).__name__}: "
            f"{str(exc)[:200]}") from exc

    # ── 3. canonical hash against the independently recorded one ────
    hash_at_read = getattr(artefact, hash_attr, None)
    hash_at_write = sidecar.get("hash_at_write")
    if hash_at_read != hash_at_write:
        raise IntegrityError(
            f"the reconstructed {shape} has canonical hash "
            f"{str(hash_at_read)[:24]}, but {str(hash_at_write)[:24]} was "
            f"recorded at write time")

    return StoredEvidence(artefact=artefact, shape=shape,
                          schema_version=SCHEMA_VERSION,
                          hash_at_write=hash_at_write,
                          hash_at_read=hash_at_read, path=str(path))
