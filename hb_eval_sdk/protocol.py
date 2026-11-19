"""
hb_eval_sdk.protocol — wire-protocol compatibility
===================================================
Two numbers are easy to confuse and must not be:

  PROTOCOL_VERSION            the WIRE protocol: which requests exist and how
                              they are signed and shaped. Additive endpoints
                              raise the minor; a change that breaks an old
                              peer raises the major.
  MEASUREMENT_PROTOCOL_VERSION the protocol the SCORES were produced under.
                              Passports and baselines are stamped with it, and
                              results under different values are not directly
                              comparable. It moves only when how a metric is
                              computed moves — never because a new endpoint
                              was added.

The Gateway used to advertise a single number for both. Raising it for a new
endpoint would have changed the measurement stamp on every new passport while
changing no measurement — a false claim of discontinuity. They are now two.

THE RULE (documented in config.py since 2.x, enforced here for the first time)
  major differs        incompatible     the peers do not share a protocol
  minor differs        warn             one side has endpoints the other lacks
  patch differs        compatible       never a protocol event
  peer did not say     unknown          older Gateways do not advertise; this
                                        is reported as unknown, not as ok
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Tuple

OK, WARN, INCOMPATIBLE, UNKNOWN = "ok", "warn", "incompatible", "unknown"


@dataclass(frozen=True)
class Compatibility:
    """The result of comparing two protocol versions: a level (ok, warn, incompatible or unknown), a message, and both versions."""
    level: str
    message: str
    sdk: str
    peer: Optional[str]

    @property
    def compatible(self) -> bool:
        """True for levels `ok` and `warn`. `unknown` is not compatible: not knowing is not agreeing."""
        return self.level in (OK, WARN)


def parse(version) -> Optional[Tuple[int, int, int]]:
    """'2.8.0' -> (2, 8, 0). Anything that is not exactly three integers -> None.
    Deliberately strict: a version string we cannot read must not be trusted
    into 'compatible'."""
    if not isinstance(version, str):
        return None
    parts = version.strip().split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return int(parts[0]), int(parts[1]), int(parts[2])


def compare(sdk_version: str, peer_version) -> Compatibility:
    """Compare the SDK's wire-protocol version with a peer's. Major differs: incompatible. Minor differs: warn. Patch differs: ok. A peer that sent nothing or something unreadable: unknown. Raises ValueError only if the SDK's own version is malformed."""
    mine = parse(sdk_version)
    if mine is None:
        raise ValueError(f"SDK protocol version is not major.minor.patch: {sdk_version!r}")
    if peer_version is None:
        return Compatibility(UNKNOWN, "peer did not advertise a protocol version "
                             "(an older Gateway); compatibility cannot be confirmed",
                             sdk_version, None)
    theirs = parse(peer_version)
    if theirs is None:
        return Compatibility(UNKNOWN, f"peer advertised an unreadable protocol version "
                             f"{peer_version!r}", sdk_version, str(peer_version))
    if mine[0] != theirs[0]:
        return Compatibility(INCOMPATIBLE, f"major protocol mismatch: SDK {sdk_version}, "
                             f"peer {peer_version}", sdk_version, peer_version)
    if mine[1] != theirs[1]:
        which = "newer" if theirs[1] > mine[1] else "older"
        return Compatibility(WARN, f"minor protocol mismatch: SDK {sdk_version}, peer "
                             f"{peer_version} ({which}); endpoints may be missing on one side",
                             sdk_version, peer_version)
    return Compatibility(OK, "protocol versions agree", sdk_version, peer_version)
