"""
HB-Eval SDK — response data models.

The Metrics model now exposes ALL FIVE metrics from the paper — PEI, IRS,
FRR, TI, CSI — not just two. Any metric may be None when it is genuinely
undefined (IRS without faults, TI without a judge call, CSI without enough
history). A None is preserved as None and never silently coerced to 0.0,
because in a reliability system "we could not measure this" and "this scored
zero" are completely different statements (Protocol §7).
"""

from pydantic import BaseModel
from typing import Optional
from enum import Enum


class Verdict(str, Enum):
    """The reliability verdict returned by the Gateway.

    SAFE and UNSAFE are the two verdicts a run with enough evidence can earn. INSUFFICIENT_DATA means the
    evidence cannot support either: one or more metrics (typically FRR, IRS and TI) were unmeasured, most
    often because no fault occurred, so there is nothing to recover from and nothing to score. It is
    deliberately not SAFE, and it is the normal answer for an agent evaluated without fault injection.
    A response with no verdict is treated as UNSAFE; an unrecognised value is an error, never a pass.
    """
    SAFE = "SAFE"
    UNSAFE = "UNSAFE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class Metrics(BaseModel):
    """
    The five reliability metrics. Each is Optional because each can be
    legitimately undefined for a given run:
      - pei: Planning Efficiency Index (always computable)
      - irs: Intentional Recovery Score (None when no fault episodes)
      - frr: Failure Resilience Rate (1.0 when no fault episodes)
      - ti:  Traceability Index (None when no judge call was made)
      - csi: Consistency Stability Index (None without sufficient history)
    """
    pei: Optional[float] = None
    irs: Optional[float] = None
    frr: Optional[float] = None
    ti: Optional[float] = None
    csi: Optional[float] = None


class EvaluationResult(BaseModel):
    """The full result of an evaluation, mirroring the Gateway response (Protocol §7)."""
    verdict: Verdict
    metrics: Metrics
    tier: Optional[int] = None
    certified: Optional[bool] = False
    safe_halt: Optional[bool] = False
    memory_hit: Optional[bool] = False
    run_id: Optional[str] = None
    reason: Optional[str] = None
    note: Optional[str] = None
    # Diagnostic guidance: explains WHY the verdict was reached and, when not
    # certified, exactly which metric blocked it and how to improve. Available
    # to every plan, including free — knowledge and mentorship are not gated.
    guidance: Optional[dict] = None
    # Why a verdict or tier is what it is. Present on every Gateway response; absent fields stay None.
    qualified: Optional[bool] = None
    tier_status: Optional[str] = None
    tier_provisional: Optional[bool] = None
    unmeasured_metrics: list = []


class MemoryMatch(BaseModel):
    """A single semantic memory match returned by the EDM retrieval endpoint."""
    id: str
    trajectory_summary: str
    pei_score: Optional[float] = None
    irs_score: Optional[float] = None
    similarity: Optional[float] = None
