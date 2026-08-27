"""
hb_eval_sdk.mcp_server
========================
Model Context Protocol (MCP) server for HB-Eval.

This exposes HB-Eval's reliability capabilities as MCP tools, so any
MCP-capable client (Claude Desktop, Claude.ai custom connectors, Cursor,
or any agent that speaks MCP) can measure agentic reliability *without
writing integration code*. A user simply asks their assistant to evaluate
an agent, and the assistant discovers and calls these tools directly.

ARCHITECTURE — why this file is thin by design
-----------------------------------------------
MCP is an ACCESS LAYER, not a re-implementation. Every tool here delegates
to the HB-Eval SDK (HBEvalClient), which in turn calls the Gateway's REST
API, which runs the real evaluation core: the fault-injection battery, the
five metrics, EDM memory, and HCI-EDM explanations. Nothing about the
scoring, the plan-gating, or the paid/free distinction is duplicated or
bypassed here — the core remains the single source of truth. This server
only translates an assistant's natural-language intent into an authentic
SDK call and formats the result for the model.

Because the value (verified evaluation, qualification credential) lives in
the core and is gated there by plan, these tools are safe to expose to
everyone: a free-plan key calling `evaluate_agent_reliability` gets the
full local battery and guidance; the verified path and the formal
qualification credential remain paid, enforced by the Gateway, exactly as
they are through the SDK and the website. The door is open to all; what lies
beyond it still respects the plan.

TRANSPORT
---------
Built on FastMCP, which supports both stdio (local subprocess — used by
Claude Desktop today) and Streamable HTTP (remote server — the enterprise
path used by Stripe/PayPal-class deployments). This file runs stdio by
default; the same tool definitions serve the remote transport later with
no change to tool logic, only the run call and an OAuth layer in front.

CREDENTIALS
-----------
The server reads the user's HB-Eval credentials from environment variables
(never hard-coded, never logged):
    HBEVAL_API_KEY, HBEVAL_AES_KEY, HBEVAL_SIGNING_SECRET
Optional:
    HBEVAL_GATEWAY_URL  (defaults to the production gateway)

Requires: pip install hb-eval-sdk[mcp]   (installs mcp>=1.2)
Run:      python -m hb_eval_sdk.mcp_server
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "The MCP server requires the 'mcp' package. Install with:\n"
        "    pip install hb-eval-sdk[mcp]"
    ) from exc

from .client import HBEvalClient
from .exceptions import HBEvalError


# ── Server instance ─────────────────────────────────────────────────────────
mcp = FastMCP("hb-eval")


# ── Credential loading (fail-closed, never logged) ──────────────────────────
def _load_client() -> HBEvalClient:
    """Construct an HBEvalClient from environment variables.

    Fail-closed: if any credential is missing, raise a clear error rather
    than silently proceeding. Credentials are never written to logs or tool
    output — only a boolean 'configured' status is ever surfaced.
    """
    api_key = os.environ.get("HBEVAL_API_KEY", "")
    aes_key = os.environ.get("HBEVAL_AES_KEY", "")
    signing_secret = os.environ.get("HBEVAL_SIGNING_SECRET", "")
    gateway_url = os.environ.get("HBEVAL_GATEWAY_URL", "").strip()

    missing = [name for name, val in (
        ("HBEVAL_API_KEY", api_key),
        ("HBEVAL_AES_KEY", aes_key),
        ("HBEVAL_SIGNING_SECRET", signing_secret),
    ) if not val]
    if missing:
        raise HBEvalError(
            "Missing HB-Eval credentials in environment: "
            + ", ".join(missing)
            + ". Set them before starting the MCP server."
        )

    kwargs: dict[str, Any] = {
        "api_key": api_key,
        "aes_key": aes_key,
        "signing_secret": signing_secret,
    }
    if gateway_url:
        kwargs["gateway_url"] = gateway_url
    return HBEvalClient(**kwargs)


def _err(message: str) -> str:
    """Uniform, safe error payload. Never leaks credentials or stack traces."""
    return json.dumps({"ok": False, "error": message}, ensure_ascii=False, indent=2)


def _ok(data: Any) -> str:
    return json.dumps({"ok": True, "result": data}, ensure_ascii=False, indent=2)


# ── Tool 1: evaluate an agent's reliability (the core) ──────────────────────
@mcp.tool(
    name="evaluate_agent_reliability",
    description=(
        "Run HB-Eval's fault-injection battery against an agent and return its "
        "operational-reliability verdict and the five metrics (PEI, FRR, IRS, "
        "TI, CSI). Use this when a user wants to know whether an agent behaves "
        "reliably under failure conditions, not just whether it completes tasks. "
        "This runs the VERIFIED path (the platform calls the agent's public HTTPS "
        "endpoint), which requires a paid plan and explicit user consent. For a "
        "free local run, the user should use the SDK's evaluate_with_battery on "
        "their own machine."
    ),
)
def evaluate_agent_reliability(
    agent_url: str,
    task_description: str,
    consent: bool = False,
    n_scenarios: int = 30,
    required_in_response: Optional[list[str]] = None,
) -> str:
    """Evaluate a deployed agent via the verified path.

    Args:
        agent_url: the agent's public HTTPS endpoint the platform will call.
        task_description: the base task the agent should perform; the battery
            perturbs this with injected faults.
        consent: MUST be true — the platform makes outbound calls to the
            agent endpoint across the battery. Fail-closed without it.
        n_scenarios: battery size (higher = tighter estimate), capped server-side.
        required_in_response: optional keywords the correct response should contain.
    """
    if not consent:
        return _err(
            "Consent required. The verified path calls your agent endpoint across "
            "multiple fault scenarios. Re-run with consent=true to proceed."
        )
    if not agent_url.lower().startswith("https://"):
        return _err("agent_url must be a public HTTPS endpoint.")
    try:
        client = _load_client()
        base_task = {"question": task_description}
        if required_in_response:
            base_task["required_in_response"] = required_in_response
        report = client.request_verified_evaluation(
            agent_url=agent_url,
            base_task=base_task,
            consent=True,
            n_scenarios=n_scenarios,
            required_in_response=required_in_response,
        )
        return _ok(report)
    except HBEvalError as exc:
        return _err(str(exc))
    except Exception as exc:  # defensive: never leak internals
        return _err(f"Evaluation failed: {type(exc).__name__}")


# ── Tool 2: explain the five metrics ────────────────────────────────────────
@mcp.tool(
    name="get_reliability_metrics",
    description=(
        "Explain HB-Eval's five reliability metrics and what each measures. Use "
        "this when a user asks what PEI, FRR, IRS, TI, or CSI mean, how the "
        "verdict is decided, or how to interpret a reliability report. Returns "
        "definitions and the weakest-link rule; no credentials or network needed."
    ),
)
def get_reliability_metrics() -> str:
    """Return the metric definitions and aggregation rule (static reference)."""
    metrics = {
        "PEI": {
            "name": "Planning Efficiency Index",
            "measures": "Whether the agent's plan is coherent and economical "
                        "rather than wasteful or confused.",
        },
        "FRR": {
            "name": "Failure Resilience Rate",
            "measures": "Whether the agent keeps functioning when a fault is "
                        "injected, rather than collapsing.",
        },
        "IRS": {
            "name": "Intentional Recovery Score",
            "measures": "Whether the agent recovers deliberately when something "
                        "goes wrong. Defined only on fault-perturbed episodes, "
                        "since recovery is meaningless without something to "
                        "recover from.",
        },
        "TI": {
            "name": "Traceability Index",
            "measures": "Whether the agent's behaviour can be followed and "
                        "audited step by step.",
        },
        "CSI": {
            "name": "Consistency Stability Index",
            "measures": "Whether the agent behaves the same way across repeated "
                        "runs, or drifts. Reported as provisional until a full "
                        "window of runs is collected.",
        },
        "aggregation": {
            "rule": "Weakest-link",
            "meaning": "The reliability tier is governed by the worst required "
                       "metric, not the average. An agent cannot average its way "
                       "to trustworthiness by excelling on some metrics while "
                       "failing a critical one.",
        },
        "tiers": {
            "Tier 1": "Supervised — meets thresholds for operation under direct "
                      "human supervision.",
            "Tier 2": "Production-with-oversight — qualifies for production use "
                      "with humans monitoring.",
            "Tier 3": "Autonomous — meets the most demanding thresholds across "
                      "all five metrics simultaneously.",
            "note": "These are an internal performance qualification, not an "
                    "accredited safety certification.",
        },
    }
    return _ok(metrics)


# ── Tool 3: retrieve qualified memory (EDM) ─────────────────────────────────
@mcp.tool(
    name="retrieve_qualified_memory",
    description=(
        "Retrieve reliability-qualified past episodes from HB-Eval's "
        "Evaluation-Driven Memory (EDM) for a given context. EDM only stores "
        "episodes that cleared the reliability bar, so results are trustworthy "
        "precedent rather than a flat log of everything that happened. Use this "
        "when a user wants to know how an agent handled similar situations "
        "reliably in the past."
    ),
)
def retrieve_qualified_memory(context: str, top_k: int = 5) -> str:
    """Retrieve up to top_k qualified episodes matching the context.

    Free plans are capped server-side (the Gateway enforces the cap); this
    tool passes the request through unchanged and does not itself decide the
    limit, so the plan boundary stays in one place.
    """
    if not context.strip():
        return _err("A non-empty context is required to retrieve memory.")
    try:
        client = _load_client()
        memories = client.retrieve_memory(context=context, top_k=top_k)
        return _ok({"retrieved": len(memories), "episodes": memories})
    except HBEvalError as exc:
        return _err(str(exc))
    except Exception as exc:
        return _err(f"Memory retrieval failed: {type(exc).__name__}")


# ── Tool 4: explain a verdict (HCI-EDM) ─────────────────────────────────────
@mcp.tool(
    name="explain_verdict",
    description=(
        "Produce a performance-grounded explanation of a reliability verdict via "
        "HB-Eval's HCI-EDM layer. The explanation is grounded in specific, "
        "qualified recorded episodes (citing their real metrics), NOT a "
        "generated rationalisation. If no sufficiently similar qualified "
        "precedent exists, it explicitly defers to human review rather than "
        "fabricating a reason. Use this when a user asks WHY an agent received a "
        "given reliability verdict."
    ),
)
def explain_verdict(plan_summary: str) -> str:
    """Explain a verdict, grounded in qualified stored episodes.

    Delegates to the Gateway's /api/v1/explain (HCI-EDM). The mandatory
    uncertainty response — deferring to a human when no qualified precedent
    exists — is produced by the core, not synthesised here.
    """
    if not plan_summary.strip():
        return _err("A non-empty plan_summary is required to explain a verdict.")
    try:
        client = _load_client()
        result = client.explain(plan_summary)
        return _ok(result)
    except HBEvalError as exc:
        return _err(str(exc))
    except Exception as exc:
        return _err(f"Explanation failed: {type(exc).__name__}")


# ── Tool 5: compare reliability of two agents/versions ──────────────────────
@mcp.tool(
    name="compare_reliability",
    description=(
        "Compare the operational reliability of two agents, or two versions of "
        "the same agent (e.g. before vs after a change). Runs the verified "
        "battery against each and returns a side-by-side of the five metrics and "
        "verdicts, plus which is more reliable and on which dimensions. Use this "
        "for regression checks and continuous improvement. Verified path — paid "
        "plan and consent required."
    ),
)
def compare_reliability(
    agent_a_url: str,
    agent_b_url: str,
    task_description: str,
    consent: bool = False,
    n_scenarios: int = 30,
) -> str:
    """Evaluate two agents on the same task and contrast their reliability."""
    if not consent:
        return _err(
            "Consent required. Comparison calls both agent endpoints across the "
            "battery. Re-run with consent=true to proceed."
        )
    for label, url in (("agent_a_url", agent_a_url), ("agent_b_url", agent_b_url)):
        if not url.lower().startswith("https://"):
            return _err(f"{label} must be a public HTTPS endpoint.")
    try:
        client = _load_client()
        base_task = {"question": task_description}
        report_a = client.request_verified_evaluation(
            agent_url=agent_a_url, base_task=base_task, consent=True, n_scenarios=n_scenarios,
        )
        report_b = client.request_verified_evaluation(
            agent_url=agent_b_url, base_task=base_task, consent=True, n_scenarios=n_scenarios,
        )

        def _metrics(r: dict) -> dict:
            return r.get("aggregate_metrics") or r.get("metrics") or {}

        ma, mb = _metrics(report_a), _metrics(report_b)
        per_metric = {}
        for key in ("pei", "frr", "irs", "ti", "csi"):
            va, vb = ma.get(key), mb.get(key)
            if va is None or vb is None:
                per_metric[key] = "insufficient data"
            elif va > vb:
                per_metric[key] = "agent_a"
            elif vb > va:
                per_metric[key] = "agent_b"
            else:
                per_metric[key] = "tie"
        comparison = {
            "agent_a": {"verdict": report_a.get("verdict"), "metrics": ma},
            "agent_b": {"verdict": report_b.get("verdict"), "metrics": mb},
            "stronger_per_metric": per_metric,
        }
        return _ok(comparison)
    except HBEvalError as exc:
        return _err(str(exc))
    except Exception as exc:
        return _err(f"Comparison failed: {type(exc).__name__}")


# ── Tool 6: reliability trend over time ─────────────────────────────────────
@mcp.tool(
    name="get_reliability_trend",
    description=(
        "Return the reliability trend for an agent over its evaluation history "
        "(is it improving or degrading over time?). Uses the agent's accumulated "
        "evaluation records. Use this when a user wants to track whether an "
        "agent's reliability is trending up or down across repeated evaluations, "
        "rather than a single point-in-time verdict."
    ),
)
def get_reliability_trend(agent_id: str, window: int = 20) -> str:
    """Summarise the reliability trend from stored evaluation history.

    Delegates to the SDK if a trend/history method is available; otherwise
    returns a clear message rather than fabricating a trend.
    """
    if not agent_id.strip():
        return _err("A non-empty agent_id is required.")
    try:
        client = _load_client()
        trend = client.get_trend(agent_id=agent_id, window=window)
        return _ok(trend)
    except HBEvalError as exc:
        return _err(str(exc))
    except Exception as exc:
        return _err(f"Trend retrieval failed: {type(exc).__name__}")


# ── Entry point ─────────────────────────────────────────────────────────────
def main() -> None:
    """Run the MCP server over stdio (local transport).

    For the remote (enterprise) transport, the same `mcp` instance is served
    via Streamable HTTP behind an OAuth 2.1 layer — no tool changes required.
    That deployment is handled separately at the Gateway/edge, not here.
    """
    mcp.run()


if __name__ == "__main__":
    main()