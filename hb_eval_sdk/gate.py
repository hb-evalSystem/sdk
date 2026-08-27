"""
hb_eval_sdk.gate
=================
Reliability as a merge gate.

    hb-eval gate --agent myapp.agent:run --task task.json

Runs the fault-injection battery against an agent, compares the result to a
threshold or a stored baseline, writes a report, and exits non-zero when the
gate fails.

THE PROBLEM THIS DESIGN IS SHAPED AROUND
-----------------------------------------
A flaky gate is worse than no gate.

Scenario selection is seeded and therefore reproducible, but the agent's own
responses are not: the same code measured twice gives slightly different
numbers. An absolute threshold of FRR >= 0.80 against a true value hovering at
0.81 will fail perhaps one run in five, for no reason anyone can act on.

The first time that blocks a correct pull request, someone opens an argument.
The second time, someone adds `continue-on-error: true`. By the third the gate
is decoration, and a gate people route around is worse than none because it
looks like coverage.

So two decisions follow from that, and everything else is detail.

**Warn by default.** The gate reports and exits 0 until explicitly told to
enforce. Teams tune thresholds against their own variance first and turn on
blocking when they trust the numbers — which is also the only honest order,
since nobody knows their agent's variance before measuring it.

**Baselines beat thresholds.** Comparing against the last known-good run
catches what actually matters — this change made reliability worse — and is far
more robust to noise, because both measurements carry the same noise. An
absolute floor asks "is this good enough?", which is a product question with no
universal answer. A baseline asks "did this get worse?", which is the question a
pull request is actually about.

EXIT CODES
----------
    0  passed, or warn mode
    1  gate failed
    2  configuration or usage error

The distinction between 1 and 2 matters: a missing credential is not a
reliability failure, and reporting it as one sends people looking for a bug in
their agent.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from typing import Any, Callable, Optional

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_CONFIG_ERROR = 2

# Metric ceilings, for rendering. TI is 0–5; the rest are 0–1.
METRIC_MAX = {"pei": 1.0, "frr": 1.0, "irs": 1.0, "ti": 5.0, "csi": 1.0}
METRIC_NAMES = {
    "pei": "Planning Efficiency",
    "frr": "Failure Resilience",
    "irs": "Deliberate Handling",
    "ti": "Traceability",
    "csi": "Consistency Stability",
}

# Default tolerance for baseline comparison. Below this, a drop is measurement
# noise rather than a regression — chosen to be roughly the run-to-run spread
# observed on a stable agent, and overridable because that spread is a property
# of the agent, not of this tool.
DEFAULT_MAX_REGRESSION = 0.05


def _err(msg: str) -> None:
    print(f"hb-eval gate: {msg}", file=sys.stderr)


def load_agent(spec: str) -> Callable:
    """Import an agent callable from 'module.path:attribute'.

    The same shape gunicorn and celery use, because a CI-only convention is one
    more thing to look up.
    """
    if ":" not in spec:
        raise ValueError(
            f"--agent must be 'module.path:callable', got {spec!r}"
        )
    module_path, _, attr = spec.partition(":")

    # The repository root is where CI checks code out, and it is not on
    # sys.path by default.
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)

    module = importlib.import_module(module_path)
    fn = getattr(module, attr, None)
    if fn is None:
        raise ValueError(f"{module_path!r} has no attribute {attr!r}")
    if not callable(fn):
        raise ValueError(f"{spec!r} is not callable")
    return fn


def load_task(path: str) -> dict:
    """Load the base task. Validated here so a typo fails before the battery
    runs rather than after every scenario has been paid for."""
    with open(path, encoding="utf-8") as fh:
        task = json.load(fh)
    if not isinstance(task, dict):
        raise ValueError("task file must contain a JSON object")
    for key in ("system", "question"):
        if not task.get(key):
            raise ValueError(f"task file is missing {key!r}")
    return task


# ── Evaluation ──────────────────────────────────────────────────────────────
def evaluate(agent: Callable, task: dict, *, n_scenarios: int,
             seed: Optional[int]) -> dict:
    from .client import HBEvalClient

    creds = {k: os.environ.get(k, "") for k in
             ("HBEVAL_API_KEY", "HBEVAL_AES_KEY", "HBEVAL_SIGNING_SECRET")}
    missing = [k for k, v in creds.items() if not v]
    if missing:
        raise RuntimeError(
            "missing credentials: " + ", ".join(missing) +
            "\nAdd them as repository secrets and pass them through in the "
            "workflow's env block."
        )

    client = HBEvalClient(
        api_key=creds["HBEVAL_API_KEY"],
        aes_key=creds["HBEVAL_AES_KEY"],
        signing_secret=creds["HBEVAL_SIGNING_SECRET"],
    )
    return client.evaluate_with_battery(
        task, agent, n_scenarios=n_scenarios, seed=seed,
    )


# ── Judgement ───────────────────────────────────────────────────────────────
def check(report: dict, *, floors: dict, baseline: Optional[dict],
          max_regression: float) -> tuple[bool, list[str], list[str]]:
    """Decide whether the gate passes. Returns (passed, failures, notes)."""
    failures: list[str] = []
    notes: list[str] = []

    metrics = report.get("metrics") or report.get("aggregate_metrics") or {}
    verdict = report.get("verdict")

    # INSUFFICIENT_DATA from a battery means the battery did not run properly,
    # not that the agent is unreliable. Failing loudly with the real cause
    # beats passing quietly on a measurement that never happened.
    if verdict == "INSUFFICIENT_DATA":
        unmeasured = report.get("unmeasured_metrics") or []
        failures.append(
            "the run produced no usable measurement"
            + (f" ({', '.join(m.upper() for m in unmeasured)} unmeasured)"
               if unmeasured else "")
            + " — check the agent returns text for every scenario"
        )
        return False, failures, notes

    if verdict == "UNSAFE":
        failures.append("verdict is UNSAFE")

    # ── Absolute floors ──
    for metric, floor in (floors or {}).items():
        value = metrics.get(metric)
        if value is None:
            # Undefined is not failing. CSI needs repeated runs and is
            # undefined in a single battery by construction, so treating it as
            # a failure would block every pull request forever.
            notes.append(f"{metric.upper()} undefined — floor not applied")
            continue
        if value < floor:
            failures.append(
                f"{metric.upper()} {value:.3f} is below the floor {floor}")

    # ── Baseline comparison ──
    if baseline:
        base_metrics = (baseline.get("metrics")
                        or baseline.get("aggregate_metrics") or {})
        for metric, value in metrics.items():
            prev = base_metrics.get(metric)
            if value is None or prev is None:
                continue
            drop = prev - value
            if drop > max_regression:
                failures.append(
                    f"{metric.upper()} fell {drop:.3f} from the baseline "
                    f"({prev:.3f} → {value:.3f}), beyond the {max_regression} "
                    f"tolerance")
            elif drop > 0:
                notes.append(
                    f"{metric.upper()} {prev:.3f} → {value:.3f} "
                    f"(within tolerance)")

    return not failures, failures, notes


# ── Reporting ───────────────────────────────────────────────────────────────
def render_markdown(report: dict, passed: bool, failures: list, notes: list,
                    *, floors: dict, baseline: Optional[dict],
                    enforce: bool) -> str:
    metrics = report.get("metrics") or report.get("aggregate_metrics") or {}
    base_metrics = ((baseline or {}).get("metrics")
                    or (baseline or {}).get("aggregate_metrics") or {})

    icon = "✅" if passed else ("❌" if enforce else "⚠️")
    heading = ("passed" if passed
               else ("failed" if enforce else "failed (warn mode)"))

    lines = [f"## {icon} HB-Eval reliability gate — {heading}", ""]

    tier = report.get("tier")
    lines.append(
        f"**Verdict** `{report.get('verdict', '—')}`"
        f"{' · **Tier** ' + str(tier) if tier else ''}"
        f"{' *(provisional)*' if report.get('tier_provisional') else ''}"
    )
    lines.append("")

    header = "| Metric | Value | Floor |"
    divider = "|---|---|---|"
    if base_metrics:
        header += " Baseline | Change |"
        divider += "---|---|"
    lines += [header, divider]

    for key in ("pei", "frr", "irs", "ti", "csi"):
        if key not in metrics and key not in base_metrics:
            continue
        value = metrics.get(key)
        shown = "—" if value is None else f"{value:.3f}"
        floor = floors.get(key)
        floor_shown = "—" if floor is None else f"{floor}"
        row = f"| **{key.upper()}** {METRIC_NAMES.get(key, '')} | {shown} | {floor_shown} |"
        if base_metrics:
            prev = base_metrics.get(key)
            prev_shown = "—" if prev is None else f"{prev:.3f}"
            if value is None or prev is None:
                change = "—"
            else:
                delta = value - prev
                arrow = "▲" if delta > 0.001 else ("▼" if delta < -0.001 else "—")
                change = f"{arrow} {delta:+.3f}"
            row += f" {prev_shown} | {change} |"
        lines.append(row)

    lines.append("")

    if failures:
        lines.append("### Blocking" if enforce else "### Would block")
        lines += [f"- {f}" for f in failures]
        lines.append("")
    if notes:
        lines.append("<details><summary>Notes</summary>")
        lines.append("")
        lines += [f"- {n}" for n in notes]
        lines += ["", "</details>", ""]

    if not enforce:
        lines.append(
            "> Running in **warn mode** — this never blocks. Tune the floors "
            "against your own run-to-run variance first, then add "
            "`enforce: true` once the numbers are trustworthy."
        )

    run_id = report.get("run_id")
    if run_id:
        lines.append("")
        lines.append(f"[Open this run](https://hbeval.com/dashboard) · `{run_id}`")

    return "\n".join(lines)


def emit_github(markdown: str, failures: list, enforce: bool) -> None:
    """Write the GitHub Actions job summary and annotations.

    Both are no-ops outside Actions, so the same command works locally.
    """
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write(markdown + "\n")
        except OSError as exc:
            _err(f"could not write the job summary: {exc}")

    if os.environ.get("GITHUB_ACTIONS"):
        level = "error" if enforce else "warning"
        for f in failures:
            # Annotations surface on the pull request itself, where the person
            # who needs them is already looking.
            print(f"::{level} title=HB-Eval reliability gate::{f}")


# ── Command ─────────────────────────────────────────────────────────────────
def run_gate(args: argparse.Namespace) -> int:
    try:
        agent = load_agent(args.agent)
        task = load_task(args.task)
    except Exception as exc:
        _err(str(exc))
        return EXIT_CONFIG_ERROR

    baseline = None
    if args.baseline:
        try:
            with open(args.baseline, encoding="utf-8") as fh:
                baseline = json.load(fh)
        except FileNotFoundError:
            # A first run has no baseline. That is not an error — it is the
            # first run, and failing it would make baselines impossible to
            # adopt.
            print(f"hb-eval gate: no baseline at {args.baseline} — "
                  f"this run becomes the baseline.")
        except Exception as exc:
            _err(f"could not read the baseline: {exc}")
            return EXIT_CONFIG_ERROR

    floors = {}
    for metric in ("pei", "frr", "irs", "ti", "csi"):
        value = getattr(args, f"min_{metric}", None)
        if value is not None:
            floors[metric] = value

    try:
        report = evaluate(agent, task,
                          n_scenarios=args.scenarios, seed=args.seed)
    except RuntimeError as exc:
        _err(str(exc))
        return EXIT_CONFIG_ERROR
    except Exception as exc:
        _err(f"the battery failed to run: {type(exc).__name__}: {exc}")
        return EXIT_CONFIG_ERROR

    passed, failures, notes = check(
        report, floors=floors, baseline=baseline,
        max_regression=args.max_regression,
    )

    markdown = render_markdown(
        report, passed, failures, notes,
        floors=floors, baseline=baseline, enforce=args.enforce,
    )
    print(markdown)
    emit_github(markdown, failures, args.enforce)

    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
        except OSError as exc:
            _err(f"could not write the report: {exc}")

    # The baseline is only updated on a PASS. Writing a failing run as the new
    # baseline would ratchet the standard downwards every time something broke,
    # which is the opposite of what a baseline is for.
    if args.update_baseline and passed:
        try:
            with open(args.update_baseline, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
            print(f"\nBaseline updated: {args.update_baseline}")
        except OSError as exc:
            _err(f"could not update the baseline: {exc}")

    if passed:
        return EXIT_OK
    if args.enforce:
        return EXIT_GATE_FAILED
    print("\nWarn mode — not blocking. Add --enforce to make this fail.")
    return EXIT_OK


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "gate",
        help="Run the reliability battery as a CI gate.",
        description=(
            "Runs the fault-injection battery and fails the build when "
            "reliability falls below a floor or regresses from a baseline. "
            "Warns without blocking unless --enforce is given."
        ),
    )
    p.add_argument("--agent", required=True,
                   help="Agent callable as 'module.path:attribute'.")
    p.add_argument("--task", required=True,
                   help="JSON file with 'system' and 'question'.")
    p.add_argument("--scenarios", type=int, default=18,
                   help="Battery size, 6–60. Default 18.")
    p.add_argument("--seed", type=int, default=42,
                   help="Scenario-selection seed. Fixed by default so two runs "
                        "face the same faults.")

    p.add_argument("--enforce", action="store_true",
                   help="Exit non-zero when the gate fails. Off by default.")

    for metric in ("pei", "frr", "irs", "ti", "csi"):
        p.add_argument(f"--min-{metric}", type=float, default=None,
                       help=f"Minimum acceptable {metric.upper()}.")

    p.add_argument("--baseline",
                   help="JSON report to compare against. Missing file is fine "
                        "on a first run.")
    p.add_argument("--max-regression", type=float,
                   default=DEFAULT_MAX_REGRESSION,
                   help=f"Largest tolerated drop from the baseline. "
                        f"Default {DEFAULT_MAX_REGRESSION}.")
    p.add_argument("--update-baseline",
                   help="Write this run as the new baseline, but only if it "
                        "passed.")
    p.add_argument("--report", help="Write the full JSON report here.")