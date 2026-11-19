"""
hb_eval_sdk.gate
=================
Reliability as a merge gate.

    hb-eval gate --agent myapp.agent:run --task task.json

Runs the fault-injection battery against an agent, compares the result to a
threshold or a stored baseline, writes a report, and exits non-zero when the
gate fails.

CLI SCOPE - decided by the Phase 9B CLI integration audit
---------------------------------------------------------
The CLI covers the DECISION SURFACE only:

    Baseline A + Baseline B  ->  Decision  ->  exit code

Attestation (Phase 7), context assessment (Phase 8) and durable evidence
(Phase 9B) are LIBRARY APIs, reached from Python, not from this command:

    from hb_eval_sdk.attestation import attest
    from hb_eval_sdk.context_assessment import assess_context
    from hb_eval_sdk.evidence_store import store_evidence, load_evidence

That is a deliberate boundary, not an omission. It is recorded here because
a CLI that printed "attestation generated" or "evidence persisted" without
having done either would be the same class of defect as DW-028: a claim
travelling without the work that would justify it. This command makes no
such claim, and must not begin to.

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

# PHASE 6. Two NEW codes for two states the legacy gate could not express.
# 0, 1 and 2 keep their published meanings exactly: redefining CONFIG_ERROR
# to carry INCONCLUSIVE would make an unusable comparison indistinguishable
# from a broken invocation, which is the confusion this phase exists to end.
#
# A pipeline branching on zero-vs-nonzero is unaffected. A pipeline that
# distinguishes 1 from 2 now sees 3 and 4 as new values, never as a changed
# meaning of an old one.
EXIT_INCONCLUSIVE = 3
EXIT_RECERTIFICATION_REQUIRED = 4

# Metric ceilings, for rendering. TI is 0–5; the rest are 0–1.
METRIC_MAX = {"pei": 1.0, "frr": 1.0, "irs": 1.0, "ti": 5.0, "csi": 1.0}
METRIC_NAMES = {
    "pei": "Planning Efficiency",
    "frr": "Failure Resilience",
    "irs": "Intentional Recovery Score",
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
    """Run the fault-injection battery against `agent` through the Gateway and return the report. Reads HBEVAL_API_KEY, HBEVAL_AES_KEY and HBEVAL_SIGNING_SECRET from the environment, and raises RuntimeError naming (never revealing) any that are missing."""
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
        if not _is_number(value):
            # Fail closed. A floor silently skipped because the value was malformed would turn a
            # broken response into a pass; an exception here would exit 1, which is the code for
            # "the gate failed", disguising a crash as a verdict.
            failures.append(f"{metric.upper()} came back as {value!r}, not a number — cannot apply the floor {floor}")
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
            if not _is_number(value) or not _is_number(prev):
                continue
            # PHASE 6 (DW-028). The raw subtraction that stood here produced
            # a reliability FAIL from two dictionaries of numbers, with no
            # comparability, no metric_version, no provenance, no battery
            # identity and no baseline eligibility checked. Two reports from
            # different batteries, slots, scoring versions or judges compared
            # cleanly and blocked a pull request.
            #
            # A reliability verdict is now the decision layer's to make.
            # This module translates a verdict; it never makes one.
            #
            # What remains is an OBSERVATION, not a decision: the numbers are
            # reported so a reader can see them, and nothing follows from
            # them. "regression" is deliberately absent - a difference is not
            # a regression without attribution conditions this system cannot
            # meet (DW-015), and direction is not derivable without metric
            # polarity (DW-027).
            difference = value - prev
            if difference != 0:
                notes.append(
                    f"{metric.upper()} {prev:.3f} → {value:.3f} "
                    f"(observed difference {difference:+.3f}; not a "
                    f"reliability verdict)")

    return not failures, failures, notes


# ── Reporting ───────────────────────────────────────────────────────────────
def render_markdown(report: dict, passed: bool, failures: list, notes: list,
                    *, floors: dict, baseline: Optional[dict],
                    enforce: bool) -> str:
    """Render the gate result as GitHub-flavoured Markdown for the job summary: the outcome, the metrics against their floors and baseline, and, in warn mode, what would have blocked."""
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


def _escape_command_data(text) -> str:
    """Escape text for the data part of a GitHub Actions workflow command (`::level::data`)."""
    return (str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A"))


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == value  # NaN != NaN


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
            # who needs them is already looking. The text is escaped per the workflow-command
            # rules: an unescaped newline would let a failure message start a command of its own.
            print(f"::{level} title=HB-Eval reliability gate::{_escape_command_data(f)}")


# ── Command ─────────────────────────────────────────────────────────────────
def run_reliability_decision(args):
    """The authoritative path: load artefacts, call the 5D chain, translate.

    ORCHESTRATION ONLY. This function loads files and renders a result. Every
    scientific step belongs to a module that already owns it:

        ReliabilityBaseline.from_dict   5D-B   reconstructs and verifies
        diff_baselines                  5D-D   which itself calls 5D-C
        decide                          6      evaluates the declared policy

    What this function must never do, and does not: subtract two metric
    values, reconstruct comparability, infer metric polarity, invent a
    threshold.

    Returns (exit_code, decision), or (exit_code, None) on a load error.
    """
    from .baseline import ReliabilityBaseline
    from .reliability_diff import diff_baselines
    from .reliability_decision import (decide, DecisionState, SLOPolicy,
                                       SLOCondition)

    def _load(path, what):
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            _err(f"could not read the {what} at {path}: {exc}")
            return None

    ref_raw = _load(args.reference_baseline, "reference baseline")
    cand_raw = _load(args.candidate_baseline, "candidate baseline")
    if ref_raw is None or cand_raw is None:
        return EXIT_CONFIG_ERROR, None

    # from_dict verifies the stored hash. A baseline that does not round-trip
    # is a configuration problem, not an inconclusive comparison: the input is
    # broken, and INCONCLUSIVE would blame the evidence instead.
    try:
        reference = ReliabilityBaseline.from_dict(ref_raw)
        candidate = ReliabilityBaseline.from_dict(cand_raw)
    except Exception as exc:
        _err(f"a baseline did not verify: {exc}")
        return EXIT_CONFIG_ERROR, None

    policy = None
    if args.slo_policy:
        raw = _load(args.slo_policy, "SLO policy")
        if raw is None:
            return EXIT_CONFIG_ERROR, None
        try:
            policy = SLOPolicy(
                policy_version=raw["policy_version"],
                policy_id=raw.get("policy_id"),
                conditions=tuple(
                    SLOCondition(
                        metric_name=c["metric_name"],
                        comparator=c["comparator"],
                        threshold=float(c["threshold"]),
                        applies_to=c.get("applies_to", "value_b"),
                        decision_eligible=c.get("decision_eligible", True))
                    for c in raw.get("conditions", [])))
        except (KeyError, TypeError, ValueError) as exc:
            _err(f"the SLO policy is malformed: {exc}")
            return EXIT_CONFIG_ERROR, None

    diff = diff_baselines(reference, candidate)
    decision = decide(diff, policy)

    print(f"\nReliability decision: {decision.state}")
    print(f"  comparability: {decision.comparability_state}")
    if decision.policy_version:
        print(f"  policy: {decision.policy_version}")
    for reason in decision.reasons:
        print(f"  - {reason}")
    for name in sorted(decision.per_metric):
        md = decision.per_metric[name]
        print(f"  {METRIC_NAMES.get(name, name.upper())}: {md.state}")
        for r in md.reasons:
            print(f"      {r}")

    # TRANSLATION, not decision. One-to-one, adding no judgement of its own.
    mapping = {
        DecisionState.PASS: EXIT_OK,
        DecisionState.FAIL: EXIT_GATE_FAILED,
        DecisionState.INCONCLUSIVE: EXIT_INCONCLUSIVE,
        DecisionState.RECERTIFICATION_REQUIRED:
            EXIT_RECERTIFICATION_REQUIRED,
    }
    code = mapping[decision.state]

    # --enforce keeps its published meaning: without it, nothing blocks.
    if code != EXIT_OK and not args.enforce:
        print("\nWarn mode — not blocking. Add --enforce to make this fail.")
        return EXIT_OK, decision

    return code, decision


def run_gate(args: argparse.Namespace) -> int:
    # ── PHASE 6 ROUTING ──────────────────────────────────────────────
    #
    # Two paths, chosen by which inputs were supplied, never by guessing:
    #
    #   --reference-baseline + --candidate-baseline
    #       the AUTHORITATIVE reliability decision path (Phase 6)
    #
    #   --baseline
    #       the LEGACY compatibility path. It reports observed differences
    #       and makes no reliability claim. Kept so existing pipelines keep
    #       working; not authoritative for anything.
    #
    # Supplying only one of the pair is a configuration error, not a silent
    # fallback to the legacy path: a caller who asked for the authoritative
    # decision must not be quietly given the legacy one instead.
    """Run the gate and return its exit code.

    0: passed, or failed in warn mode. 1: the gate failed under --enforce. 2: usage or configuration
    error (a missing credential is not a reliability failure). 3: the evidence was inconclusive.
    4: recertification is required. Routing is decided by which inputs were given, never guessed:
    two baselines select the authoritative decision path; an agent and a task select the live battery.
    """
    ref = getattr(args, "reference_baseline", None)
    cand = getattr(args, "candidate_baseline", None)
    if ref or cand:
        if not (ref and cand):
            _err("--reference-baseline and --candidate-baseline must be "
                 "supplied together; the CLI evaluation path produces no "
                 "evidence envelopes and cannot derive the missing one")
            return EXIT_CONFIG_ERROR
        code, _decision = run_reliability_decision(args)
        return code

    # Argparse no longer demands these (the authoritative path needs neither), so the
    # legacy path must: a missing one is a usage error (2), exactly as before.
    if not getattr(args, "agent", None) or not getattr(args, "task", None):
        _err("--agent and --task are required unless --reference-baseline and "
             "--candidate-baseline are given")
        return EXIT_CONFIG_ERROR

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
    """Register the `gate` subcommand and its options on an argparse subparsers object."""
    p = subparsers.add_parser(
        "gate",
        help="Run the reliability battery as a CI gate.",
        description=(
            "Runs the fault-injection battery and fails the build when "
            "reliability falls below a floor or regresses from a baseline. "
            "Warns without blocking unless --enforce is given."
        ),
    )
    p.add_argument("--agent", default=None,
                   help="Agent callable as 'module.path:attribute'. Required unless "
                        "--reference-baseline and --candidate-baseline are given.")
    p.add_argument("--task", default=None,
                   help="JSON file with 'system' and 'question'. Required unless "
                        "--reference-baseline and --candidate-baseline are given.")
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

    # ── PHASE 6: the authoritative reliability decision path ─────────
    #
    # NEW flags rather than a changed meaning for --baseline. Silently
    # repointing --baseline from a raw metric report to a ReliabilityBaseline
    # would break every pipeline that already passes one, and would blur the
    # legacy compatibility path into the authoritative one - which is exactly
    # the confusion Phase 6 exists to end.
    #
    # Both baselines must be supplied: gate.evaluate() runs a local battery
    # that produces no evidence envelopes, so the CLI cannot derive a
    # ReliabilityBaseline for the candidate on its own. That is a real
    # limitation of the CLI evaluation path, stated rather than worked around.
    p.add_argument("--reference-baseline", metavar="PATH",
                   help="Serialised ReliabilityBaseline to compare against. "
                        "Enables the authoritative decision path.")
    p.add_argument("--candidate-baseline", metavar="PATH",
                   help="Serialised ReliabilityBaseline for the candidate. "
                        "Required with --reference-baseline.")
    p.add_argument("--slo-policy", metavar="PATH",
                   help="Declared, versioned SLO policy. Without one no PASS "
                        "or FAIL is possible.")

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