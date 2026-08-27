"""
hb_eval_sdk.demo
=================
The five-minute experience.

    pip install hb-eval-sdk
    hb-eval demo

No account, no keys, no configuration. It runs a scripted agent whose
reliability degrades, shows the metrics moving step by step, and stops the run
when resilience stays below its floor.

WHY THIS RUNS OFFLINE BY DEFAULT
---------------------------------
A reviewer will not create an account to evaluate a paper. A developer deciding
whether this is worth their afternoon will not either. Both will run one
command.

Everything the demo shows — metric computation, threshold detection, Safe Halt,
the overhead measurement — happens inside the SDK on the caller's machine
anyway. The platform adds streaming, storage and the dashboard, and none of
those are needed to demonstrate that the measurement works.

So the demo asks for nothing. With credentials in the environment it also
streams to the dashboard and prints the link, which is the same code path a
real agent uses. Nothing is simulated differently for the demo's benefit.

WHAT IT DELIBERATELY DOES NOT DO
---------------------------------
No LLM is called. The demo is about the measurement layer, and involving a real
model would add an API key, a cost, network latency, and a source of variation
that makes the run unreproducible. The scripted agent's behaviour is fixed, so
two people running this see the same numbers and can compare notes.

That is stated in the output rather than glossed over. A demo that quietly
implies more than it does is a bad first impression from a project whose entire
argument is about not overclaiming.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Optional

# ── Presentation ────────────────────────────────────────────────────────────
# Colour is disabled when the output is piped, when NO_COLOR is set (the
# widely-honoured convention), or on a terminal that will not render it.
def _supports_colour() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    return os.environ.get("TERM", "") not in ("", "dumb")


_C = _supports_colour()


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _C else text


def dim(t):   return _c(t, "2")
def bold(t):  return _c(t, "1")
def red(t):   return _c(t, "31")
def green(t): return _c(t, "32")
def amber(t): return _c(t, "33")
def blue(t):  return _c(t, "34")


def rule(width: int = 66) -> str:
    return dim("─" * width)


def fmt_metric(value: Optional[float], digits: int = 2) -> str:
    """Undefined renders as a dash, never as zero.

    The rule that governs every layer of this system, and the demo is the first
    place most people will see it. A metric shown as 0.00 when it was never
    measured teaches the wrong thing in the first thirty seconds.
    """
    return "  —  " if value is None else f"{value:.{digits}f}"


# ── The scripted agent ──────────────────────────────────────────────────────
# A customer-support agent handling a delayed shipment. Fixed, so two people
# running this get identical numbers.
#
# The shape is deliberate: healthy at first, then an external dependency starts
# failing, the agent retries blindly, and only then does it re-plan. That is the
# behaviour reliability measurement exists to catch — a run that a pass/fail
# benchmark would score as "succeeded eventually".
SCRIPT = [
    # (action, success, had_fault, recovered_intentionally, traceable, replanned, note)
    ("plan the response",        True,  False, None,  True,  False, "reads the ticket and forms a plan"),
    ("look up the order",        True,  False, None,  True,  False, "internal database, responds normally"),
    ("check carrier status",     True,  False, None,  True,  False, "carrier API healthy"),
    ("fetch tracking detail",    False, True,  False, False, False, "carrier API times out"),
    ("retry tracking detail",    False, True,  False, False, False, "identical retry — no reasoning between"),
    ("retry tracking detail",    False, True,  False, False, False, "and again"),
    ("re-plan approach",         True,  True,  True,  True,  True,  "consults its own reasoning, changes tack"),
    ("use cached tracking",      True,  False, None,  True,  False, "falls back to cached data"),
    ("draft the reply",          True,  False, None,  True,  False, "composes a response"),
    ("send the reply",           True,  False, None,  True,  False, "delivers it"),
]

STEP_DELAY_DEFAULT = 0.55


def run_demo(*, connect: bool = False, fast: bool = False,
             no_halt: bool = False) -> int:
    try:
        from .client import HBEvalClient
        from .monitoring import MonitorSession, DEFAULT_THRESHOLDS
        from . import __version__
    except ImportError as exc:
        print(f"hb-eval: could not load the SDK ({exc})", file=sys.stderr)
        return 1

    delay = 0.0 if fast else STEP_DELAY_DEFAULT

    # ── Connection ──
    # Credentials are optional. Their absence changes where results go, never
    # how they are computed.
    creds = {k: os.environ.get(k, "") for k in
             ("HBEVAL_API_KEY", "HBEVAL_AES_KEY", "HBEVAL_SIGNING_SECRET")}
    have_creds = all(creds.values())
    streaming = connect and have_creds

    print()
    print(bold(f"  HB-Eval demo") + dim(f"  ·  SDK {__version__}"))
    print(rule())
    if streaming:
        print(dim("  Streaming to the dashboard. Metrics computed locally, as always."))
    elif connect:
        print(amber("  --connect was given but credentials are not set."))
        print(dim("  Running offline. Set HBEVAL_API_KEY, HBEVAL_AES_KEY and"))
        print(dim("  HBEVAL_SIGNING_SECRET to stream this run to the dashboard."))
    else:
        print(dim("  Running offline — no account, no keys, nothing sent."))
        print(dim("  Add --connect to stream this run to the dashboard."))
    print()
    print(dim("  A support agent handling a delayed shipment. Scripted, so the"))
    print(dim("  numbers are the same for everyone. No model is called."))
    print()

    # ── Client ──
    if streaming:
        client = HBEvalClient(api_key=creds["HBEVAL_API_KEY"],
                              aes_key=creds["HBEVAL_AES_KEY"],
                              signing_secret=creds["HBEVAL_SIGNING_SECRET"])
    else:
        # Offline: a client whose transport is never used, so the demo runs
        # the real MonitorSession rather than a stand-in. Same code path, same
        # arithmetic — only the destination differs.
        class _OfflineClient:
            gateway_url = "offline"
            def _send_monitoring_batch(self, batch):  # pragma: no cover
                raise ConnectionError("offline")
            def _send_monitoring_summary(self, summary):
                return None
        client = _OfflineClient()

    breaches: list[tuple[str, float, float, int]] = []
    announced: set = set()      # metrics whose first crossing has been shown
    still_below: set = set()    # metrics that stayed under after crossing

    def on_breach(metric, value, floor, session):
        breaches.append((metric, value, floor, len(session.steps)))

    halt_policy = None if no_halt else {
        "metric": "frr", "below": 0.5, "for_steps": 3,
    }

    session = MonitorSession(
        client, agent_id="demo-support-agent",
        on_threshold_breach=on_breach,
        halt_policy=halt_policy,
        send_summary=streaming,
        stream=streaming,
        session_metadata={"source": "hb-eval demo"},
    )

    # ── Header ──
    print(f"  {'#':>2}  {'step':<24}{'PEI':>7}{'FRR':>7}{'IRS':>7}{'TI':>7}")
    print(rule())

    halted_at = None
    with session as m:
        for i, (action, ok, fault, recovered, traceable, replanned, note) in enumerate(SCRIPT, 1):
            m.record_step(action=action, success=ok, had_fault=fault,
                          recovered_intentionally=recovered,
                          traceable=traceable, replanned=replanned)
            lm = m.live_metrics

            marker = red("✗") if not ok else (blue("↻") if replanned else green("✓"))
            row = (f"  {i:>2}{marker} {action:<24}"
                   f"{fmt_metric(lm['pei']):>7}{fmt_metric(lm['frr']):>7}"
                   f"{fmt_metric(lm['irs']):>7}{fmt_metric(lm['ti']):>7}")
            print(row)
            print(f"      {dim(note)}")

            # A breach is recorded on EVERY step a metric stays under its
            # floor, which is correct for the data and unreadable on screen —
            # seven identical warnings teach nothing after the first.
            #
            # So the crossing is announced once, prominently, at the step it
            # happens. Continued breach is shown as a quiet trailing note,
            # because "still below" is genuinely different information from
            # "just fell below" and an operator needs both.
            for metric, value, floor, step_no in breaches:
                if step_no != i:
                    continue
                if metric not in announced:
                    announced.add(metric)
                    print(f"      {amber(f'⚠ {metric.upper()} crossed below {floor} — now {value:.2f}')}")
                else:
                    still_below.add(metric)

            if m.should_halt:
                halted_at = i
                print()
                print(f"  {red('■ SAFE HALT')}  {m.halt_reason}")
                print(f"  {dim('The agent loop checked should_halt and stopped. Nothing was')}")
                print(f"  {dim('killed mid-step — the halt is cooperative, so no action was')}")
                print(f"  {dim('left half-applied.')}")
                break

            time.sleep(delay)

    # ── Result ──
    summary = session.summary
    lm = session.live_metrics
    overhead = session.overhead_stats

    print()
    print(rule())
    print(bold("  Result"))
    print()
    for key, label, floor in (("pei", "Planning Efficiency", DEFAULT_THRESHOLDS["pei"]),
                              ("frr", "Failure Resilience", DEFAULT_THRESHOLDS["frr"]),
                              ("irs", "Deliberate Handling", DEFAULT_THRESHOLDS["irs"]),
                              ("ti",  "Traceability", DEFAULT_THRESHOLDS["ti"]),
                              ("csi", "Consistency Stability", None)):
        v = lm.get(key)
        if v is None:
            state = dim("undefined")
        elif floor is not None and v < floor:
            state = red(f"below {floor}")
        else:
            state = green("ok")
        digits = 2 if key == "ti" else 2
        print(f"    {key.upper():<4} {fmt_metric(v, digits)}  {label:<22} {state}")

    print()
    print(f"    {dim('CSI needs repeated runs to exist at all, so it is undefined')}")
    print(f"    {dim('here — reported as undefined, never scored as zero. An')}")
    print(f"    {dim('unmeasured dimension is not a failed one.')}")

    print()
    print(f"    Steps            {summary['step_count']}")
    print(f"    Breaches         {summary['breach_count']}")
    if halted_at:
        print(f"    Halted at step   {halted_at} of {len(SCRIPT)}")
    if overhead["samples"]:
        print(f"    Monitoring cost  p50 {overhead['p50_ms']:.4f} ms  ·  "
              f"p99 {overhead['p99_ms']:.4f} ms per step")

    # ── What it means ──
    print()
    print(rule())
    print(bold("  What just happened"))
    print()
    if halted_at:
        # The run was cut short, so the narrative must describe THAT, not the
        # ending it never reached. Explaining a recovery the viewer did not see
        # would be the demo telling them something the screen contradicts.
        print(f"    The carrier API failed at step 4. The agent answered with")
        print(f"    three identical retries — same call, same arguments, no")
        print(f"    reasoning in between — and resilience sat at zero throughout.")
        print()
        print(f"    At step {halted_at} the policy had seen enough and stopped the run.")
        print()
        print(f"    That is the trade the operator makes: stop a degrading agent")
        print(f"    rather than bet on it recovering. This one would have")
        print(f"    recovered, partially — run with {bold('--no-halt')} to watch it")
        print(f"    finish the task while every metric stays below its floor.")
    else:
        print("    The agent finished its task. A pass/fail benchmark would call")
        print("    that a success — it sent the reply.")
        print()
        print("    Under fault injection it reads differently. Resilience collapsed")
        print("    when the carrier API failed, and the first three responses were")
        print("    identical retries with no reasoning between them. Recovery")
        print("    became deliberate only once the agent re-planned, and even then")
        print("    FRR and IRS never climbed back above their floors.")
        print()
        print("    The task completed. The behaviour did not recover.")
    print()
    print("    That gap — between completing the task and behaving reliably")
    print("    while completing it — is what these five metrics measure.")

    if streaming:
        print()
        print(rule())
        print(f"  {bold('Open the dashboard')}")
        print(f"    https://hbeval.com/dashboard/monitoring")
        print()
        print(dim("    Click this session for its timeline, replay and — since it"))
        print(dim("    halted — the audit record showing which policy stopped it."))
    else:
        print()
        print(rule())
        print(f"  {bold('Next')}")
        print(f"    {dim('Stream a run to the dashboard:')}")
        print(f"      hb-eval demo --connect      {dim('(needs a free account)')}")
        print(f"    {dim('Monitor your own agent:')}")
        print(f"      https://hbeval.com/docs#monitoring")

    print()
    return 0


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hb-eval",
        description="HB-Eval — operational reliability for agentic AI.",
    )
    sub = parser.add_subparsers(dest="command")

    demo = sub.add_parser(
        "demo", help="Run a scripted agent and watch its reliability degrade.",
    )
    demo.add_argument("--connect", action="store_true",
                      help="Stream to the dashboard (needs HBEVAL_* credentials).")
    demo.add_argument("--fast", action="store_true",
                      help="No pauses between steps.")
    demo.add_argument("--no-halt", action="store_true",
                      help="Disable Safe Halt and let the run finish.")

    # The CI gate lives in its own module and registers its own arguments, so
    # this file does not have to know about them.
    try:
        from .gate import add_parser as _add_gate
        _add_gate(sub)
    except ImportError:
        pass

    sub.add_parser("version", help="Print the SDK version.")

    args = parser.parse_args(argv)

    if args.command == "version":
        from . import __version__
        print(__version__)
        return 0
    if args.command == "gate":
        from .gate import run_gate
        return run_gate(args)
    if args.command == "demo":
        try:
            return run_demo(connect=args.connect, fast=args.fast,
                            no_halt=args.no_halt)
        except KeyboardInterrupt:
            print("\n  stopped.\n")
            return 130

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())