"""
test_otel_derive.py — correctness and measured agreement for span derivation.

TWO KINDS OF TEST HERE
-----------------------
The first are ordinary unit tests: given this span, does the rule fire?

The second is the part that matters scientifically. Auto-derivation replaces a
human's judgement with a rule, and a rule that is merely plausible is not good
enough for a metric anyone will cite. So AGREEMENT is measured against
scenarios whose ground truth is known by construction, and reported as
Cohen's kappa rather than asserted.

WHAT THIS DOES AND DOES NOT ESTABLISH
--------------------------------------
These scenarios are built with their answer known, so this measures whether the
derivation implements its own specification faithfully. That is necessary and it
is not sufficient: it cannot tell us whether the specification matches what a
human expert would call an intentional recovery on a real trace.

That second study needs real traces and human annotation, and the harness at
the bottom is written so those can be dropped in unchanged. Stating the
distinction here rather than letting the kappa figure speak for more than it
measures.
"""
import math

import pytest

from otel_derive import (
    SpanRecord, StepDeriver, derivation_notes,
    CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW,
)


# ── Builders ────────────────────────────────────────────────────────────────
def tool(name="search", *, failed=False, args="{}", how="status", ms=10.0):
    """A tool-call span. `how` selects which failure signal is used, because
    instrumentations differ and we must catch all of them."""
    attrs = {"gen_ai.operation.name": "execute_tool",
             "gen_ai.tool.name": name,
             "gen_ai.tool.call.arguments": args}
    status, events = "UNSET", []
    if failed:
        if how == "status":
            status = "ERROR"
        elif how == "exception":
            events = [{"name": "exception",
                       "attributes": {"exception.type": "TimeoutError"}}]
        elif how == "error_type":
            attrs["error.type"] = "TimeoutError"
    return SpanRecord(name=f"execute_tool {name}", attributes=attrs,
                      status_code=status, events=events, duration_ms=ms)


def chat(model="gpt-4o"):
    return SpanRecord(name=f"chat {model}",
                      attributes={"gen_ai.operation.name": "chat"})


def agent(name="my-agent"):
    return SpanRecord(name=f"invoke_agent {name}",
                      attributes={"gen_ai.operation.name": "invoke_agent",
                                  "gen_ai.agent.name": name},
                      is_root=True)


def run(spans):
    """Feed spans through a fresh deriver, returning only produced steps."""
    d = StepDeriver()
    return [s for s in (d.consume(sp) for sp in spans) if s is not None]


# ── Classification ──────────────────────────────────────────────────────────
def test_only_tool_calls_become_steps():
    """Model and agent spans are context, not actions.

    A step is something the agent DID, with consequences. Counting model turns
    as steps would inflate the denominator of every rate metric."""
    steps = run([agent(), chat(), tool(), chat(), tool()])
    assert len(steps) == 2


def test_operation_falls_back_to_span_name():
    """Some instrumentations set the span name but not the attribute.

    Requiring the attribute would silently drop those frameworks entirely."""
    s = SpanRecord(name="execute_tool lookup", attributes={})
    assert s.is_tool_call()
    assert s.tool_name() == "lookup"


def test_all_three_failure_signals_detected():
    """Instrumentations vary in how they report failure; missing any one of
    these loses real faults."""
    for how in ("status", "exception", "error_type"):
        steps = run([tool(failed=True, how=how)])
        assert steps[0].had_fault is True, how
        assert steps[0].success is False, how


def test_clean_span_is_not_a_fault():
    steps = run([tool()])
    assert steps[0].had_fault is False and steps[0].success is True


# ── Confidence, stated honestly ─────────────────────────────────────────────
def test_observed_fault_is_high_confidence():
    steps = run([tool(failed=True)])
    assert steps[0].confidence["had_fault"] == CONFIDENCE_HIGH


def test_absence_of_error_is_low_confidence():
    """The most important assertion in this file.

    An agent can fail while returning success — a tool answering HTTP 200 with
    stale data throws nothing and leaves a clean span. So "no error observed"
    must never be reported with the same confidence as "error observed", or FRR
    silently becomes a claim the telemetry cannot support."""
    steps = run([tool()])
    assert steps[0].confidence["had_fault"] == CONFIDENCE_LOW
    assert steps[0].confidence["success"] == CONFIDENCE_LOW


def test_intent_is_never_claimed_as_observed():
    """No span carries intent, so IRS can never be HIGH confidence."""
    steps = run([tool(failed=True), chat(), tool()])
    assert steps[-1].confidence["recovered_intentionally"] in (
        CONFIDENCE_MEDIUM, CONFIDENCE_LOW
    )


# ── Recovery: the inference that carries the most weight ────────────────────
def test_no_preceding_failure_means_recovery_not_applicable():
    """None, not False. There was nothing to recover from, and IRS is
    undefined on such steps rather than scored zero."""
    steps = run([tool()])
    assert steps[0].recovered_intentionally is None


def test_identical_retry_is_not_intentional():
    """Same tool, same arguments, no model call in between: the agent repeated
    itself without reasoning about the failure."""
    steps = run([
        tool("search", failed=True, args='{"q":"x"}'),
        tool("search", args='{"q":"x"}'),
    ])
    assert steps[1].recovered_intentionally is False


def test_model_call_between_failure_and_retry_is_intentional():
    """The agent went back to the model before retrying: it reconsidered."""
    steps = run([
        tool("search", failed=True, args='{"q":"x"}'),
        chat(),
        tool("search", args='{"q":"x"}'),
    ])
    assert steps[1].recovered_intentionally is True
    assert steps[1].replanned is True


def test_changed_arguments_counts_as_a_changed_approach():
    steps = run([
        tool("search", failed=True, args='{"q":"x"}'),
        tool("search", args='{"q":"y"}'),
    ])
    assert steps[1].recovered_intentionally is True
    # Reported at lower confidence: the approach changed, but no reasoning step
    # was observed to explain it.
    assert steps[1].confidence["recovered_intentionally"] == CONFIDENCE_LOW


def test_different_tool_counts_as_a_changed_approach():
    steps = run([
        tool("search", failed=True),
        tool("fallback_search"),
    ])
    assert steps[1].recovered_intentionally is True


def test_consecutive_failures_are_not_recoveries():
    """Still failing is not recovering, in either direction."""
    steps = run([tool("s", failed=True), tool("s", failed=True)])
    assert all(s.recovered_intentionally is None for s in steps)
    assert all(s.had_fault for s in steps)


def test_recovery_state_resets_after_success():
    """A failure two steps ago must not colour an unrelated later step."""
    steps = run([
        tool("a", failed=True), chat(), tool("a"),   # recovered
        tool("b"),                                    # unrelated
    ])
    assert steps[1].recovered_intentionally is True
    assert steps[2].recovered_intentionally is None


# ── Fault episodes ──────────────────────────────────────────────────────────
def test_recovery_attempt_is_inside_the_fault_episode():
    """The step that recovers must read as "a fault was present, and it
    completed" — that is the only shape FRR can score as a survival.

    Marking only the throwing span would leave FRR seeing failures and never a
    recovery, and IRS with nothing to judge. Verified end to end: both metrics
    came back None until episodes were tracked."""
    steps = run([tool("api", failed=True), chat(), tool("api")])
    assert steps[0].had_fault is True and steps[0].success is False
    assert steps[1].had_fault is True, "recovery step must be inside the episode"
    assert steps[1].success is True, "and must read as having completed"
    assert steps[1].recovered_intentionally is True


def test_clean_step_after_recovery_leaves_the_episode():
    steps = run([tool("a", failed=True), chat(), tool("a"), tool("b")])
    assert steps[2].had_fault is False, "episode should have closed"


def test_episode_membership_is_lower_confidence_than_an_observed_error():
    """A step marked faulted because the episode is open is an inference, and
    must not borrow the confidence of a directly observed error."""
    steps = run([tool("api", failed=True), chat(), tool("api")])
    assert steps[0].confidence["had_fault"] == CONFIDENCE_HIGH
    assert steps[1].confidence["had_fault"] == CONFIDENCE_MEDIUM


def test_failed_retry_is_not_counted_as_a_recovery():
    """A retry that also failed did not recover, so it is not judged.

    This keeps IRS answering "of the recoveries that happened, how many were
    deliberate" rather than silently scoring failed attempts. The cost of the
    blind retry still lands elsewhere: it is another fault in the episode, so
    FRR falls, and the weakest-link rule sees it there."""
    steps = run([
        tool("api", failed=True, args='{"i":1}'),
        tool("api", failed=True, args='{"i":1}'),   # blind retry, also failed
        chat(),
        tool("fallback"),                            # deliberate recovery
    ])
    assert steps[1].recovered_intentionally is None
    assert steps[2].recovered_intentionally is True
    faulted = [s for s in steps if s.had_fault]
    assert len(faulted) == 3, "all three belong to the one episode"
    assert sum(1 for s in faulted if s.success) == 1, "one survival"


# ── Traceability ────────────────────────────────────────────────────────────
def test_model_call_before_tool_makes_it_traceable():
    steps = run([chat(), tool()])
    assert steps[0].traceable is True


def test_unexplained_tool_call_is_not_traceable():
    """A tool call with no model turn in front of it has no recorded reasoning
    behind the decision, which is precisely what TI measures."""
    steps = run([tool()])
    assert steps[0].traceable is False


def test_traceability_does_not_carry_over():
    steps = run([chat(), tool(), tool()])
    assert steps[0].traceable is True
    assert steps[1].traceable is False


# ── Disclosure ──────────────────────────────────────────────────────────────
def test_derivation_notes_disclose_the_silent_failure_limit():
    notes = derivation_notes()
    joined = " ".join(notes["known_limits"]).lower()
    assert "silent" in joined or "returning success" in joined
    assert notes["method"] == "otel_genai_v1"


def test_notes_separate_observed_from_inferred():
    notes = derivation_notes()
    assert notes["observed_directly"] and notes["inferred"]
    inferred = " ".join(notes["inferred"])
    assert "recovered_intentionally" in inferred
    assert "traceable" in inferred


# ── Measured agreement ──────────────────────────────────────────────────────
# Scenarios with their answer known by construction. Each is a realistic
# fragment of agent behaviour paired with the label a specification-following
# annotator should assign for recovered_intentionally — the hardest and least
# directly observable of the derived fields.
GROUND_TRUTH = [
    # (description, spans, expected recovered_intentionally on the last step)
    ("clean call, nothing to recover from",
     [tool("get")], None),
    ("blind identical retry",
     [tool("api", failed=True, args='{"id":1}'), tool("api", args='{"id":1}')],
     False),
    ("retry after consulting the model",
     [tool("api", failed=True, args='{"id":1}'), chat(), tool("api", args='{"id":1}')],
     True),
    ("switched to a fallback tool",
     [tool("primary", failed=True), tool("secondary")], True),
    ("adjusted the arguments",
     [tool("api", failed=True, args='{"page":1}'), tool("api", args='{"page":2}')],
     True),
    ("two failures in a row",
     [tool("api", failed=True), tool("api", failed=True)], None),
    ("recovered, then an unrelated call",
     [tool("a", failed=True), chat(), tool("a"), tool("b")], None),
    ("model call first, then a clean call",
     [chat(), tool("x")], None),
    ("failure reported via exception rather than status",
     [tool("api", failed=True, how="exception"), chat(), tool("api")], True),
    ("failure reported via error.type",
     [tool("api", failed=True, how="error_type"), tool("api")], False),
    ("long chain ending in a deliberate recovery",
     [chat(), tool("a"), tool("b", failed=True), chat(), tool("c")], True),
    ("long chain ending in a blind retry",
     [chat(), tool("a"), tool("b", failed=True, args='{"k":1}'),
      tool("b", args='{"k":1}')], False),
]


def _cohens_kappa(pairs) -> float:
    """Cohen's kappa over (derived, expected) label pairs.

    Raw agreement flatters any classifier on a skewed label set; kappa corrects
    for the agreement expected by chance, which is why it is the figure the
    paper should report rather than a percentage.
    """
    labels = sorted({str(a) for a, _ in pairs} | {str(b) for _, b in pairs})
    n = len(pairs)
    observed = sum(1 for a, b in pairs if str(a) == str(b)) / n
    expected = 0.0
    for lab in labels:
        p_a = sum(1 for a, _ in pairs if str(a) == lab) / n
        p_b = sum(1 for _, b in pairs if str(b) == lab) / n
        expected += p_a * p_b
    if math.isclose(expected, 1.0):
        return 1.0
    return (observed - expected) / (1.0 - expected)


def test_agreement_against_known_ground_truth():
    """Report agreement rather than assume it."""
    pairs = []
    failures = []
    for desc, spans, expected in GROUND_TRUTH:
        steps = run(spans)
        got = steps[-1].recovered_intentionally if steps else None
        pairs.append((got, expected))
        if got != expected:
            failures.append(f"{desc}: derived {got!r}, expected {expected!r}")

    kappa = _cohens_kappa(pairs)
    raw = sum(1 for a, b in pairs if a == b) / len(pairs)
    print(f"\n  scenarios: {len(pairs)}")
    print(f"  raw agreement: {raw:.3f}")
    print(f"  Cohen's kappa: {kappa:.3f}")
    for f in failures:
        print(f"  MISMATCH {f}")

    # The derivation must implement its own specification exactly. Anything
    # less means the rules and the code disagree, which is a bug, not noise.
    assert not failures, "; ".join(failures)
    assert kappa == pytest.approx(1.0)


def test_ground_truth_covers_every_label():
    """A kappa computed over one label is meaningless."""
    labels = {expected for _, _, expected in GROUND_TRUTH}
    assert labels == {True, False, None}


def test_harness_accepts_externally_annotated_traces():
    """The same function must serve the real study.

    Human-annotated traces slot into this signature unchanged, so the study
    that establishes expert agreement needs no new machinery — only data."""
    external = [(True, True), (False, False), (None, None), (True, False)]
    k = _cohens_kappa(external)
    assert -1.0 <= k <= 1.0
    # Deliberately imperfect input yields imperfect kappa, confirming the
    # measure is not hard-coded to agree.
    assert k < 1.0