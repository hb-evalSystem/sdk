"""
hb_eval_sdk.crewai_integration
=================================
Adapter that lets a CrewAI Agent, Task, or full Crew be evaluated by
HB-Eval's fault-injection battery via evaluate_with_battery /
request_verified_evaluation.

CrewAI's execution model is task-centric rather than message-centric: you
run a Task (bound to an Agent) or a whole Crew, and get back a
CrewOutput/TaskOutput whose .raw attribute holds the text. This adapter's
job is to build a fresh Task from the battery's per-scenario
(system_prompt, question) on every call — important because CrewAI Agents
carry a persistent `backstory`/`goal` set at construction time, not a
per-call system prompt, so the fault-injected system prompt is folded into
the task description to ensure the fault condition actually reaches the
agent rather than being silently dropped.

Tested against crewai 1.15.x.
Requires: pip install hb-eval-sdk crewai

Usage
-----
    from hb_eval_sdk import HBEvalClient
    from hb_eval_sdk.crewai_integration import adapt_crewai_agent

    client = HBEvalClient(api_key=..., aes_key=..., signing_secret=...)
    my_agent = adapt_crewai_agent(my_crewai_agent)

    base_task = {
        "system": "You are a safety-critical incident-response agent.",
        "question": "A critical incident is detected. Provide your response plan.",
        "required_in_response": ["assess", "respond"],
    }
    report = client.evaluate_with_battery(base_task, my_agent, n_scenarios=18)
"""
from __future__ import annotations
from typing import Any, Callable, Optional


def adapt_crewai_agent(
    agent: Any,
    *,
    expected_output: str = "A complete, direct response to the request.",
) -> Callable[[str, str], str]:
    """Wrap a single CrewAI Agent as an HB-Eval agent_runner.

    A fresh Task is created per call so that each fault-injection scenario
    runs in isolation, with no memory or state carried over between
    scenarios (which would otherwise contaminate the reliability measurement
    by letting recovery from one scenario influence the next).

    Args:
        agent: a crewai.Agent instance.
        expected_output: CrewAI Tasks require an expected_output description;
            kept generic so it does not bias the agent toward any one
            battery scenario.

    Returns:
        A callable (system_prompt, question) -> str.
    """
    from crewai import Task, Crew

    def agent_runner(system_prompt: str, question: str) -> str:
        task = Task(
            description=f"{system_prompt}\n\nRequest: {question}",
            expected_output=expected_output,
            agent=agent,
        )
        # A single-agent, single-task crew is the minimal unit of execution
        # CrewAI supports; this does not change agent behaviour vs. running
        # it inside a larger crew, only the orchestration scope.
        crew = Crew(agents=[agent], tasks=[task], verbose=False)
        result = crew.kickoff()
        return _extract_text(result)

    return agent_runner


def adapt_crewai_crew(
    build_crew_fn: Callable[[str, str], Any],
) -> Callable[[str, str], str]:
    """Wrap a full multi-agent CrewAI Crew as an HB-Eval agent_runner.

    Unlike adapt_crewai_agent, a Crew's tasks/agents are typically wired
    together at construction time (task dependencies, process type), so
    there is no single generic way to inject a new task into an arbitrary
    existing Crew. Instead, you supply a factory function that builds and
    returns a fresh Crew for the given (system_prompt, question) — giving
    you full control over how the fault-injected prompt is threaded through
    your multi-agent pipeline.

    Args:
        build_crew_fn: callable(system_prompt, question) -> crewai.Crew,
            already configured with its tasks/agents for this input.

    Returns:
        A callable (system_prompt, question) -> str.

    Example:
        def build_crew(system_prompt, question):
            researcher = Agent(role="Researcher", goal=system_prompt, ...)
            writer = Agent(role="Writer", ...)
            research_task = Task(description=question, agent=researcher, ...)
            write_task = Task(description="Summarise findings", agent=writer, ...)
            return Crew(agents=[researcher, writer], tasks=[research_task, write_task])

        my_agent = adapt_crewai_crew(build_crew)
    """
    def agent_runner(system_prompt: str, question: str) -> str:
        crew = build_crew_fn(system_prompt, question)
        result = crew.kickoff()
        return _extract_text(result)

    return agent_runner


def _extract_text(result: Any) -> str:
    """CrewOutput (crewai >= 0.28) exposes .raw; older versions returned a
    plain string directly from kickoff(). Handle both without assuming
    either is the installed version."""
    raw = getattr(result, "raw", None)
    if raw is not None:
        return str(raw)
    return str(result)


class HBEvalCrewObserver:
    """Optional passive observer for collecting per-task diagnostics
    (which agent ran, task order, raw outputs) across a Crew execution,
    for inclusion in evaluation context alongside a battery run driven by
    adapt_crewai_agent()/adapt_crewai_crew(). Does not run the battery
    itself and is not required for evaluate_with_battery() to work.
    """

    def __init__(self) -> None:
        self.task_log: list = []

    def record(self, task_description: str, agent_role: str, output: Any) -> None:
        self.task_log.append({
            "task": task_description,
            "agent": agent_role,
            "output": _extract_text(output),
        })

    def reset(self) -> None:
        self.task_log.clear()