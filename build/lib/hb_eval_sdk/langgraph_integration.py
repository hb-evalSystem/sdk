"""
hb_eval_sdk.langgraph_integration
====================================
Adapter that lets any compiled LangGraph graph be evaluated by HB-Eval's
fault-injection battery via the current evaluate_with_battery /
request_verified_evaluation API.

LangGraph's calling convention differs from LangChain's AgentExecutor: a
compiled graph is invoked with a STATE dict (often a TypedDict/MessagesState
with a "messages" list) and returns a state dict of the same shape. This
adapter's only job is translating (system_prompt, question) into that state
shape on the way in, and extracting the final assistant message on the way
out — the battery orchestration itself is unchanged and lives in the SDK.

Tested against langgraph 1.2.x / langchain-core 1.4.x.
Requires: pip install hb-eval-sdk langgraph langchain-core

Usage
-----
    from hb_eval_sdk import HBEvalClient
    from hb_eval_sdk.langgraph_integration import adapt_langgraph_agent

    client = HBEvalClient(api_key=..., aes_key=..., signing_secret=...)
    my_agent = adapt_langgraph_agent(compiled_graph)

    base_task = {
        "system": "You are a safety-critical incident-response agent.",
        "question": "A critical incident is detected. Provide your response plan.",
        "required_in_response": ["assess", "respond"],
    }
    report = client.evaluate_with_battery(base_task, my_agent, n_scenarios=18)
"""
from __future__ import annotations
from typing import Any, Callable, Optional


def adapt_langgraph_agent(
    compiled_graph: Any,
    *,
    messages_key: str = "messages",
    config: Optional[dict] = None,
) -> Callable[[str, str], str]:
    """Wrap a compiled LangGraph graph as an HB-Eval agent_runner.

    Args:
        compiled_graph: the object returned by StateGraph(...).compile().
            Must expose .invoke(state, config=...) -> state, which is the
            standard LangGraph interface.
        messages_key: the state key holding the message list. "messages" is
            the LangGraph/LangChain convention (MessagesState).
        config: optional LangGraph run config (e.g. {"configurable":
            {"thread_id": ...}}) forwarded on every call. If your graph uses
            checkpointing, supply a fresh/neutral thread_id here so battery
            scenarios do not leak state into one another between runs.

    Returns:
        A callable (system_prompt, question) -> str suitable for
        client.evaluate_with_battery(base_task, this_callable, ...).
    """
    try:
        from langchain_core.messages import HumanMessage, SystemMessage
        _HAVE_LC_MESSAGES = True
    except ImportError:
        _HAVE_LC_MESSAGES = False

    def _build_input_messages(system_prompt: str, question: str):
        if _HAVE_LC_MESSAGES:
            return [SystemMessage(content=system_prompt), HumanMessage(content=question)]
        # Fallback: LangGraph also accepts plain (role, content) tuples if
        # langchain_core isn't installed as a direct dependency.
        return [("system", system_prompt), ("human", question)]

    def _extract_last_ai_text(result_state: Any) -> str:
        msgs = None
        if isinstance(result_state, dict):
            msgs = result_state.get(messages_key)
        else:
            msgs = getattr(result_state, messages_key, None)

        if not msgs:
            return str(result_state)

        last = msgs[-1]
        content = getattr(last, "content", None)
        if content is not None:
            return str(content)
        if isinstance(last, tuple) and len(last) == 2:
            return str(last[1])
        return str(last)

    def agent_runner(system_prompt: str, question: str) -> str:
        state = {messages_key: _build_input_messages(system_prompt, question)}
        result_state = compiled_graph.invoke(state, config=config) if config else compiled_graph.invoke(state)
        return _extract_last_ai_text(result_state)

    return agent_runner


def adapt_langgraph_node(
    node_fn: Callable[[dict], dict],
    *,
    messages_key: str = "messages",
) -> Callable[[str, str], str]:
    """Wrap a SINGLE LangGraph node function (not a compiled graph) as an
    HB-Eval agent_runner. Useful for evaluating one node in isolation
    (e.g. a planning node) rather than an end-to-end multi-agent graph.
    """
    def agent_runner(system_prompt: str, question: str) -> str:
        state = {messages_key: [("system", system_prompt), ("human", question)]}
        result = node_fn(state)
        msgs = result.get(messages_key) if isinstance(result, dict) else None
        if not msgs:
            return str(result)
        last = msgs[-1]
        content = getattr(last, "content", None)
        return str(content) if content is not None else str(last)

    return agent_runner