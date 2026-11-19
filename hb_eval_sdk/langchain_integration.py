"""
hb_eval_sdk.langchain_integration
===================================
Adapter that lets any LangChain AgentExecutor (or Runnable) be evaluated by
HB-Eval's fault-injection battery, using the CURRENT battery/verified API
(evaluate_with_battery / request_verified_evaluation) — not the legacy
single-shot evaluate().

This file replaces an earlier version that wired into the old evaluate()
path. That path still exists for backward compatibility, but new code
should use the battery methods below.

Design principle: this file does not reimplement evaluation logic. Its only
job is to adapt a LangChain agent's calling convention
    agent_executor.invoke({"input": ...})
into the one thing the SDK's battery methods need:
    agent_runner(system_prompt: str, question: str) -> str

Once adapted, evaluate_with_battery() and request_verified_evaluation() work
unchanged, because the battery is orchestrated entirely by the SDK/Gateway,
not by the framework being evaluated.

Compatible with langchain >= 0.2 (AgentExecutor / LCEL Runnable interfaces),
tested against langchain 1.3.x / langchain-core 1.4.x.
Requires: pip install hb-eval-sdk langchain

Usage
-----
    from hb_eval_sdk import HBEvalClient
    from hb_eval_sdk.langchain_integration import adapt_langchain_agent

    client = HBEvalClient(api_key=..., aes_key=..., signing_secret=...)
    my_agent = adapt_langchain_agent(agent_executor)

    base_task = {
        "system": "You are a safety-critical incident-response agent.",
        "question": "A critical incident is detected. Provide your response plan.",
        "required_in_response": ["assess", "respond"],
    }
    report = client.evaluate_with_battery(base_task, my_agent, n_scenarios=18)
"""
from __future__ import annotations
from typing import Any, Callable, Optional

from ._adapters import content_to_text


def adapt_langchain_agent(
    agent_executor: Any,
    *,
    input_key: str = "input",
    system_key: Optional[str] = None,
    output_key: Optional[str] = None,
) -> Callable[[str, str], str]:
    """Wrap a LangChain AgentExecutor / Runnable as an HB-Eval agent_runner.

    Args:
        agent_executor: Any object exposing .invoke(dict) -> dict|str, which
            covers AgentExecutor, LCEL chains, and most LangChain Runnables.
        input_key: the dict key the agent expects the user question under.
            Default "input" matches AgentExecutor's convention.
        system_key: if your agent/prompt template accepts a separate system
            message key (e.g. "system_prompt"), set it here. If None (the
            default), the battery's per-scenario system prompt is prepended
            to the question instead, since most AgentExecutors are built
            with a fixed system prompt at construction time and do not
            accept one per call.
        output_key: if agent_executor.invoke(...) returns a dict, this is
            the key holding the text response (commonly "output" for
            AgentExecutor). If None, common keys are tried automatically.

    Returns:
        A callable (system_prompt, question) -> str suitable for
        client.evaluate_with_battery(base_task, this_callable, ...).
    """
    _AUTO_OUTPUT_KEYS = ("output", "answer", "result", "text")

    def _extract_text(raw: Any) -> str:
        if isinstance(raw, str):
            return raw
        if isinstance(raw, dict):
            if output_key and output_key in raw:
                return str(raw[output_key])
            for k in _AUTO_OUTPUT_KEYS:
                if k in raw:
                    return str(raw[k])
            return str(raw)
        content = getattr(raw, "content", None)
        if content is not None:
            return content_to_text(content)
        return str(raw)

    def agent_runner(system_prompt: str, question: str) -> str:
        payload = {}
        if system_key:
            payload[system_key] = system_prompt
            payload[input_key] = question
        else:
            payload[input_key] = f"{system_prompt}\n\n{question}"
        raw = agent_executor.invoke(payload)
        return _extract_text(raw)

    return agent_runner


try:                                    # a real LangChain handler when LangChain is installed
    from langchain_core.callbacks import BaseCallbackHandler as _CallbackBase
except ImportError:                     # the adapter itself needs no LangChain import
    _CallbackBase = object  # type: ignore[assignment,misc]


class HBEvalLangChainCallback(_CallbackBase):  # type: ignore[misc, valid-type]
    """Optional passive callback for LangChain's callback system.

    Subclasses LangChain's BaseCallbackHandler. A plain object is not a valid handler: LangChain
    reads attributes such as `raise_error` and `ignore_agent` from every handler, so a duck-typed
    class raised AttributeError inside the user's own run the first time a tool was called.

    This does NOT run the battery itself — it collects per-run diagnostics
    (tool calls, retries, errors) alongside a battery run driven by
    adapt_langchain_agent(), for inclusion in evaluation context. Attach it
    when invoking the wrapped agent if you want that diagnostic detail;
    it is optional and evaluate_with_battery() works without it.
    """

    def __init__(self) -> None:
        self.tool_calls: list = []
        self.errors: list = []

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs: Any) -> None:
        # LangChain passes `serialized=None` for many tool invocations.
        """Record a tool invocation. LangChain often passes `serialized=None`, in which case the name falls back to the `name` keyword argument."""
        self.tool_calls.append({"tool": (serialized or {}).get("name") or kwargs.get("name"), "input": input_str})

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        """Record the message of a tool error."""
        self.errors.append(str(error))

    def reset(self) -> None:
        """Clear the recorded tool calls and errors."""
        self.tool_calls.clear()
        self.errors.clear()