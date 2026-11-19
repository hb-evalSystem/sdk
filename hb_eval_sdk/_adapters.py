"""Shared helpers for the framework adapters (private; not part of the public API)."""
from __future__ import annotations
from typing import Any


def content_to_text(content: Any) -> str:
    """Text of a model message's `content`.

    Providers return either a plain string or a list of content blocks (strings, or dicts such as
    {"type": "text", "text": "..."} alongside tool-use blocks). `str(list)` would hand the battery a
    Python repr, which then fails required-keyword checks for a reason that has nothing to do with the
    agent. Only text is kept; tool-use and other blocks contribute nothing.
    """
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, (list, tuple)):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                text = block.get("text")
                if isinstance(text, str) and block.get("type", "text") == "text":
                    parts.append(text)
        return "".join(parts)
    return str(content)
