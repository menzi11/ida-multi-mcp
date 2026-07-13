"""Tool parameter alias normalization for common LLM hallucinations."""

from __future__ import annotations

from typing import Any

# method/tool name -> {alias: canonical}
_TOOL_PARAM_ALIASES: dict[str, dict[str, str]] = {
    "disasm": {
        "end_ea": "end",
        "end_addr": "end",
        "until": "end",
        "stop": "end",
        "start": "addr",
        "start_addr": "addr",
        "count": "max_instructions",
        "n": "max_instructions",
        "num": "max_instructions",
        "limit": "max_instructions",
    },
}


def normalize_tool_params(method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Rename known alias keys before JSON-RPC param validation."""
    aliases = _TOOL_PARAM_ALIASES.get(method)
    if not aliases:
        return params

    out = dict(params)
    for alias, canonical in aliases.items():
        if alias not in out:
            continue
        if canonical not in out:
            out[canonical] = out.pop(alias)
        else:
            out.pop(alias)
    return out
