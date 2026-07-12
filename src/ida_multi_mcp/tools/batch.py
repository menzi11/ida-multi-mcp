"""Read-only batch query dispatch for ida-multi-mcp server."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..router import InstanceRouter

_router: "InstanceRouter | None" = None

MAX_BATCH_QUERIES = 50

# Read-only IDA tools safe for batch dispatch (no patch/rename/debug/py_eval).
BATCH_QUERY_WHITELIST = frozenset({
    "analyze_batch",
    "analyze_function",
    "basic_blocks",
    "callgraph",
    "callees",
    "decompile",
    "call_path",
    "diff_functions",
    "decompile_tree",
    "disasm",
    "export_funcs",
    "find",
    "find_bytes",
    "find_reads",
    "find_regex",
    "find_writes",
    "func_profile",
    "func_query",
    "get_bytes",
    "get_global_value",
    "get_int",
    "get_string",
    "imports",
    "imports_query",
    "insn_query",
    "int_convert",
    "list_funcs",
    "list_globals",
    "lookup_funcs",
    "trace_data_flow",
    "trace_value",
    "struct_infer",
    "xref_query",
    "xrefs_from",
    "xrefs_to",
})

BATCH_QUERY_SCHEMA = {
    "name": "batch_query",
    "description": (
        "Execute multiple read-only IDA queries in one server round-trip. "
        "Each entry is {tool, ...args} using the same parameters as the "
        "individual tool (except instance_id, which is shared). "
        "Prefer analyze_batch for multi-function analysis; use batch_query "
        "when mixing different tool types (e.g. decompile + xrefs_to + get_bytes)."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "queries": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "tool": {
                            "type": "string",
                            "description": "Tool name (must be in read-only whitelist)",
                        },
                    },
                    "required": ["tool"],
                    "additionalProperties": True,
                },
                "description": "List of tool calls, max 50",
            },
            "instance_id": {
                "type": "string",
                "description": "Target IDA instance ID (required)",
            },
        },
        "required": ["queries", "instance_id"],
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "count": {"type": "integer"},
            "results": {
                "type": "array",
                "items": {"type": "object"},
            },
            "error": {"type": "string"},
        },
    },
}


def set_router(router: "InstanceRouter") -> None:
    global _router
    _router = router


def _get_router() -> "InstanceRouter":
    if _router is None:
        raise RuntimeError("Router not initialized")
    return _router


def _normalize_subcall_response(ida_response: dict[str, Any]) -> dict[str, Any]:
    if "error" in ida_response:
        return {"error": ida_response["error"], **{
            k: ida_response[k]
            for k in ("hint", "available_instances")
            if k in ida_response
        }}

    is_error = bool(ida_response.get("isError"))
    structured = ida_response.get("structuredContent")
    if structured is None:
        content = ida_response.get("content")
        if isinstance(content, list) and content:
            text = content[0].get("text", "")
            if text:
                structured = {"text": text}

    if is_error:
        return {"error": "tool returned error", "result": structured}

    return {"result": structured}


def batch_query(arguments: dict[str, Any]) -> dict[str, Any]:
    """Run a batch of read-only IDA tool calls sequentially."""
    router = _get_router()
    queries = arguments.get("queries")
    instance_id = arguments.get("instance_id")

    if not instance_id:
        return {"error": "Missing required parameter 'instance_id'."}
    if not isinstance(queries, list) or not queries:
        return {"error": "queries must be a non-empty list"}
    if len(queries) > MAX_BATCH_QUERIES:
        return {
            "error": f"Too many queries (max {MAX_BATCH_QUERIES})",
            "count": len(queries),
        }

    results: list[dict[str, Any]] = []
    for index, entry in enumerate(queries):
        if not isinstance(entry, dict):
            results.append({"index": index, "error": "query must be an object"})
            continue

        tool = entry.get("tool")
        if not tool or not isinstance(tool, str):
            results.append({"index": index, "error": "missing tool field"})
            continue

        if tool not in BATCH_QUERY_WHITELIST:
            results.append({
                "index": index,
                "tool": tool,
                "error": "tool not in read-only batch_query whitelist",
            })
            continue

        sub_args = {k: v for k, v in entry.items() if k != "tool"}
        sub_args["instance_id"] = instance_id

        ida_response = router.route_request("tools/call", {
            "name": tool,
            "arguments": sub_args,
        })

        normalized = _normalize_subcall_response(ida_response)
        normalized["index"] = index
        normalized["tool"] = tool
        results.append(normalized)

    return {"count": len(results), "results": results}
