"""Composite analysis tools that aggregate multiple data sources.

Ported from upstream `ida-pro-mcp` `api_composite.py` (v2.0.0). Adapted:
- No `_parse_function_tinfo` helper in this project's `api_types`; `diff_before_after`
  uses `ida_typeinf.tinfo_t(text, None, PT_SIL)` directly, matching this project's
  `set_type` style (api_types.py:314).
- `get_stack_frame_variables_internal` import dropped (unused upstream as well).
"""

from __future__ import annotations

from collections import defaultdict, deque
import difflib
from typing import Annotated, Callable, TypedDict

import ida_hexrays
import ida_typeinf
import ida_ua
import ida_bytes
import idaapi
import idautils
import idc

from .rpc import tool, unsafe
from .sync import idasync, tool_timeout, IDAError
from .utils import (
    decompile_function_safe,
    extract_function_constants,
    extract_function_strings,
    get_all_comments,
    get_all_xrefs,
    get_assembly_lines,
    get_callees,
    get_callers,
    get_prototype,
    normalize_list_input,
    parse_address,
    safe_get_reg_name,
    insn_mnem,
    disasm_at,
)


_DECOMPILE_LINE_CAP_DEFAULT = 600
_DECOMPILE_TREE_MAX_DEPTH_DEFAULT = 2
_DECOMPILE_TREE_MAX_NODES_DEFAULT = 30
_TOP_STRINGS = 10
_TOP_CONSTANTS = 10
# Cap on the shared-string map returned by analyze_component. Sorted by
# accessor count desc so the most-shared strings surface first. Mirrors
# the bounded-output style used by survey_binary (e.g. root_functions[:100]).
_MAX_STRING_USAGE = 50
_BORING_CONSTANTS = frozenset({0, 1, -1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})


class BasicBlockSummary(TypedDict):
    count: int
    cyclomatic_complexity: int


class XrefEntry(TypedDict):
    addr: str
    type: str


FunctionXrefs = TypedDict(
    "FunctionXrefs",
    {"to": list[XrefEntry], "from": list[XrefEntry]},
)


class CommentEntry(TypedDict, total=False):
    regular: str
    repeatable: str


class ConstantEntry(TypedDict):
    addr: str
    value: str
    decimal: int


class AnalyzeFunctionResult(TypedDict, total=False):
    addr: str
    name: str
    prototype: str | None
    size: int
    decompiled: str | None
    decompile_lines: int
    decompile_truncated: int
    assembly: str | None
    strings: list[str]
    constants: list[ConstantEntry]
    callees: list[str]
    callers: list[str]
    xrefs: FunctionXrefs
    comments: dict[str, CommentEntry]
    basic_blocks: BasicBlockSummary
    error: str | None


class DecompileTreeNode(TypedDict, total=False):
    addr: str
    name: str
    depth: int
    pseudocode: str | None
    decompile_lines: int
    decompile_truncated: int
    assembly: str | None


DecompileTreeEdge = TypedDict(
    "DecompileTreeEdge",
    {"from": str, "to": str},
)


class DecompileTreeStats(TypedDict):
    decompiled: int
    stubbed: int
    deduped: int
    total_discovered: int


class DecompileTreeResult(TypedDict, total=False):
    root: str
    depth: int
    nodes: list[DecompileTreeNode]
    edges: list[DecompileTreeEdge]
    stubs: list[str]
    stats: DecompileTreeStats
    error: str


class DiffFunctionsResult(TypedDict, total=False):
    addr_a: str
    addr_b: str
    name_a: str
    name_b: str
    pseudocode_changed: bool
    unified_diff: str
    constants: dict[str, list[str]]
    error: str


class CallPathResult(TypedDict, total=False):
    from_addr: str
    to_addr: str
    paths: list[list[str]]
    path_strings: list[str]
    count: int
    error: str


class ComponentFunctionSummary(TypedDict, total=False):
    addr: str
    name: str
    prototype: str | None
    size: int
    callees: list[str]
    strings: list[str]
    basic_blocks: int
    complexity: int
    error: str


ComponentGraphEdge = TypedDict(
    "ComponentGraphEdge",
    {"from": str, "to": str, "name": str},
)


class InternalCallGraph(TypedDict):
    nodes: list[str]
    edges: list[ComponentGraphEdge]


class SharedGlobalInfo(TypedDict):
    addr: str
    name: str
    accessed_by: list[str]


class AnalyzeComponentResult(TypedDict, total=False):
    functions: list[ComponentFunctionSummary]
    internal_call_graph: InternalCallGraph
    shared_globals: list[SharedGlobalInfo]
    interface_functions: list[str]
    internal_only: list[str]
    string_usage: dict[str, list[str]]
    error: str


class DiffBeforeAfterResult(TypedDict, total=False):
    before: str | None
    after: str | None
    action_applied: str
    changes_detected: bool
    error: str


class TraceDataFlowNode(TypedDict):
    addr: str
    func: str | None
    instruction: str | None
    type: str
    name: str | None
    depth: int


TraceDataFlowEdge = TypedDict(
    "TraceDataFlowEdge",
    {"from": str, "to": str, "type": str},
)


class TraceDataFlowResult(TypedDict, total=False):
    start: str
    direction: str
    depth_reached: int
    nodes: list[TraceDataFlowNode]
    edges: list[TraceDataFlowEdge]
    error: str


class TraceValueSite(TypedDict, total=False):
    addr: str
    insn: str
    source: str
    role: str


class TraceValueResult(TypedDict, total=False):
    variable: str
    function: str
    direction: str
    definitions: list[TraceValueSite]
    uses: list[TraceValueSite]
    error: str


# ---------------------------------------------------------------------------
# Internal helpers (called from within @idasync context)
# ---------------------------------------------------------------------------


def _resolve_addr(addr: str) -> int:
    """Resolve hex/decimal/symbol to ea. Raises IDAError if not found."""
    try:
        return parse_address(addr)
    except IDAError:
        ea = idaapi.get_name_ea(idaapi.BADADDR, addr)
        if ea == idaapi.BADADDR:
            raise IDAError(f"Address/name not found: {addr!r}")
        return ea


def _basic_block_info(ea: int) -> BasicBlockSummary:
    func = idaapi.get_func(ea)
    if func is None:
        return {"count": 0, "cyclomatic_complexity": 0}

    fc = idaapi.FlowChart(func)
    nodes = 0
    edges = 0
    for block in fc:
        nodes += 1
        for _ in block.succs():
            edges += 1

    return {"count": nodes, "cyclomatic_complexity": edges - nodes + 2}


def _filter_constants(raw: list[dict], limit: int = _TOP_CONSTANTS) -> list[ConstantEntry]:
    """Drop boring constants, return top N by absolute value."""
    out: list[ConstantEntry] = []
    for c in raw:
        val = c.get("decimal")
        if val is None:
            continue
        if not isinstance(val, int):
            try:
                val = int(val)
            except (TypeError, ValueError):
                continue
        if abs(val) < 0x100 or val in _BORING_CONSTANTS:
            continue
        out.append({
            "addr": str(c.get("addr", "")),
            "value": str(c.get("value", hex(val))),
            "decimal": val,
        })
    out.sort(key=lambda c: abs(c["decimal"]), reverse=True)
    return out[:limit]


def _cap_decompile(
    code: str | None,
    max_lines: int = _DECOMPILE_LINE_CAP_DEFAULT,
) -> tuple[str | None, int | None, int | None]:
    """Cap decompiled output. max_lines=0 means no IDA-side truncation (full text).

    Returns (possibly_truncated_code, total_lines_if_truncated, total_lines)."""
    if code is None:
        return None, None, None
    lines = code.split("\n")
    total = len(lines)
    if max_lines == 0:
        return code, None, total
    if total <= max_lines:
        return code, None, total
    truncated = "\n".join(lines[:max_lines])
    return truncated, total, total


def _callee_target_ea(callee: dict) -> int | None:
    addr = callee.get("addr")
    if not isinstance(addr, str):
        return None
    try:
        return int(addr, 16)
    except ValueError:
        return None


def _internal_callee_eas(ea: int) -> list[int]:
    """Return resolved internal callee start addresses for a function."""
    out: list[int] = []
    seen: set[int] = set()
    for callee in get_callees(hex(ea)) or []:
        target = _callee_target_ea(callee)
        if target is None or target in seen:
            continue
        if idaapi.get_func(target) is None:
            continue
        seen.add(target)
        out.append(target)
    return out


def _plan_decompile_tree(
    root_ea: int,
    max_depth: int,
    get_internal_callees: Callable[[int], list[int]],
) -> tuple[list[tuple[int, int]], list[tuple[int, int]], int]:
    """BFS call-tree planner. Returns (discovered, edges, deduped_queue_skips)."""
    if max_depth < 0:
        max_depth = 0

    discovered: list[tuple[int, int]] = []
    seen: set[int] = set()
    edges: list[tuple[int, int]] = []
    deduped = 0
    queue: deque[tuple[int, int]] = deque([(root_ea, 0)])

    while queue:
        ea, node_depth = queue.popleft()
        if ea in seen:
            deduped += 1
            continue
        seen.add(ea)
        discovered.append((ea, node_depth))

        if node_depth >= max_depth:
            continue

        for target in get_internal_callees(ea):
            edges.append((ea, target))
            if target not in seen:
                queue.append((target, node_depth + 1))

    return discovered, edges, deduped


def _build_decompile_tree_node(
    ea: int,
    depth: int,
    *,
    include_asm: bool,
    max_pseudocode_lines: int,
) -> DecompileTreeNode:
    name = idaapi.get_func_name(ea) or ""
    node: DecompileTreeNode = {"addr": hex(ea), "name": name, "depth": depth}
    try:
        raw_code = decompile_function_safe(ea)
        code, truncated_at, total_lines = _cap_decompile(
            raw_code, max_pseudocode_lines
        )
        node["pseudocode"] = code
        if total_lines is not None:
            node["decompile_lines"] = total_lines
        if truncated_at is not None:
            node["decompile_truncated"] = truncated_at
    except Exception:
        node["pseudocode"] = None

    if include_asm:
        try:
            node["assembly"] = get_assembly_lines(ea)
        except Exception:
            node["assembly"] = None

    return node


def _decompile_tree_internal(
    root_ea: int,
    *,
    depth: int = _DECOMPILE_TREE_MAX_DEPTH_DEFAULT,
    max_nodes: int = _DECOMPILE_TREE_MAX_NODES_DEFAULT,
    include_asm: bool = False,
    max_pseudocode_lines: int = _DECOMPILE_LINE_CAP_DEFAULT,
) -> DecompileTreeResult:
    if idaapi.get_func(root_ea) is None:
        return {"error": f"No function at {hex(root_ea)}"}

    if depth < 0:
        depth = 0
    if depth > 10:
        depth = 10
    if max_nodes < 1:
        max_nodes = 1
    if max_nodes > 200:
        max_nodes = 200

    discovered, raw_edges, deduped = _plan_decompile_tree(
        root_ea,
        depth,
        _internal_callee_eas,
    )

    stubs = [hex(ea) for ea, _ in discovered[max_nodes:]]

    nodes: list[DecompileTreeNode] = []
    for ea, node_depth in discovered[:max_nodes]:
        nodes.append(
            _build_decompile_tree_node(
                ea,
                node_depth,
                include_asm=include_asm,
                max_pseudocode_lines=max_pseudocode_lines,
            )
        )

    edges: list[DecompileTreeEdge] = [
        {"from": hex(src), "to": hex(dst)} for src, dst in raw_edges
    ]

    return {
        "root": hex(root_ea),
        "depth": depth,
        "nodes": nodes,
        "edges": edges,
        "stubs": stubs,
        "stats": {
            "decompiled": len(nodes),
            "stubbed": len(stubs),
            "deduped": deduped,
            "total_discovered": len(discovered),
        },
    }


def _compact_strings(raw: list[dict], limit: int = _TOP_STRINGS) -> list[str]:
    """Return just the string values, deduplicated, capped at limit."""
    seen: set[str] = set()
    out: list[str] = []
    for s in raw:
        val = s.get("value") or s.get("string", "")
        if val and val not in seen:
            seen.add(val)
            out.append(val)
            if len(out) >= limit:
                break
    return out


def _compact_callees(raw: list[dict]) -> list[str]:
    return [c.get("name") or c.get("addr", "?") for c in raw]


def _analyze_function_internal(
    ea: int,
    *,
    include_asm: bool = False,
    max_pseudocode_lines: int = _DECOMPILE_LINE_CAP_DEFAULT,
) -> AnalyzeFunctionResult:
    """Compact per-function analysis. Must be called inside an @idasync context."""
    result: AnalyzeFunctionResult = {"addr": hex(ea), "error": None}

    try:
        func = idaapi.get_func(ea)
        if func is None:
            result["error"] = f"No function at {hex(ea)}"
            return result

        result["name"] = idaapi.get_func_name(ea) or ""
        result["prototype"] = get_prototype(func)
        result["size"] = func.end_ea - func.start_ea

        try:
            raw_code = decompile_function_safe(ea)
            code, truncated_at, total_lines = _cap_decompile(
                raw_code, max_pseudocode_lines
            )
            result["decompiled"] = code
            if total_lines is not None:
                result["decompile_lines"] = total_lines
            if truncated_at is not None:
                result["decompile_truncated"] = truncated_at
        except Exception:
            result["decompiled"] = None

        if include_asm:
            try:
                result["assembly"] = get_assembly_lines(ea)
            except Exception:
                result["assembly"] = None

        result["strings"] = _compact_strings(extract_function_strings(ea))
        result["constants"] = _filter_constants(extract_function_constants(ea))
        result["callees"] = _compact_callees(get_callees(hex(ea)))
        result["callers"] = _compact_callees(get_callers(hex(ea)))
        result["xrefs"] = get_all_xrefs(ea)
        result["comments"] = get_all_comments(ea)
        result["basic_blocks"] = _basic_block_info(ea)

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Tool 1 — analyze_function
# ---------------------------------------------------------------------------


@tool
@idasync
@tool_timeout(120.0)
def analyze_function(
    addr: Annotated[str, "Function address or name"],
    include_asm: Annotated[bool, "Include full disassembly (default: false, saves tokens)"] = False,
    max_pseudocode_lines: Annotated[
        int,
        "Pseudocode line cap (default: 600). Set 0 for full text (large outputs cached by server)",
    ] = _DECOMPILE_LINE_CAP_DEFAULT,
) -> AnalyzeFunctionResult:
    """Compact single-function analysis in one call: pseudocode, strings,
    constants, callers, callees, xrefs, comments, and basic block summary.

    Prefer this over chaining decompile + callees + xrefs_to for a single
    function. For multiple functions, use analyze_batch instead."""
    try:
        ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"addr": addr, "error": str(exc)}

    return _analyze_function_internal(
        ea,
        include_asm=include_asm,
        max_pseudocode_lines=max_pseudocode_lines,
    )


# ---------------------------------------------------------------------------
# Tool — decompile_tree
# ---------------------------------------------------------------------------


@tool
@idasync
@tool_timeout(300.0)
def decompile_tree(
    addr: Annotated[str, "Root function address or name"],
    depth: Annotated[int, "Callee recursion depth (default: 2, max: 10)"] = _DECOMPILE_TREE_MAX_DEPTH_DEFAULT,
    max_nodes: Annotated[int, "Max functions to decompile (default: 30, max: 200)"] = _DECOMPILE_TREE_MAX_NODES_DEFAULT,
    include_asm: Annotated[bool, "Include disassembly per node (default: false)"] = False,
    max_pseudocode_lines: Annotated[
        int,
        "Pseudocode line cap per node (default: 600). Set 0 for full text",
    ] = _DECOMPILE_LINE_CAP_DEFAULT,
) -> DecompileTreeResult:
    """Decompile a function and its internal callees up to depth N in one call.

    Returns flat nodes + edges (deduped by address). Nodes beyond max_nodes
    appear in stubs — decompile them individually or rerun with a higher budget.

    Prefer this over calling decompile + callees recursively when exploring
    a call subtree."""
    try:
        root_ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"error": str(exc)}

    return _decompile_tree_internal(
        root_ea,
        depth=depth,
        max_nodes=max_nodes,
        include_asm=include_asm,
        max_pseudocode_lines=max_pseudocode_lines,
    )


# ---------------------------------------------------------------------------
# diff_functions — pseudocode + constants diff
# ---------------------------------------------------------------------------


def _constant_decimal_set(raw: list[dict]) -> set[int]:
    out: set[int] = set()
    for c in raw:
        val = c.get("decimal")
        if isinstance(val, int):
            out.add(val)
    return out


def _format_constant_set(values: set[int]) -> list[str]:
    return sorted(hex(v) for v in values)


def _diff_constant_sets(raw_a: list[dict], raw_b: list[dict]) -> dict[str, list[str]]:
    set_a = _constant_decimal_set(raw_a)
    set_b = _constant_decimal_set(raw_b)
    return {
        "only_in_a": _format_constant_set(set_a - set_b),
        "only_in_b": _format_constant_set(set_b - set_a),
        "common": _format_constant_set(set_a & set_b),
    }


def _diff_pseudocode(
    code_a: str | None,
    code_b: str | None,
    name_a: str,
    name_b: str,
) -> tuple[bool, str]:
    if code_a is None and code_b is None:
        return False, ""
    if code_a is None:
        code_a = ""
    if code_b is None:
        code_b = ""
    changed = code_a != code_b
    diff_lines = difflib.unified_diff(
        code_a.splitlines(keepends=True),
        code_b.splitlines(keepends=True),
        fromfile=name_a,
        tofile=name_b,
        lineterm="",
    )
    return changed, "".join(diff_lines)


def _diff_functions_internal(ea_a: int, ea_b: int) -> DiffFunctionsResult:
    func_a = idaapi.get_func(ea_a)
    func_b = idaapi.get_func(ea_b)
    if func_a is None:
        return {"error": f"No function at {hex(ea_a)}"}
    if func_b is None:
        return {"error": f"No function at {hex(ea_b)}"}

    name_a = idaapi.get_func_name(ea_a) or hex(ea_a)
    name_b = idaapi.get_func_name(ea_b) or hex(ea_b)
    code_a = decompile_function_safe(ea_a)
    code_b = decompile_function_safe(ea_b)
    changed, unified = _diff_pseudocode(code_a, code_b, name_a, name_b)

    return {
        "addr_a": hex(ea_a),
        "addr_b": hex(ea_b),
        "name_a": name_a,
        "name_b": name_b,
        "pseudocode_changed": changed,
        "unified_diff": unified,
        "constants": _diff_constant_sets(
            extract_function_constants(ea_a),
            extract_function_constants(ea_b),
        ),
    }


@tool
@idasync
@tool_timeout(180.0)
def diff_functions(
    addr_a: Annotated[str, "First function address or name"],
    addr_b: Annotated[str, "Second function address or name"],
) -> DiffFunctionsResult:
    """Compare two functions by pseudocode unified diff and constant sets.

    Unlike compare_functions (similarity score), this shows line-level
    pseudocode differences and symmetric constant set changes."""
    try:
        ea_a = _resolve_addr(addr_a)
        ea_b = _resolve_addr(addr_b)
    except IDAError as exc:
        return {"error": str(exc)}

    return _diff_functions_internal(ea_a, ea_b)


# ---------------------------------------------------------------------------
# call_path — find call paths between two functions
# ---------------------------------------------------------------------------

_CALL_PATH_MAX_DEPTH_DEFAULT = 10
_CALL_PATH_MAX_PATHS_DEFAULT = 20


def _find_call_paths(
    from_ea: int,
    to_ea: int,
    max_depth: int,
    max_paths: int,
    get_internal_callees: Callable[[int], list[int]],
) -> list[list[int]]:
    """BFS enumerate call paths from from_ea to to_ea (internal callees only)."""
    if max_depth < 1:
        max_depth = 1
    if max_paths < 1:
        max_paths = 1

    paths: list[list[int]] = []
    queue: deque[list[int]] = deque([[from_ea]])

    while queue and len(paths) < max_paths:
        path = queue.popleft()
        current = path[-1]
        if len(path) > max_depth + 1:
            continue
        if current == to_ea and len(path) > 1:
            paths.append(path)
            continue
        if len(path) > max_depth:
            continue
        for callee in get_internal_callees(current):
            if callee in path:
                continue
            queue.append(path + [callee])

    return paths


def _format_call_path(path: list[int]) -> str:
    names = []
    for ea in path:
        name = idaapi.get_func_name(ea) or hex(ea)
        names.append(f"{name} ({hex(ea)})")
    return " -> ".join(names)


@tool
@idasync
@tool_timeout(120.0)
def call_path(
    from_addr: Annotated[str, "Start function address or name"],
    to_addr: Annotated[str, "Target function address or name"],
    max_depth: Annotated[int, "Max hops (default: 10, max: 20)"] = _CALL_PATH_MAX_DEPTH_DEFAULT,
    max_paths: Annotated[int, "Max paths returned (default: 20, max: 50)"] = _CALL_PATH_MAX_PATHS_DEFAULT,
) -> CallPathResult:
    """Find call paths from function A to function B over internal calls.

    Returns all paths up to max_depth. Use to distinguish main-path vs
    init-path reachability."""
    try:
        from_ea = _resolve_addr(from_addr)
        to_ea = _resolve_addr(to_addr)
    except IDAError as exc:
        return {"error": str(exc)}

    if idaapi.get_func(from_ea) is None:
        return {"error": f"No function at {hex(from_ea)}"}
    if idaapi.get_func(to_ea) is None:
        return {"error": f"No function at {hex(to_ea)}"}

    if max_depth > 20:
        max_depth = 20
    if max_paths > 50:
        max_paths = 50

    raw_paths = _find_call_paths(
        from_ea, to_ea, max_depth, max_paths, _internal_callee_eas
    )
    hex_paths = [[hex(ea) for ea in path] for path in raw_paths]

    return {
        "from_addr": hex(from_ea),
        "to_addr": hex(to_ea),
        "paths": hex_paths,
        "path_strings": [_format_call_path(path) for path in raw_paths],
        "count": len(hex_paths),
    }


# ---------------------------------------------------------------------------
# Tool 2 — analyze_component
# ---------------------------------------------------------------------------


@tool
@idasync
@tool_timeout(180.0)
def analyze_component(
    addrs: Annotated[list[str] | str, "Function addresses (comma-separated or list)"],
) -> AnalyzeComponentResult:
    """Analyze related functions as a group: per-function compact summaries,
    internal call graph (edges only between supplied functions), shared globals,
    interface vs internal classification, and strings used by multiple members."""
    raw = normalize_list_input(addrs)
    if not raw:
        return {"error": "Empty address list"}

    ea_map: dict[int, str] = {}
    for a in raw:
        try:
            ea_map[_resolve_addr(a)] = a
        except IDAError:
            return {"error": f"Cannot resolve address: {a!r}"}

    ea_set = set(ea_map.keys())

    # --- Per-function compact summary ---
    functions: list[ComponentFunctionSummary] = []
    for ea in ea_set:
        func = idaapi.get_func(ea)
        if func is None:
            functions.append({"addr": hex(ea), "error": "No function"})
            continue
        name = idaapi.get_func_name(ea) or ""
        top_strings = _compact_strings(extract_function_strings(ea), limit=5)
        callee_list = _compact_callees(get_callees(hex(ea)))
        bb = _basic_block_info(ea)
        functions.append({
            "addr": hex(ea),
            "name": name,
            "prototype": get_prototype(func),
            "size": func.end_ea - func.start_ea,
            "callees": callee_list,
            "strings": top_strings,
            "basic_blocks": bb["count"],
            "complexity": bb["cyclomatic_complexity"],
        })

    # --- Internal call graph ---
    nodes = [hex(ea) for ea in ea_set]
    edges: list[ComponentGraphEdge] = []
    for ea in ea_set:
        for callee in (get_callees(hex(ea)) or []):
            callee_ea = callee.get("addr")
            if isinstance(callee_ea, str):
                try:
                    callee_ea = int(callee_ea, 16)
                except (ValueError, TypeError):
                    continue
            if callee_ea in ea_set:
                edges.append({
                    "from": hex(ea),
                    "to": hex(callee_ea),
                    "name": callee.get("name", ""),
                })

    # --- Shared globals ---
    func_globals: dict[int, set[int]] = {}
    for ea in ea_set:
        accessed: set[int] = set()
        func = idaapi.get_func(ea)
        if func is None:
            func_globals[ea] = accessed
            continue
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head, 0):
                if xref.iscode:
                    continue
                ref_func = idaapi.get_func(xref.to)
                if ref_func is None and idaapi.is_loaded(xref.to):
                    accessed.add(xref.to)
        func_globals[ea] = accessed

    global_refcount: dict[int, list[str]] = defaultdict(list)
    for ea, gset in func_globals.items():
        fname = idaapi.get_func_name(ea) or hex(ea)
        for g in gset:
            global_refcount[g].append(fname)

    shared_globals: list[SharedGlobalInfo] = []
    for g_ea, accessors in sorted(global_refcount.items()):
        if len(accessors) >= 2:
            shared_globals.append({
                "addr": hex(g_ea),
                "name": idaapi.get_name(g_ea) or hex(g_ea),
                "accessed_by": sorted(accessors),
            })

    # --- Interface vs internal ---
    # Use raw xrefs instead of get_callers() to avoid its default 50-caller cap,
    # which could misclassify a function with >50 callers if all inspected ones
    # are internal but a later one is external. Short-circuits on first external.
    # A function with zero call xrefs (entry point, exported, indirect-call
    # target via data xref) is treated as interface — it cannot be reached
    # from within the component, so by definition it is externally reachable.
    interface_functions: list[str] = []
    internal_only: list[str] = []
    for ea in ea_set:
        has_external = False
        has_internal = False
        for xref in idautils.XrefsTo(ea, 0):
            if not xref.iscode:
                continue
            if xref.type not in (idaapi.fl_CF, idaapi.fl_CN):
                continue
            caller_func = idaapi.get_func(xref.frm)
            if caller_func is None or caller_func.start_ea not in ea_set:
                has_external = True
                break
            has_internal = True
        if has_external or not has_internal:
            interface_functions.append(hex(ea))
        else:
            internal_only.append(hex(ea))

    # --- String usage across functions ---
    string_funcs: dict[str, set[str]] = defaultdict(set)
    for ea in ea_set:
        fname = idaapi.get_func_name(ea) or hex(ea)
        for s in (extract_function_strings(ea) or []):
            sval = s.get("value") or s.get("string", "")
            if sval:
                string_funcs[sval].add(fname)

    # Sort by accessor count desc (most-shared first), break ties alphabetically.
    # Capped at _MAX_STRING_USAGE to keep the response bounded for large components.
    sorted_items = sorted(
        ((s, fnames) for s, fnames in string_funcs.items() if len(fnames) >= 2),
        key=lambda kv: (-len(kv[1]), kv[0]),
    )
    string_usage = {
        s: sorted(fnames) for s, fnames in sorted_items[:_MAX_STRING_USAGE]
    }

    return {
        "functions": functions,
        "internal_call_graph": {"nodes": nodes, "edges": edges},
        "shared_globals": shared_globals,
        "interface_functions": interface_functions,
        "internal_only": internal_only,
        "string_usage": string_usage,
    }


# ---------------------------------------------------------------------------
# Tool 3 — diff_before_after
# ---------------------------------------------------------------------------

_VALID_ACTIONS = frozenset({"rename_func", "set_type", "set_comment"})


def _parse_func_tinfo(signature_text: str) -> ida_typeinf.tinfo_t:
    """Parse a function-type declaration. Mirrors the style used by set_type in
    api_types.py (tinfo_t constructor with PT_SIL)."""
    text = signature_text.strip()
    if not text:
        raise ValueError("Function signature is required")
    tif = ida_typeinf.tinfo_t(text, None, ida_typeinf.PT_SIL)
    if not tif.is_func():
        raise ValueError(f"Not a function type: {signature_text!r}")
    return tif


@tool
@unsafe
@idasync
@tool_timeout(120.0)
def diff_before_after(
    addr: Annotated[str, "Function address"],
    action: Annotated[str, "Action: 'rename_func', 'set_type', 'set_comment'"],
    action_args: Annotated[dict, "Arguments for the action"],
) -> DiffBeforeAfterResult:
    """Apply a rename/type/comment action and return the before/after decompilation
    side by side. Actions: 'rename_func' ({name}), 'set_type' ({type}),
    'set_comment' ({comment}). Useful to verify a rename or type change actually
    improved readability. Returns {before, after, action_applied, changes_detected}."""
    if action not in _VALID_ACTIONS:
        return {"error": f"Invalid action {action!r}. Must be one of: {', '.join(sorted(_VALID_ACTIONS))}"}

    try:
        ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"error": str(exc)}

    func = idaapi.get_func(ea)
    if func is None:
        return {"error": f"No function at {hex(ea)}"}

    before = decompile_function_safe(ea)

    try:
        if action == "rename_func":
            name = action_args.get("name")
            if not name:
                return {"error": "action_args must contain 'name'"}
            ok = idaapi.set_name(ea, name, idaapi.SN_CHECK)
            if not ok:
                return {"error": f"set_name failed for {name!r}"}
            applied = f"Renamed to {name!r}"

        elif action == "set_type":
            type_str = action_args.get("type")
            if not type_str:
                return {"error": "action_args must contain 'type'"}
            try:
                tif = _parse_func_tinfo(type_str)
            except ValueError as exc:
                return {"error": str(exc)}
            ok = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
            if not ok:
                return {"error": f"apply_tinfo failed for {type_str!r}"}
            applied = f"Set type to {type_str!r}"

        elif action == "set_comment":
            comment = action_args.get("comment")
            if comment is None:
                return {"error": "action_args must contain 'comment'"}
            idaapi.set_cmt(ea, comment, False)
            applied = f"Set comment: {comment!r}"

        else:
            return {"error": f"Unhandled action {action!r}"}
    except Exception as exc:
        return {"error": f"Action {action!r} failed: {exc}"}

    ida_hexrays.mark_cfunc_dirty(ea)
    after = decompile_function_safe(ea)

    return {
        "before": before,
        "after": after,
        "action_applied": applied,
        "changes_detected": before != after,
    }


# ---------------------------------------------------------------------------
# trace_value — single-function register def-use (Phase 2 MVP)
# ---------------------------------------------------------------------------

_X86_REG_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("rax", ("rax", "eax", "ax", "al")),
    ("rbx", ("rbx", "ebx", "bx", "bl")),
    ("rcx", ("rcx", "ecx", "cx", "cl")),
    ("rdx", ("rdx", "edx", "dx", "dl")),
    ("rsi", ("rsi", "esi", "si", "sil")),
    ("rdi", ("rdi", "edi", "di", "dil")),
    ("rbp", ("rbp", "ebp", "bp", "bpl")),
    ("rsp", ("rsp", "esp", "sp", "spl")),
    ("r8", ("r8", "r8d", "r8w", "r8b")),
    ("r9", ("r9", "r9d", "r9w", "r9b")),
    ("r10", ("r10", "r10d", "r10w", "r10b")),
    ("r11", ("r11", "r11d", "r11w", "r11b")),
    ("r12", ("r12", "r12d", "r12w", "r12b")),
    ("r13", ("r13", "r13d", "r13w", "r13b")),
    ("r14", ("r14", "r14d", "r14w", "r14b")),
    ("r15", ("r15", "r15d", "r15w", "r15b")),
)

_REG_DEF_MNEMS = frozenset({
    "mov", "movzx", "movsx", "movsxd", "lea", "pop", "add", "sub",
    "and", "or", "xor", "inc", "dec", "not", "neg", "adc", "sbb",
    "imul", "xadd", "cmpxchg", "shl", "shr", "sar", "rol", "ror",
    "bswap", "cdqe", "cqo",
})


def _reg_family_for(name: str) -> frozenset[str] | None:
    n = name.strip().lower()
    for _canonical, aliases in _X86_REG_FAMILIES:
        if n in aliases:
            return frozenset(aliases)
    return frozenset({n})


def _reg_matches(variable: str, reg_name: str | None) -> bool:
    if not reg_name:
        return False
    family = _reg_family_for(variable)
    return reg_name.strip().lower() in family


def _decode_insn_at(ea: int) -> ida_ua.insn_t | None:
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0:
        return None
    return insn


def _next_head(ea: int, end_ea: int) -> int:
    return ida_bytes.next_head(ea, end_ea)


def _insn_mnem(insn: ida_ua.insn_t, ea: int | None = None) -> str:
    return insn_mnem(insn, ea)


def _operand_reg_name(insn: ida_ua.insn_t, idx: int) -> str | None:
    op = insn.ops[idx]
    if op.type == ida_ua.o_void:
        return None
    if op.type == ida_ua.o_reg:
        return safe_get_reg_name(op.reg) if op.reg else None
    return None


def _describe_operand_source(insn: ida_ua.insn_t, skip_idx: int) -> str:
    for i in range(8):
        if i == skip_idx:
            continue
        op = insn.ops[i]
        if op.type == ida_ua.o_void:
            break
        if op.type == ida_ua.o_reg:
            name = safe_get_reg_name(op.reg) if op.reg else "?"
            return f"reg_{name}"
        if op.type == ida_ua.o_imm:
            return f"imm_{hex(op.value)}"
        if op.type == ida_ua.o_mem:
            return f"mem_{hex(op.addr)}"
        if op.type == ida_ua.o_displ:
            base = safe_get_reg_name(op.reg) if op.reg else "?"
            return f"mem[{base}+{hex(op.addr)}]"
        if op.type == ida_ua.o_phrase:
            base = safe_get_reg_name(op.reg) if op.reg else "?"
            index_reg = None
            if hasattr(op, "specreg") and op.specreg:
                index_reg = safe_get_reg_name(op.specreg)
            return f"mem[{base}+{index_reg or '?'}*{hex(op.addr)}]"
    return "unknown"


def _is_reg_definition(insn: ida_ua.insn_t, variable: str, ea: int | None = None) -> bool:
    mnem = _insn_mnem(insn, ea)
    if mnem not in _REG_DEF_MNEMS:
        return False
    dest = _operand_reg_name(insn, 0)
    if not _reg_matches(variable, dest):
        return False
    if mnem == "xor":
        src = _operand_reg_name(insn, 1)
        return _reg_matches(variable, src)
    if mnem in ("inc", "dec", "not", "neg", "bswap", "cdqe", "cqo"):
        return True
    if mnem == "pop":
        return True
    return True


def _classify_reg_use_role(insn: ida_ua.insn_t, variable: str, op_idx: int, ea: int | None = None) -> str:
    mnem = _insn_mnem(insn, ea)
    op = insn.ops[op_idx]
    if op.type in (ida_ua.o_displ, ida_ua.o_phrase):
        base = safe_get_reg_name(op.reg) if op.reg else None
        if _reg_matches(variable, base):
            return "pointer_base"
        index_reg = None
        if op.type == ida_ua.o_phrase and hasattr(op, "specreg") and op.specreg:
            index_reg = safe_get_reg_name(op.specreg)
        if _reg_matches(variable, index_reg):
            return "array_index"
    if mnem in ("cmp", "test"):
        return "compare_operand"
    if mnem == "call":
        return "call_argument"
    if mnem == "lea":
        return "address_operand"
    return "use"


def _trace_value_in_function(
    func_ea: int,
    variable: str,
    direction: str,
) -> TraceValueResult:
    func = idaapi.get_func(func_ea)
    if func is None:
        return {"error": f"No function at {hex(func_ea)}"}

    definitions: list[TraceValueSite] = []
    uses: list[TraceValueSite] = []

    ea = func.start_ea
    while ea < func.end_ea:
        insn = _decode_insn_at(ea)
        if insn is None:
            ea = _next_head(ea, func.end_ea)
            if ea == idaapi.BADADDR:
                break
            continue

        insn_text = disasm_at(ea)
        matched_def = False

        if _is_reg_definition(insn, variable, ea):
            definitions.append({
                "addr": hex(ea),
                "insn": insn_text,
                "source": _describe_operand_source(insn, 0),
            })
            matched_def = True

        for i in range(8):
            if insn.ops[i].type == ida_ua.o_void:
                break
            if insn.ops[i].type != ida_ua.o_reg:
                continue
            reg_name = _operand_reg_name(insn, i)
            if not _reg_matches(variable, reg_name):
                continue
            if matched_def and i == 0:
                continue
            uses.append({
                "addr": hex(ea),
                "insn": insn_text,
                "role": _classify_reg_use_role(insn, variable, i, ea),
            })

        ea = _next_head(ea, func.end_ea)
        if ea == idaapi.BADADDR:
            break

    if direction == "backward":
        definitions = list(reversed(definitions))
        uses = list(reversed(uses))

    return {
        "variable": variable,
        "function": hex(func.start_ea),
        "direction": direction,
        "definitions": definitions,
        "uses": uses,
    }


@tool
@idasync
@tool_timeout(120.0)
def trace_value(
    addr: Annotated[str, "Function address or name"],
    variable: Annotated[str, "Register name to trace (e.g. r13, rax, rdi)"],
    direction: Annotated[str, "'forward' or 'backward' (default: forward)"] = "forward",
) -> TraceValueResult:
    """Trace a register's definitions and uses within a single function.

    Returns instruction-level def-use sites (no cross-function propagation).
    Prefer over chaining disasm + manual scanning for register semantics."""
    if direction not in ("forward", "backward"):
        return {"error": f"direction must be 'forward' or 'backward', got {direction!r}"}

    try:
        ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"error": str(exc)}

    return _trace_value_in_function(ea, variable.strip(), direction)


# ---------------------------------------------------------------------------
# Tool 4 — trace_data_flow
# ---------------------------------------------------------------------------

_MAX_TRACE_NODES = 200
_MAX_TRACE_EDGES = 500


@tool
@idasync
@tool_timeout(120.0)
def trace_data_flow(
    addr: Annotated[str, "Starting address"],
    direction: Annotated[str, "'forward' (xrefs from) or 'backward' (xrefs to)"] = "forward",
    max_depth: Annotated[int, "Maximum traversal depth (default 5, max 20)"] = 5,
) -> TraceDataFlowResult:
    """Follow cross-references from or to an address, automatically traversing
    multiple hops. 'forward' follows xrefs-from, 'backward' follows xrefs-to.
    Returns nodes (with function name, instruction, code/data classification) and
    edges. Do not use for call graph traversal — use callgraph for that."""
    if direction not in ("forward", "backward"):
        return {"error": f"direction must be 'forward' or 'backward', got {direction!r}"}

    try:
        start_ea = _resolve_addr(addr)
    except IDAError as exc:
        return {"error": str(exc)}

    if max_depth < 1:
        max_depth = 1
    if max_depth > 20:
        max_depth = 20

    visited: set[int] = set()
    nodes: list[TraceDataFlowNode] = []
    edges: list[TraceDataFlowEdge] = []
    depth_reached = 0

    queue: deque[tuple[int, int]] = deque()
    queue.append((start_ea, 0))
    visited.add(start_ea)

    while queue and len(nodes) < _MAX_TRACE_NODES:
        ea, depth = queue.popleft()
        if depth > max_depth:
            continue
        if depth > depth_reached:
            depth_reached = depth

        func = idaapi.get_func(ea)
        func_name = idaapi.get_func_name(ea) if func else None
        insn_text = idc.GetDisasm(ea) if idaapi.is_loaded(ea) else None

        name_at = idaapi.get_name(ea)
        node_type = "code"
        if func is None and idaapi.is_loaded(ea):
            node_type = "data"

        nodes.append({
            "addr": hex(ea),
            "func": func_name,
            "instruction": insn_text,
            "type": node_type,
            "name": name_at if name_at else None,
            "depth": depth,
        })

        if depth >= max_depth:
            continue

        if direction == "forward":
            xrefs = list(idautils.XrefsFrom(ea, 0))
        else:
            xrefs = list(idautils.XrefsTo(ea, 0))

        for xref in xrefs:
            if len(edges) >= _MAX_TRACE_EDGES:
                break
            target = xref.to if direction == "forward" else xref.frm
            xtype = "code" if xref.iscode else "data"

            edges.append({
                "from": hex(ea) if direction == "forward" else hex(target),
                "to": hex(target) if direction == "forward" else hex(ea),
                "type": xtype,
            })

            if target not in visited and len(nodes) + len(queue) < _MAX_TRACE_NODES:
                visited.add(target)
                queue.append((target, depth + 1))

    return {
        "start": hex(start_ea),
        "direction": direction,
        "depth_reached": depth_reached,
        "nodes": nodes,
        "edges": edges,
    }
