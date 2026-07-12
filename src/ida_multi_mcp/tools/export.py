"""Server-side session export orchestration."""

from __future__ import annotations

import json
import os
import re
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..router import InstanceRouter

_router: "InstanceRouter | None" = None

EXPORT_SESSION_MAX_FUNCTIONS = 5000

EXPORT_SESSION_SCHEMA = {
    "name": "export_session",
    "description": (
        "Export IDA session artifacts to a local directory: named function "
        "pseudocode (.c files), struct index, and enum definitions. "
        "One-click static evidence bundle for git diff / handoff docs."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "output_dir": {
                "type": "string",
                "description": "Directory to write export files (within CWD by default)",
            },
            "instance_id": {
                "type": "string",
                "description": "Target IDA instance ID (required)",
            },
            "named_only": {
                "type": "boolean",
                "description": "Export only non-sub_* named functions (default: true)",
            },
            "include_structs": {
                "type": "boolean",
                "description": "Write structs/index.json (default: true)",
            },
            "include_enums": {
                "type": "boolean",
                "description": "Write enums/enums.json (default: true)",
            },
            "allow_outside_cwd": {
                "type": "boolean",
                "description": "Permit output_dir outside CWD (default: false)",
            },
        },
        "required": ["output_dir", "instance_id"],
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "output_dir": {"type": "string"},
            "manifest_path": {"type": "string"},
            "functions_exported": {"type": "integer"},
            "functions_failed": {"type": "integer"},
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


def _validate_output_dir(output_dir: str, allow_outside_cwd: bool) -> str | dict:
    if ".." in os.path.normpath(output_dir).split(os.sep):
        return {"error": "output_dir must not contain '..' path components"}
    resolved = os.path.realpath(output_dir)
    if not allow_outside_cwd:
        cwd = os.path.realpath(os.getcwd())
        if resolved != cwd and not resolved.startswith(cwd + os.sep):
            return {
                "error": (
                    "output_dir must be within the current working directory. "
                    "Pass allow_outside_cwd=true to write elsewhere."
                ),
                "cwd": cwd,
            }
    return resolved


def _call_tool(router: "InstanceRouter", name: str, arguments: dict) -> Any:
    raw = router.route_request("tools/call", {"name": name, "arguments": arguments})
    if "error" in raw:
        return raw
    try:
        content = raw.get("content", [])
        if content:
            return json.loads(content[0]["text"])
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        pass
    return raw


def _is_named_function(name: str) -> bool:
    if not name or name.startswith("sub_") or name == "<unnamed>":
        return False
    return True


def _safe_filename(name: str, addr: str) -> str:
    safe = re.sub(r'[<>:"/\\|?*]', "_", name)
    safe = safe.replace("..", "_")
    addr_suffix = re.sub(r"[^0-9A-Fa-fx]", "_", str(addr))
    return f"{safe}_{addr_suffix}.c"


def export_session(arguments: dict[str, Any]) -> dict[str, Any]:
    instance_id = arguments.get("instance_id")
    if not instance_id:
        return {"error": "Missing required parameter 'instance_id'."}

    router = _get_router()

    output_dir_arg = arguments.get("output_dir", ".")
    named_only = arguments.get("named_only", True)
    include_structs = arguments.get("include_structs", True)
    include_enums = arguments.get("include_enums", True)
    allow_outside_cwd = arguments.get("allow_outside_cwd", False)

    validated = _validate_output_dir(output_dir_arg, allow_outside_cwd)
    if isinstance(validated, dict):
        return validated
    output_dir = validated

    func_dir = os.path.join(output_dir, "functions")
    os.makedirs(func_dir, exist_ok=True)

    addrs: list[str] = []
    addr_names: dict[str, str] = {}
    offset = 0
    page_size = 500
    while True:
        page = _call_tool(router, "list_funcs", {
            "queries": json.dumps({"count": page_size, "offset": offset}),
            "instance_id": instance_id,
        })
        if isinstance(page, dict) and "error" in page:
            return {"error": f"list_funcs failed: {page['error']}"}
        if not isinstance(page, list) or not page:
            break
        data = page[0].get("data", [])
        if not data:
            break
        for fn in data:
            addr = fn.get("addr")
            name = fn.get("name", "")
            if not addr:
                continue
            if named_only and not _is_named_function(name):
                continue
            addrs.append(addr)
            addr_names[addr] = name
        next_offset = page[0].get("next_offset")
        if next_offset is None or len(data) < page_size:
            break
        offset = next_offset

    if len(addrs) > EXPORT_SESSION_MAX_FUNCTIONS:
        return {
            "error": (
                f"Too many functions ({len(addrs)}). "
                f"Max {EXPORT_SESSION_MAX_FUNCTIONS}. Set named_only=true or filter first."
            ),
            "function_count": len(addrs),
        }

    exported = 0
    failed = 0
    files_written: list[str] = []

    for addr in addrs:
        decomp = _call_tool(router, "decompile", {
            "addr": addr,
            "instance_id": instance_id,
        })
        if not isinstance(decomp, dict):
            failed += 1
            continue
        code = decomp.get("code")
        if not code:
            failed += 1
            continue
        name = addr_names.get(addr) or decomp.get("name") or addr
        filename = _safe_filename(name, addr)
        filepath = os.path.join(func_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"// {name} @ {addr}\n")
            f.write(code)
            f.write("\n")
        files_written.append(f"functions/{filename}")
        exported += 1

    struct_count = 0
    if include_structs:
        structs = _call_tool(router, "search_structs", {
            "filter": "",
            "instance_id": instance_id,
        })
        structs_dir = os.path.join(output_dir, "structs")
        os.makedirs(structs_dir, exist_ok=True)
        index_path = os.path.join(structs_dir, "index.json")
        if isinstance(structs, list):
            struct_count = len(structs)
            with open(index_path, "w", encoding="utf-8") as f:
                json.dump(structs, f, indent=2, ensure_ascii=False)
                f.write("\n")
            files_written.append("structs/index.json")

    enum_count = 0
    if include_enums:
        enums = _call_tool(router, "list_enums", {
            "instance_id": instance_id,
        })
        enums_dir = os.path.join(output_dir, "enums")
        os.makedirs(enums_dir, exist_ok=True)
        enums_path = os.path.join(enums_dir, "enums.json")
        if isinstance(enums, list):
            enum_count = len(enums)
            with open(enums_path, "w", encoding="utf-8") as f:
                json.dump(enums, f, indent=2, ensure_ascii=False)
                f.write("\n")
            files_written.append("enums/enums.json")

    manifest = {
        "functions_exported": exported,
        "functions_failed": failed,
        "structs_indexed": struct_count,
        "enums_exported": enum_count,
        "named_only": named_only,
        "files": files_written[:100],
        "files_total": len(files_written),
    }
    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")

    return {
        "output_dir": output_dir,
        "manifest_path": manifest_path,
        "functions_exported": exported,
        "functions_failed": failed,
        "structs_indexed": struct_count,
        "enums_exported": enum_count,
        "files_total": len(files_written) + 1,
    }
