#!/usr/bin/env python3
"""Generate ida_tool_schemas.json from @tool function signatures.

Runs without IDA Pro by stubbing ida_* modules and importing the tool registry.
Usage:
    python scripts/generate_tool_schemas.py          # write schemas
    python scripts/generate_tool_schemas.py --check  # exit 1 if drift
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
IDA_MCP_ROOT = SRC_ROOT / "ida_multi_mcp" / "ida_mcp"
OUTPUT_PATH = SRC_ROOT / "ida_multi_mcp" / "ida_tool_schemas.json"

_IDA_MODULE_NAMES = [
    "ida_auto",
    "ida_bytes",
    "ida_dbg",
    "ida_dirtree",
    "ida_entry",
    "ida_frame",
    "ida_funcs",
    "ida_hexrays",
    "ida_ida",
    "ida_idaapi",
    "ida_idd",
    "ida_kernwin",
    "ida_lines",
    "ida_loader",
    "ida_name",
    "ida_nalt",
    "ida_segment",
    "ida_typeinf",
    "ida_ua",
    "ida_xref",
    "idaapi",
    "idautils",
    "idc",
]


def _install_ida_stubs() -> None:
    """Replace ida_* modules with MagicMock stubs for headless import."""
    src = str(SRC_ROOT)
    if src not in sys.path:
        sys.path.insert(0, src)

    for name in _IDA_MODULE_NAMES:
        mock = MagicMock()
        sys.modules[name] = mock

    idaapi = sys.modules["idaapi"]
    idaapi.BADADDR = -1
    idaapi.get_kernel_version.return_value = "9.0"
    idaapi.plugin_t = type("plugin_t", (), {})
    idaapi.IDB_Hooks = type("IDB_Hooks", (), {})
    idaapi.UI_Hooks = type("UI_Hooks", (), {})

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    sys.modules["ida_multi_mcp.ida_mcp"] = pkg


_API_MODULES = (
    "rpc",
    "sync",
    "utils",
    "api_core",
    "api_analysis",
    "api_memory",
    "api_types",
    "api_modify",
    "api_stack",
    "api_debug",
    "api_python",
    "api_resources",
    "api_survey",
    "api_composite",
    "api_similarity",
)


def _load_tool_registry():
    """Import all api_* modules so @tool decorators register on MCP_SERVER."""
    _install_ida_stubs()
    for mod_name in _API_MODULES:
        importlib.import_module(f"ida_multi_mcp.ida_mcp.{mod_name}")
    from ida_multi_mcp.ida_mcp.rpc import MCP_SERVER

    return MCP_SERVER


def generate_schemas() -> list[dict]:
    server = _load_tool_registry()
    schemas = []
    for func_name in sorted(server.tools.methods):
        func = server.tools.methods[func_name]
        schemas.append(server._generate_tool_schema(func_name, func))
    return schemas


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if generated schemas differ from ida_tool_schemas.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_PATH,
        help=f"Output path (default: {OUTPUT_PATH})",
    )
    args = parser.parse_args()

    generated = generate_schemas()
    text = json.dumps(generated, indent=2, ensure_ascii=False) + "\n"

    if args.check:
        if not args.output.is_file():
            print(f"Missing {args.output}", file=sys.stderr)
            return 1
        existing = args.output.read_text(encoding="utf-8")
        if existing != text:
            print(
                f"Schema drift: regenerate with python scripts/generate_tool_schemas.py "
                f"({len(json.loads(existing))} tools on disk, {len(generated)} generated)",
                file=sys.stderr,
            )
            return 1
        print(f"Schemas up to date ({len(generated)} tools)")
        return 0

    args.output.write_text(text, encoding="utf-8")
    print(f"Wrote {len(generated)} tool schemas to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
