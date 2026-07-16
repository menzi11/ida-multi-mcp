"""Pure tests for decompile Hex-Rays failure → asm fallback."""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
IDA_MCP_ROOT = REPO_ROOT / "src" / "ida_multi_mcp" / "ida_mcp"


@pytest.fixture
def decompile_mod(monkeypatch):
    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)

    for name in (
        "ida_hexrays", "ida_lines", "ida_funcs", "idaapi", "idautils",
        "ida_typeinf", "ida_nalt", "ida_bytes", "ida_ida", "ida_entry",
        "ida_idaapi", "ida_xref", "ida_name", "ida_ua", "idc",
    ):
        monkeypatch.setitem(sys.modules, name, MagicMock())

    rpc = types.ModuleType("ida_multi_mcp.ida_mcp.rpc")
    rpc.tool = lambda func: func
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.rpc", rpc)

    sync = types.ModuleType("ida_multi_mcp.ida_mcp.sync")
    sync.idasync = lambda func: func
    sync.tool_timeout = lambda seconds: (lambda func: func)
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.sync", sync)

    utils = types.ModuleType("ida_multi_mcp.ida_mcp.utils")
    for attr in (
        "parse_address", "unwrap_bin_search_result", "normalize_list_input",
        "normalize_dict_list", "paginate", "get_function", "get_prototype",
        "get_stack_frame_variables_internal", "decompile_function_safe",
        "decompile_function_result", "compact_whitespace", "get_assembly_lines",
        "safe_get_reg_name", "insn_mnem", "disasm_at",
        "get_all_xrefs", "get_all_comments", "extract_function_strings",
    ):
        setattr(utils, attr, MagicMock())
    utils.Function = dict
    utils.Argument = dict
    utils.DisassemblyFunction = dict
    utils.Xref = dict
    utils.BasicBlock = dict
    utils.StructFieldQuery = dict
    utils.InsnPattern = dict
    utils.parse_address.side_effect = lambda v: int(v, 0) if isinstance(v, str) else v
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    mod = importlib.import_module("ida_multi_mcp.ida_mcp.api_analysis")
    return mod, utils


class TestDecompileFallback:
    def test_hexrays_fail_returns_asm_not_hard_error(self, decompile_mod):
        mod, utils = decompile_mod
        utils.decompile_function_result.return_value = {
            "code": None,
            "error": "Decompilation failed at 0x1000: MERR_BADFRAME",
            "hexrays_merr": "MERR_BADFRAME",
            "hexrays_code": -13,
            "errea": "0x1000",
        }
        utils.get_assembly_lines.return_value = "sub_1000 (.text @ 0x1000):\n1000  retn"

        out = mod.decompile("0x1000")
        assert out["code"] is None
        assert out["error"] is None
        assert out["fallback"] == "disasm"
        assert out["asm"].startswith("sub_1000")
        assert out["hexrays_merr"] == "MERR_BADFRAME"
        assert "MERR_BADFRAME" in out["warning"]

    def test_success_returns_code(self, decompile_mod):
        mod, utils = decompile_mod
        utils.decompile_function_result.return_value = {
            "code": "void sub_1000() {}",
            "error": None,
            "hexrays_merr": None,
            "hexrays_code": None,
            "errea": None,
        }
        out = mod.decompile("0x1000")
        assert out["code"] == "void sub_1000() {}"
        assert out["error"] is None
        assert "asm" not in out
