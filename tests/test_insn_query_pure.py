"""Pure test for insn_query wiring to _scan_insn_ranges."""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
IDA_MCP_ROOT = REPO_ROOT / "src" / "ida_multi_mcp" / "ida_mcp"


@pytest.fixture
def insn_query_mod(monkeypatch):
    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)

    ida_ua = MagicMock()
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)

    for name in (
        "ida_hexrays", "ida_lines", "ida_funcs", "idaapi", "idautils",
        "ida_typeinf", "ida_nalt", "ida_bytes", "ida_ida", "ida_entry",
        "ida_idaapi", "ida_xref", "ida_name", "idc",
    ):
        monkeypatch.setitem(sys.modules, name, MagicMock())
    sys.modules["idaapi"].is_loaded.return_value = True
    sys.modules["idc"].GetDisasm.return_value = "push rax"

    rpc = types.ModuleType("ida_multi_mcp.ida_mcp.rpc")
    rpc.tool = lambda func: func
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.rpc", rpc)

    sync = types.ModuleType("ida_multi_mcp.ida_mcp.sync")
    sync.idasync = lambda func: func
    sync.tool_timeout = lambda seconds: (lambda func: func)
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.sync", sync)

    utils = types.ModuleType("ida_multi_mcp.ida_mcp.utils")
    utils.normalize_dict_list = (
        lambda value, str_to_dict=None, max_items=500:
        value if isinstance(value, list) else [value if not isinstance(value, str) else str_to_dict(value)]
    )
    for attr in (
        "parse_address", "unwrap_bin_search_result", "normalize_list_input", "paginate",
        "get_function", "get_prototype", "get_stack_frame_variables_internal",
        "decompile_function_safe", "decompile_function_result", "compact_whitespace", "get_assembly_lines",
        "safe_get_reg_name", "insn_mnem", "disasm_at",
        "get_all_xrefs", "get_all_comments", "extract_function_strings",
    ):
        setattr(utils, attr, MagicMock())
    utils.get_function.return_value = {"addr": "0x1000", "name": "sub_1000"}
    utils.compact_whitespace.return_value = "push rax"
    utils.Function = dict
    utils.Argument = dict
    utils.DisassemblyFunction = dict
    utils.Xref = dict
    utils.BasicBlock = dict
    utils.StructFieldQuery = dict
    utils.InsnPattern = dict
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    mod = importlib.import_module("ida_multi_mcp.ida_mcp.api_analysis")
    return mod


class TestInsnQuery:
    def test_passes_limit_not_count(self, insn_query_mod):
        with patch.object(insn_query_mod, "_resolve_insn_scan_ranges", return_value=([(0x1000, 0x2000)], None)), \
             patch.object(insn_query_mod, "_scan_insn_ranges", return_value=(["0x1000"], False, 1, False, None)) as scan:
            out = insn_query_mod.insn_query({"mnem": "push", "func": "0x1000", "count": 2})
            scan.assert_called_once()
            kwargs = scan.call_args.kwargs
            assert "count" not in kwargs
            assert kwargs["limit"] == 2
            assert out[0]["count"] == 1
            assert "error" not in out[0]
