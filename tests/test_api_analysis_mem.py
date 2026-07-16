"""Pure tests for memory-access matching helpers in api_analysis."""

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
def analysis_mem_helpers(monkeypatch):
    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)

    ida_ua = MagicMock()
    ida_ua.o_void = 0
    ida_ua.o_mem = 1
    ida_ua.o_displ = 2
    ida_ua.o_phrase = 3
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)

    for name in (
        "ida_hexrays", "ida_lines", "ida_funcs", "idaapi", "idautils",
        "ida_typeinf", "ida_nalt", "ida_bytes", "ida_ida", "ida_entry",
        "ida_idaapi", "ida_xref", "ida_name", "idc",
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
        "parse_address", "unwrap_bin_search_result", "normalize_list_input", "normalize_dict_list", "paginate",
        "get_function", "get_prototype", "get_stack_frame_variables_internal",
        "decompile_function_safe", "decompile_function_result", "compact_whitespace", "get_assembly_lines",
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
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    mod = importlib.import_module("ida_multi_mcp.ida_mcp.api_analysis")
    return mod


class TestMemTargetMatches:
    def test_absolute_range(self, analysis_mem_helpers):
        mem = {"abs_addr": 0x180B0004, "base_reg": None, "offset": 0}
        assert analysis_mem_helpers._mem_target_matches(
            mem, abs_start=0x180B0000, abs_size=8,
            base_reg=None, struct_offset=None,
        )
        assert not analysis_mem_helpers._mem_target_matches(
            mem, abs_start=0x180B0010, abs_size=4,
            base_reg=None, struct_offset=None,
        )

    def test_struct_offset(self, analysis_mem_helpers):
        mem = {"abs_addr": None, "base_reg": "RDI", "offset": 0x1C}
        assert analysis_mem_helpers._mem_target_matches(
            mem, abs_start=None, abs_size=None,
            base_reg="rdi", struct_offset=0x1C,
        )
        assert not analysis_mem_helpers._mem_target_matches(
            mem, abs_start=None, abs_size=None,
            base_reg="rsi", struct_offset=0x1C,
        )


class TestAccessFilter:
    def test_write_includes_read_write(self, analysis_mem_helpers):
        assert analysis_mem_helpers._access_matches_filter("read_write", "write")
        assert analysis_mem_helpers._access_matches_filter("read", "read")
        assert not analysis_mem_helpers._access_matches_filter("read", "write")
