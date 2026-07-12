"""Pure tests for trace_value register helpers."""

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
def trace_helpers(monkeypatch):
    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)

    ida_ua = MagicMock()
    ida_ua.o_void = 0
    ida_ua.o_reg = 1
    ida_ua.o_imm = 2
    ida_ua.o_mem = 3
    ida_ua.o_displ = 4
    ida_ua.o_phrase = 5
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)

    for name in (
        "ida_hexrays", "ida_typeinf", "ida_bytes", "idaapi", "idautils", "idc",
    ):
        monkeypatch.setitem(sys.modules, name, MagicMock())

    rpc = types.ModuleType("ida_multi_mcp.ida_mcp.rpc")
    rpc.tool = lambda func: func
    rpc.unsafe = lambda func: func
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.rpc", rpc)

    sync = types.ModuleType("ida_multi_mcp.ida_mcp.sync")

    class IDAError(Exception):
        pass

    sync.IDAError = IDAError
    sync.idasync = lambda func: func
    sync.tool_timeout = lambda seconds: (lambda func: func)
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.sync", sync)

    utils = types.ModuleType("ida_multi_mcp.ida_mcp.utils")
    for attr in (
        "decompile_function_safe", "extract_function_constants", "extract_function_strings",
        "get_all_comments", "get_all_xrefs", "get_assembly_lines", "get_callees",
        "get_callers", "get_prototype", "normalize_list_input", "parse_address",
        "safe_get_reg_name", "insn_mnem", "disasm_at",
    ):
        setattr(utils, attr, MagicMock())
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    mod = importlib.import_module("ida_multi_mcp.ida_mcp.api_composite")
    return mod


class TestRegMatches:
    def test_r13_family(self, trace_helpers):
        assert trace_helpers._reg_matches("r13", "r13d")
        assert trace_helpers._reg_matches("r13d", "r13w")
        assert not trace_helpers._reg_matches("r13", "r14")

    def test_rax_family(self, trace_helpers):
        assert trace_helpers._reg_matches("rax", "eax")
        assert trace_helpers._reg_matches("al", "rax")
