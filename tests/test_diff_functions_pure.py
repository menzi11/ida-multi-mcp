"""Pure tests for diff_functions helpers."""

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
def diff_helpers(monkeypatch):
    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)

    for name in (
        "ida_hexrays", "ida_typeinf", "ida_ua", "ida_bytes", "idaapi", "idautils", "idc",
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

    return importlib.import_module("ida_multi_mcp.ida_mcp.api_composite")


class TestDiffConstants:
    def test_symmetric_diff(self, diff_helpers):
        raw_a = [{"decimal": 0x100}, {"decimal": 0x200}]
        raw_b = [{"decimal": 0x200}, {"decimal": 0x300}]
        diff = diff_helpers._diff_constant_sets(raw_a, raw_b)
        assert diff["only_in_a"] == ["0x100"]
        assert diff["only_in_b"] == ["0x300"]
        assert diff["common"] == ["0x200"]


class TestDiffPseudocode:
    def test_detects_change(self, diff_helpers):
        changed, text = diff_helpers._diff_pseudocode("a\n", "b\n", "f", "g")
        assert changed
        assert "--- f" in text or "+++ g" in text

    def test_identical(self, diff_helpers):
        changed, text = diff_helpers._diff_pseudocode("same", "same", "f", "g")
        assert not changed
        assert text == ""
