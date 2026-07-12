"""Pure tests for call_path BFS."""

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
def path_helpers(monkeypatch):
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
    ):
        setattr(utils, attr, MagicMock())
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    return importlib.import_module("ida_multi_mcp.ida_mcp.api_composite")


class TestFindCallPaths:
    def test_finds_multiple_paths(self, path_helpers):
        graph = {
            0x1000: [0x2000],
            0x2000: [0x3000, 0x4000],
            0x3000: [0x5000],
            0x4000: [0x5000],
            0x5000: [],
        }

        paths = path_helpers._find_call_paths(
            0x1000, 0x5000, max_depth=5, max_paths=10,
            get_internal_callees=lambda ea: graph.get(ea, []),
        )
        assert len(paths) == 2
        assert paths[0][0] == 0x1000 and paths[0][-1] == 0x5000

    def test_respects_max_paths(self, path_helpers):
        graph = {0x1000: [0x2000, 0x2001], 0x2000: [0x3000], 0x2001: [0x3000], 0x3000: []}
        paths = path_helpers._find_call_paths(
            0x1000, 0x3000, max_depth=5, max_paths=1,
            get_internal_callees=lambda ea: graph.get(ea, []),
        )
        assert len(paths) == 1
