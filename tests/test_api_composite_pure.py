"""Pure tests for api_composite helpers (IDA modules stubbed)."""

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
def composite_helpers(monkeypatch):
    """Load api_composite with IDA dependencies stubbed."""
    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)

    for name in (
        "ida_hexrays",
        "ida_typeinf",
        "ida_ua",
        "ida_bytes",
        "idaapi",
        "idautils",
        "idc",
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
    utils.decompile_function_safe = MagicMock()
    utils.extract_function_constants = MagicMock()
    utils.extract_function_strings = MagicMock()
    utils.get_all_comments = MagicMock()
    utils.get_all_xrefs = MagicMock()
    utils.get_assembly_lines = MagicMock()
    utils.get_callees = MagicMock()
    utils.get_callers = MagicMock()
    utils.get_prototype = MagicMock()
    utils.normalize_list_input = lambda x: x if isinstance(x, list) else [x]
    utils.parse_address = int
    utils.safe_get_reg_name = MagicMock()
    utils.insn_mnem = MagicMock(return_value="")
    utils.disasm_at = MagicMock(return_value="")
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    mod = importlib.import_module("ida_multi_mcp.ida_mcp.api_composite")
    return mod


class TestFilterConstants:
    def test_uses_decimal_not_hex_string(self, composite_helpers):
        raw = [
            {"addr": "0x1000", "value": "0xdeadbeef", "decimal": 0xDEADBEEF},
            {"addr": "0x1004", "value": "0x1", "decimal": 1},
            {"addr": "0x1008", "value": "0x50", "decimal": 0x50},
        ]
        out = composite_helpers._filter_constants(raw)
        assert len(out) == 1
        assert out[0]["decimal"] == 0xDEADBEEF
        assert out[0]["value"] == "0xdeadbeef"

    def test_empty_when_all_boring(self, composite_helpers):
        raw = [{"addr": "0x1", "value": "0x1", "decimal": 1}]
        assert composite_helpers._filter_constants(raw) == []


class TestCapDecompile:
    def test_default_cap_truncates(self, composite_helpers):
        code = "\n".join(f"line{i}" for i in range(800))
        truncated, truncated_at, total = composite_helpers._cap_decompile(code, 600)
        assert truncated is not None
        assert truncated.count("\n") == 599
        assert truncated_at == 800
        assert total == 800

    def test_zero_means_no_truncation(self, composite_helpers):
        code = "\n".join(f"line{i}" for i in range(1200))
        result, truncated_at, total = composite_helpers._cap_decompile(code, 0)
        assert result == code
        assert truncated_at is None
        assert total == 1200

    def test_short_code_unchanged(self, composite_helpers):
        code = "int main() { return 0; }"
        result, truncated_at, total = composite_helpers._cap_decompile(code, 600)
        assert result == code
        assert truncated_at is None
        assert total == 1


class TestPlanDecompileTree:
    def test_bfs_depth_and_dedup(self, composite_helpers):
        # root -> A, B; A -> shared; B -> shared
        graph = {
            0x1000: [0x2000, 0x3000],
            0x2000: [0x4000],
            0x3000: [0x4000],
            0x4000: [],
        }

        def callees(ea: int) -> list[int]:
            return graph.get(ea, [])

        discovered, edges, deduped = composite_helpers._plan_decompile_tree(
            0x1000, 2, callees
        )
        addrs = [ea for ea, _ in discovered]
        assert addrs == [0x1000, 0x2000, 0x3000, 0x4000]
        assert deduped == 1  # 0x4000 enqueued from both 0x2000 and 0x3000
        assert (0x1000, 0x2000) in edges
        assert (0x2000, 0x4000) in edges
        assert (0x3000, 0x4000) in edges

    def test_depth_zero_root_only(self, composite_helpers):
        discovered, edges, _ = composite_helpers._plan_decompile_tree(
            0x1000, 0, lambda _ea: [0x2000]
        )
        assert discovered == [(0x1000, 0)]
        assert edges == []

    def test_shared_callee_deduped_in_queue(self, composite_helpers):
        graph = {0x1000: [0x2000, 0x2000]}

        discovered, _, deduped = composite_helpers._plan_decompile_tree(
            0x1000, 1, lambda ea: graph.get(ea, [])
        )
        assert [ea for ea, _ in discovered] == [0x1000, 0x2000]
        assert deduped == 1
