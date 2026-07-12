"""Tests for safe_get_reg_name helper."""

import importlib
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
IDA_MCP_ROOT = REPO_ROOT / "src" / "ida_multi_mcp" / "ida_mcp"


@pytest.fixture
def safe_get_reg_name(monkeypatch):
    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp.utils" or name.startswith("ida_multi_mcp.ida_mcp.utils."):
            sys.modules.pop(name, None)

    for mod in (
        "ida_funcs", "ida_hexrays", "ida_bytes", "ida_kernwin", "ida_nalt",
        "ida_typeinf", "idaapi", "idautils", "idc",
    ):
        monkeypatch.setitem(sys.modules, mod, MagicMock())

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)

    sync = types.ModuleType("ida_multi_mcp.ida_mcp.sync")
    sync.IDAError = Exception
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.sync", sync)

    mod = importlib.import_module("ida_multi_mcp.ida_mcp.utils")
    return mod.safe_get_reg_name, mod


def test_safe_get_reg_name_tries_size_fallback(safe_get_reg_name):
    fn, mod = safe_get_reg_name
    calls: list[tuple] = []

    def fake_get_reg_name(*args):
        calls.append(args)
        if len(args) == 2:
            return "r13d"
        raise TypeError("missing size")

    mod.idaapi.get_reg_name = fake_get_reg_name
    assert fn(13) == "r13d"
    assert len(calls) >= 2


def test_safe_get_reg_name_decodes_bytes(safe_get_reg_name):
    fn, mod = safe_get_reg_name
    mod.idaapi.get_reg_name = lambda reg: b"rax"
    assert fn(1) == "rax"


def test_safe_get_reg_name_empty_reg(safe_get_reg_name):
    fn, _mod = safe_get_reg_name
    assert fn(0) is None
