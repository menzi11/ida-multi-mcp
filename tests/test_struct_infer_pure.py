"""Pure tests for struct_infer field aggregation."""

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
def struct_helpers(monkeypatch):
    for name in list(sys.modules):
        if name == "ida_multi_mcp.ida_mcp" or name.startswith("ida_multi_mcp.ida_mcp."):
            sys.modules.pop(name, None)

    pkg = types.ModuleType("ida_multi_mcp.ida_mcp")
    pkg.__path__ = [str(IDA_MCP_ROOT)]
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp", pkg)

    ida_ua = MagicMock()
    ida_ua.o_void = 0
    ida_ua.o_displ = 4
    ida_ua.o_phrase = 5
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)

    for name in (
        "ida_typeinf", "ida_hexrays", "ida_nalt", "ida_bytes", "ida_frame",
        "ida_ida", "idaapi", "idautils", "idc",
    ):
        monkeypatch.setitem(sys.modules, name, MagicMock())

    rpc = types.ModuleType("ida_multi_mcp.ida_mcp.rpc")
    rpc.tool = lambda func: func
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.rpc", rpc)

    sync = types.ModuleType("ida_multi_mcp.ida_mcp.sync")
    sync.idasync = lambda func: func
    sync.tool_timeout = lambda seconds: (lambda func: func)
    sync.ida_major = 9
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.sync", sync)

    utils = types.ModuleType("ida_multi_mcp.ida_mcp.utils")
    for attr in (
        "normalize_list_input", "normalize_dict_list", "parse_address",
        "get_type_by_name", "parse_decls_ctypes", "my_modifier_t",
        "read_bytes_bss_safe", "read_int_bss_safe",
        "safe_get_reg_name", "insn_mnem", "disasm_at",
    ):
        setattr(utils, attr, MagicMock())
    utils.StructureMember = dict
    utils.StructureDefinition = dict
    utils.StructRead = dict
    utils.TypeEdit = dict
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.ida_mcp.utils", utils)

    mod = importlib.import_module("ida_multi_mcp.ida_mcp.api_types")
    return mod


class TestStructInferHelpers:
    def test_reg_name_matches_case_insensitive(self, struct_helpers):
        assert struct_helpers._reg_name_matches("rcx", "RCX")
        assert not struct_helpers._reg_name_matches("rcx", "rdx")

    def test_extract_base_disp(self, struct_helpers):
        import ida_ua

        struct_helpers.safe_get_reg_name = lambda reg: "rcx" if reg else None
        struct_helpers.insn_mnem = lambda insn, ea=None: "mov"

        insn = MagicMock()
        op = MagicMock()
        op.type = ida_ua.o_displ
        op.reg = 1
        op.addr = 0x3B8
        insn.ops = [op] + [MagicMock(type=ida_ua.o_void)] * 7

        hits = struct_helpers._extract_base_disp_accesses(insn, "rcx")
        assert hits == [(0x3B8, "write")]
