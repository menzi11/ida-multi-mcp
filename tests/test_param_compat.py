"""Tests for LLM param alias normalization."""

from ida_multi_mcp.param_compat import normalize_tool_params


class TestDisasmAliases:
    def test_end_alias(self):
        out = normalize_tool_params(
            "disasm",
            {"addr": "0x1000", "end": "0x1100", "instance_id": "abc"},
        )
        assert out == {"addr": "0x1000", "end": "0x1100", "instance_id": "abc"}

    def test_end_ea_to_end(self):
        out = normalize_tool_params(
            "disasm",
            {"addr": "0x1000", "end_ea": "0x1100"},
        )
        assert out == {"addr": "0x1000", "end": "0x1100"}

    def test_start_to_addr(self):
        out = normalize_tool_params(
            "disasm",
            {"start": "0x1000", "end": "0x1100"},
        )
        assert out == {"addr": "0x1000", "end": "0x1100"}

    def test_count_to_max_instructions(self):
        out = normalize_tool_params(
            "disasm",
            {"addr": "0x1000", "count": 80},
        )
        assert out == {"addr": "0x1000", "max_instructions": 80}

    def test_start_and_count(self):
        out = normalize_tool_params(
            "disasm",
            {"start": "0x180529700", "count": 80, "instance_id": "x"},
        )
        assert out == {
            "addr": "0x180529700",
            "max_instructions": 80,
            "instance_id": "x",
        }

    def test_canonical_wins_when_both_present(self):
        out = normalize_tool_params(
            "disasm",
            {"addr": "0x2000", "start": "0x1000", "end": "0x1100", "end_ea": "0x1200"},
        )
        assert out == {"addr": "0x2000", "end": "0x1100"}

    def test_unknown_tool_unchanged(self):
        params = {"addr": "0x1", "end": "0x2"}
        assert normalize_tool_params("decompile", params) is params
