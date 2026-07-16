"""Tests for version_info and server_info."""

import json

import pytest

from ida_multi_mcp import version_info
from ida_multi_mcp.tools import management


class TestVersionInfo:
    def test_schema_metadata_has_count_and_fingerprint(self):
        meta = version_info.schema_metadata()
        assert meta["schema_tools_count"] >= 80
        assert meta["schema_fingerprint"]
        assert len(meta["schema_fingerprint"]) == 12

    def test_build_id_stable_format(self):
        bid = version_info.build_id("0.1.0", "abc1234", "deadbeef1234")
        assert bid == "0.1.0+abc1234+deadbeef1234"

    def test_capability_map_reflects_registration(self):
        caps = version_info.capability_map({"batch_query", "decompile_tree"})
        assert caps["batch_query"] is True
        assert caps["decompile_tree"] is True
        assert caps["trace_value"] is False

    def test_package_build_router_role(self):
        payload = version_info.package_build(role="router", uptime_sec=1.5)
        assert payload["role"] == "router"
        assert payload["package"] == "ida-multi-mcp"
        assert payload["version"]
        assert payload["build_id"]
        assert payload["python_executable"]
        assert payload["uptime_sec"] == 1.5


class TestServerInfoTool:
    def test_server_info_without_instances(self, tmp_path):
        from ida_multi_mcp.registry import InstanceRegistry

        registry = InstanceRegistry(str(tmp_path / "inst.json"))
        management.set_registry(registry)
        tool_cache = {
            "server_info": {},
            "batch_query": {},
            "decompile_tree": {},
        }
        result = management.server_info(tool_cache)
        assert result["role"] == "router"
        assert result["tools_registered"] == 3
        assert result["instances_connected"] == 0
        assert result["capabilities"]["batch_query"] is True
        assert result["capabilities"]["trace_value"] is False
        assert result["schema_tools_count"] >= 80
        assert "max_output_chars" in result
        assert isinstance(result["max_output_chars"], int)

    def test_server_info_json_serializable(self, tmp_path):
        from ida_multi_mcp.registry import InstanceRegistry

        registry = InstanceRegistry(str(tmp_path / "inst.json"))
        management.set_registry(registry)
        result = management.server_info({})
        json.dumps(result)
