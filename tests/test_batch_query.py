"""Tests for server-side batch_query."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ida_multi_mcp.tools import batch


@pytest.fixture(autouse=True)
def reset_router():
    batch.set_router(None)
    yield
    batch.set_router(None)


class TestBatchQuery:
    def test_rejects_non_whitelist_tool(self):
        router = MagicMock()
        batch.set_router(router)
        result = batch.batch_query({
            "instance_id": "inst1",
            "queries": [{"tool": "patch", "addr": "0x1000", "data": "90"}],
        })
        assert result["count"] == 1
        assert "whitelist" in result["results"][0]["error"]
        router.route_request.assert_not_called()

    def test_dispatches_whitelisted_tool(self):
        router = MagicMock()
        router.route_request.return_value = {
            "structuredContent": {"addr": "0x1000", "code": "void f(){}"},
            "isError": False,
        }
        batch.set_router(router)

        result = batch.batch_query({
            "instance_id": "inst1",
            "queries": [{"tool": "decompile", "addr": "0x1000"}],
        })

        assert result["count"] == 1
        assert result["results"][0]["tool"] == "decompile"
        assert "result" in result["results"][0]
        router.route_request.assert_called_once()
        call = router.route_request.call_args
        assert call[0][1]["name"] == "decompile"
        assert call[0][1]["arguments"]["instance_id"] == "inst1"

    def test_max_queries(self):
        batch.set_router(MagicMock())
        result = batch.batch_query({
            "instance_id": "inst1",
            "queries": [{"tool": "decompile", "addr": hex(i)} for i in range(51)],
        })
        assert "error" in result
        assert "max" in result["error"].lower()
