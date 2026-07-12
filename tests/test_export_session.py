"""Tests for export_session server tool."""

from __future__ import annotations

from ida_multi_mcp.tools import export


class TestExportSessionValidation:
    def test_rejects_outside_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = export._validate_output_dir(str(tmp_path.parent / "outside"), False)
        assert isinstance(result, dict)
        assert "error" in result

    def test_requires_instance_id(self):
        export.set_router(None)
        result = export.export_session({"output_dir": "."})
        assert "instance_id" in result["error"]
