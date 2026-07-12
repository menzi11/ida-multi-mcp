"""Build and version metadata for ida-multi-mcp."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import ida_multi_mcp

_PACKAGE_DIR = Path(ida_multi_mcp.__file__).resolve().parent
_SCHEMA_PATH = _PACKAGE_DIR / "ida_tool_schemas.json"

# Tools added in composite-tool phases; presence indicates an up-to-date deployment.
CAPABILITY_MARKERS: tuple[str, ...] = (
    "batch_query",
    "export_session",
    "decompile_tree",
    "trace_value",
    "diff_functions",
    "call_path",
    "find_writes",
    "find_reads",
    "struct_infer",
)


def _find_repo_root(start: Path) -> Path | None:
    for candidate in (start, *start.parents):
        if (candidate / ".git").is_dir():
            return candidate
    return None


def git_revision(start: Path | None = None) -> str | None:
    """Return short git HEAD for editable installs, or None."""
    root = _find_repo_root(start or _PACKAGE_DIR)
    if root is None:
        return None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    rev = (result.stdout or "").strip()
    return rev or None


def schema_metadata() -> dict[str, Any]:
    """Fingerprint bundled IDA tool schemas."""
    try:
        raw = _SCHEMA_PATH.read_bytes()
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, list):
            return {"schema_tools_count": 0, "schema_fingerprint": None}
        digest = hashlib.sha256(raw).hexdigest()[:12]
        return {"schema_tools_count": len(data), "schema_fingerprint": digest}
    except (OSError, json.JSONDecodeError):
        return {"schema_tools_count": 0, "schema_fingerprint": None}


def capability_map(registered_tools: set[str] | None) -> dict[str, bool]:
    if not registered_tools:
        return {name: False for name in CAPABILITY_MARKERS}
    return {name: name in registered_tools for name in CAPABILITY_MARKERS}


def build_id(version: str, git_rev: str | None, schema_fingerprint: str | None) -> str:
    parts = [version, git_rev or "nogit", schema_fingerprint or "noschema"]
    return "+".join(parts)


def package_build(*, role: str, uptime_sec: float | None = None) -> dict[str, Any]:
    """Core package/build fields shared by router and IDA plugin."""
    schema = schema_metadata()
    rev = git_revision()
    version = ida_multi_mcp.__version__
    payload: dict[str, Any] = {
        "role": role,
        "package": "ida-multi-mcp",
        "version": version,
        "git_revision": rev,
        "build_id": build_id(version, rev, schema.get("schema_fingerprint")),
        "schema_tools_count": schema["schema_tools_count"],
        "schema_fingerprint": schema["schema_fingerprint"],
        "python_executable": sys.executable,
        "python_version": sys.version.split()[0],
        "package_path": str(_PACKAGE_DIR),
    }
    if uptime_sec is not None:
        payload["uptime_sec"] = round(uptime_sec, 1)
    return payload
