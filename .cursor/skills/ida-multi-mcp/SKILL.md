---
name: ida-multi-mcp
description: >-
  Operate ida-multi-mcp multi-instance IDA Pro MCP tools: deployment checks,
  composite analysis, batch queries, and tool selection. Use when reverse
  engineering with IDA via MCP, ida-multi-mcp, decompile_tree, trace_value,
  batch_query, server_info, or when MCP tools seem stale or missing.
---

# ida-multi-mcp

## Start of session

1. Call `server_info` (no `instance_id`) — confirm `build_id` and `capabilities`.
2. Call `list_instances` — pick `instance_id`.
3. Call `server_health` on that instance — `build.build_id` must match Router; check `capabilities`.

If capabilities are false after an upgrade: restart Cursor MCP **and** restart IDA (separate Python runtimes).

## Tool selection

Read [docs/ops/mcp-tool-selection.md](../../../docs/ops/mcp-tool-selection.md) before picking tools.

External mirrors (same content, self-contained docs): `AllSkills/skills/ida-multi-mcp/`, `ComfyAI/config/skills/ida-multi-mcp/`.

Quick defaults:
- One function → `analyze_function`
- Many functions → `analyze_batch`
- Callee subtree → `decompile_tree`
- Register def-use (one function) → `trace_value`
- Memory `[reg+disp]` → `find_reads` / `find_writes`
- A reaches B (calls) → `call_path`
- Mixed read-only batch → `batch_query`

Always pass `instance_id` for IDA-side tools.

## Windows dev install (editable)

Router and IDA use **different** Python interpreters:

```powershell
pip install -e .
ida-multi-mcp --install
& "$env:APPDATA\IDA Pro\python311\python.exe" -m pip install -e .
```

Adjust the IDA path if Output window shows a different version.

## When Cursor Agent lacks new tools

Router may expose ~96 tools while the chat UI caches fewer. Verify with `server_info` / `refresh_tools`. Use Router-backed calls or a new chat if specific tool names fail with "tool not found".

## Docs entry

`docs/README.md` → contracts → `docs/ops/mcp-tool-selection.md` → `docs/ops/ROADMAP.md`
