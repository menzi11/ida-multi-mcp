# MCP Tool Selection Guide

Last updated: 2026-07-16

> Note: `decompile` soft-fails with `asm` fallback on Hex-Rays errors (e.g. `MERR_BADFRAME`).  
Status: Active  
Audience: AI agents using ida-multi-mcp

This guide reduces round-trips by picking the right tool on the first call. It does not redefine tool contracts in `docs/.ssot/contracts/*`.

## Golden Rules

0. **Verify deployment:** call `server_info` (router, no instance_id) before a session; call `server_health` on an instance and check `build.build_id` / `capabilities`.
1. **One function, one call:** prefer `analyze_function` over `decompile` + `callees` + `xrefs_to`.
2. **Many functions, one call:** prefer `analyze_batch` over repeated `analyze_function`.
3. **Callee subtree:** prefer `decompile_tree` over recursive `decompile` + `callees`.
4. **Mixed read-only queries:** prefer `batch_query` over serial single-tool calls.
5. **Instruction patterns:** prefer `insn_query` over `py_eval` scripts.
6. **Dynamic memory access:** prefer `find_writes` / `find_reads` over `xrefs_to` alone.
7. **Register semantics (single function):** prefer `trace_value` over manual `disasm` loops.
8. **Struct layout hints:** prefer `struct_infer` over manual offset tallying.
9. **Similarity score:** use `compare_functions`. **Line-level diff:** use `diff_functions`.
10. **Reachability:** use `call_path` instead of manual BFS over `callees`.

## Decision Tree

```
Need info about ONE function?
├── Pseudocode + xrefs + callees + constants → analyze_function
├── Only pseudocode → decompile
├── Function + callees (depth N) → decompile_tree
└── Many unrelated functions → analyze_batch

Need memory / data-flow?
├── [reg+disp] or absolute addr in ONE function → find_writes / find_reads
├── Register def-use in ONE function → trace_value
├── Struct field offsets from this/base reg → struct_infer
└── Multi-hop xref chain (not call graph) → trace_data_flow

Need call graph?
├── Full graph from roots → callgraph
└── Paths A → B → call_path

Need to compare two functions?
├── Similarity score → compare_functions
└── Unified diff + constants → diff_functions

Need bulk export to disk?
├── Named functions only → export_session
└── Specific addr list → decompile_to_file

Need several independent reads?
└── batch_query (read-only whitelist)
```

## Tool Cheat Sheet

| Goal | Tool | Avoid |
|------|------|-------|
| Version / deployment check | `server_info`, `server_health` | Guessing from tool count alone |
| Function overview | `analyze_function` | 3–5 separate calls |
| N function overviews | `analyze_batch` | N × `analyze_function` |
| Callee pseudocode tree | `decompile_tree` | N × `decompile` |
| `[base+offset]` access | `find_writes`, `find_reads` | `xrefs_to` only |
| Register tracking | `trace_value` | `disasm` + manual scan |
| Field offset map | `struct_infer` | Repeated `disasm` |
| A reaches B? | `call_path` | Deep `callees` chains |
| Pseudocode diff | `diff_functions` | Two `decompile` + manual compare |
| Semantic similarity | `compare_functions` | Eyeballing decompile |
| Instruction search | `insn_query` | `py_eval` |
| Heterogeneous batch | `batch_query` | Many serial tool calls |
| Session snapshot | `export_session` | Many `decompile_to_file` |

## Parameters Worth Knowing

| Tool | Parameter | Default | Tip |
|------|-----------|---------|-----|
| `server_info` | _(none)_ | — | Router only; compare `build_id` and `capabilities` after upgrades |
| `server_health` | `instance_id` | required | Inspect `build` for IDA plugin version and capability flags |
| `decompile` | `retry_reanalyze` | true | light reanalyze+retry; `"recreate"` = also del+add func; `false` = off |
| `analyze_function` | `max_pseudocode_lines` | 600 | `0` = full text (prefer for huge funcs if context is tight) |
| `analyze_batch` | `max_pseudocode_lines` | 600 | Same as above |
| `decompile_tree` | `depth` / `max_nodes` | 2 / 30 | Increase `max_nodes` for stubs |
| `call_path` | `max_depth` / `max_paths` | 10 / 20 | Internal calls only |
| `export_session` | `named_only` | true | Skips auto `sub_*` names |

Router **does not** truncate tool outputs (`max_output_chars` / `IDA_MCP_MAX_OUTPUT_CHARS` ignored). Prefer `max_pseudocode_lines` or `export_session` / `decompile_to_file` when you need smaller context.

## Maintenance

After adding or changing `@tool` functions in the IDA plugin:

```bash
python scripts/generate_tool_schemas.py
python scripts/generate_tool_schemas.py --check   # CI
```

**Install / upgrade (two runtimes on Windows):**

```powershell
# Router (MCP client / terminal Python)
pip install -e .

# IDA plugin (check Output window for version, often python311)
& "$env:APPDATA\IDA Pro\python311\python.exe" -m pip install -e .
ida-multi-mcp --install
```

Restart Cursor MCP and restart IDA after upgrades. Verify with `server_info` and `server_health` (`build_id` / `capabilities`).

Reload the IDA plugin so running instances expose new tools, then call `refresh_tools`.
