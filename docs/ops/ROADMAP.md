# Roadmap

Last updated: 2026-07-12
Status: Active

## Scope Synchronization
This roadmap does not redefine `docs/.ssot/PRD.md` or `docs/.ssot/contracts/*`; it only manages execution priorities.

## MCP Tool Enhancement (2026-07)

Based on MCP usage analysis and design review. Phased delivery.

### Phase 0 — Reliability hotfix (done)
| Item | Description | Status |
|------|-------------|--------|
| 0a | Fix `_filter_constants` (use `decimal` field) | Done |
| 0b | Tighten `AnalyzeFunctionResult` TypedDict; extend `analyze_function` params | Done |
| 0c | Default pseudocode cap 600 lines; `max_pseudocode_lines=0` = full text (server cache) | Done |
| 0d | `scripts/generate_tool_schemas.py` + CI drift check | Done |
| 0e | Promote `analyze_batch` / `insn_query` in tool descriptions | Done |
| 0f | `server_info` + `server_health.build` deployment probe | Done |

**Acceptance:** `analyze_function` schema validation failures → 0; `constants` non-empty on functions with large immediates; schemas CI-aligned.

### Phase 1 — Composite tools
| Tool | Description | Depends on |
|------|-------------|------------|
| `decompile_tree` | Flat nodes + edges; per-node 600-line cap; global 30-node budget; dedup | **Done** |
| `find_writes` / `find_reads` | Absolute address range + struct offset (`base_reg` + `offset`) | **Done** |
| `batch_query` | Read-only multi-tool batch (whitelist) | **Done** |

### Phase 2 — Semantic tracing
| Tool | MVP scope | Status |
|------|-----------|--------|
| `trace_value` | Single-function def-use (register/operand); no `inferred_type`; no ctree | **Done** |
| `struct_infer` | Aggregate `[base+disp]` access patterns | **Done** |

### Phase 3 — Workstation
| Tool | Notes | Status |
|------|-------|--------|
| `diff_functions` | Pseudocode unified diff + constant set diff (separate from `compare_functions` similarity) | **Done** |
| `call_path` | BFS on internal call graph | **Done** |
| `export_session` | Bulk decompile + structs + enums to local dir | **Done** |

## Near-term (Now)
1. Close P0/P1 stability issues together with contracts and tests.
2. Regularly review the governance gates (SSOT precedence, consistency, absolute-date, traceability).
3. Automate the doc-code consistency verification routine (pre-release).
4. Keep `docs/ops/mcp-tool-selection.md` aligned with the tool surface.

## Mid-term
1. Formalize contract versioning (compatible/incompatible) operational procedures.
2. Split decision records (ADRs) into finer units and strengthen history linkage.
3. Consider turning operational diagnostics (pre/post-install auto-diagnosis) into actual automated scripts.

## N/A
- Runbook: N/A (no on-call/service operation model at this time)
