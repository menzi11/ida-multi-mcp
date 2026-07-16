# AGENTS

Last updated: 2026-07-16

## 1) Entry Rules
- Read order: `docs/README.md` -> `docs/.ssot/PRD.md` -> `docs/.ssot/contracts/*` -> target domain docs.
- Conflict resolution: Contracts are the source of truth.

## 2) Documentation Rules
- Do not redefine contract semantics outside `docs/.ssot/contracts/*`.
- Use links + versions when referencing contracts.
- Update absolute dates in modified docs.

## 3) Code/Docs Traceability
- When changing architecture or behavior docs, include references to affected code paths.
- Keep roadmap and PRD synchronized with repository reality.

## 4) Project Profile
- CLI-centric project
- No external HTTP API spec
- No DB-backed schema docs
- Uses AI agents
- Does not use RAG KB currently

## 5) MCP Agent Guide
- Tool selection: `docs/ops/mcp-tool-selection.md`
- Deployment check: call `server_info` (Router) and `server_health` (per instance); compare `build_id` / `capabilities`.
- Router does not char-truncate tool outputs (legacy `max_output_chars` ignored).
- Project skill (optional): `.cursor/skills/ida-multi-mcp/SKILL.md`
- External skill mirrors: `AllSkills/skills/ida-multi-mcp/`, `ComfyAI/config/skills/ida-multi-mcp/`
- Windows: install the package for **both** Router Python and IDA's Python (see `docs/installation.md`).
