# Documentation Hub

Last updated: 2026-07-12
Status: Active

This document is the entry point for the `ida-multi-mcp` documentation.

## Governance First
- Governance entry: this file (`docs/README.md`)
- Top authority (SSOT): `docs/.ssot/contracts/*`
- Precedence when documents conflict:
1. `docs/.ssot/contracts/*`
2. `docs/.ssot/PRD.md`
3. `docs/.ssot/decisions/*`
4. `docs/.ssot/architectures/*`
5. `docs/plans/_completed/*`
6. `docs/ops/*`

## Canonical Map
- SSOT root: `docs/.ssot/`
- PRD: `docs/.ssot/PRD.md`
- Contracts: `docs/.ssot/contracts/INDEX.md`
- Decisions: `docs/.ssot/decisions/INDEX.md`
- Architecture: `docs/.ssot/architectures/00_INDEX.md`
- SSOT TODO: `docs/.ssot/TODO.md`
- Ops roadmap: `docs/ops/ROADMAP.md`
- Agent tool selection: `docs/ops/mcp-tool-selection.md`
- Cursor project skill: `.cursor/skills/ida-multi-mcp/SKILL.md`
- External skill mirrors: `AllSkills/skills/ida-multi-mcp/`, `ComfyAI/config/skills/ida-multi-mcp/`
- Installation guide: `docs/installation.md`

## Applicability Snapshot
- HTTP API spec: `N/A` (CLI-centric for now)
- DB schema docs: `N/A` (file-based registry)
- Runbook: `N/A` (not an on-call service)
- KB config: `N/A` (`uses_rag_kb: false`)
