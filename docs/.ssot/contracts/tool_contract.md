# Tool Federation Contract

Last updated: 2026-07-16
Version: v2

## Authority
This contract defines the central MCP server's tool schema federation and large-response handling rules.

## Schema Rules
- IDA tools expose `instance_id` as a required input.
- For client compatibility, the output schema must be object-compatible.

## Output Rules
- Router proxies return the full IDA tool payload; they do **not** apply character-budget truncation.
- Legacy `max_output_chars` / `IDA_MCP_MAX_OUTPUT_CHARS` are ignored if present.
- `get_cached_output` remains available for manually stored cache entries (offset/size pagination).

## Traceability
- Tool cache/federation: `src/ida_multi_mcp/server.py`
- Cache model: `src/ida_multi_mcp/cache.py`
