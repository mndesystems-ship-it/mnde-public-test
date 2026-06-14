# Discovery

Discovery is a deterministic local inspection step. It finds supported MCP client configuration files and records enough information to build a wiring plan.

Discovery does not call the network, does not start MNDe, does not query the sidecar, and does not modify files.

## Supported Discovery Targets

Current discovery targets:

- Claude Desktop MCP config
- Cursor MCP config
- project `.mcp.json`

Discovery checks platform-specific default paths and the current project directory.

## Output

Discovery reports:

- operating system
- Node.js version
- package manager hints
- project type hints
- discovered MCP clients
- discovered MCP servers
- already-wrapped servers
- unreadable or malformed configs

Malformed configs are reported as errors and skipped by wiring.

## Determinism

Discovery is filesystem based. The same files and same context produce the same discovery result.

Tests cover Windows, macOS, and Linux path resolution using fixture roots so discovery can be verified offline.

## Fail-Closed Behavior

Discovery does not repair broken configs and does not guess missing server definitions.

If a config is missing, discovery reports no client for that path.

If a config is malformed, discovery records the parse error and wiring refuses to modify it.

If a server is already wrapped by MNDe, discovery marks it as wrapped so wiring does not wrap it again.

## Known Limits

Discovery only supports known MCP config shapes. It does not inspect arbitrary application settings, browser profiles, shell history, or private files outside the configured search locations.
