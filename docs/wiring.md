# Wiring

Wiring places the MNDe MCP proxy in front of existing MCP servers.

The proxy asks MNDe for a pre-execution decision before forwarding a tool call to the upstream server.

## Wiring Plan

The wiring planner consumes discovery output and produces a deterministic plan.

For each supported client config, the plan records:

- config path
- client id
- client name
- servers to protect
- backup path
- backup metadata path
- restore command

Already-wrapped servers are skipped.

Malformed configs are skipped.

## Apply Flow

`mnde init --apply` performs the apply flow in this order:

1. Read the current config.
2. Build the wrapped config in memory.
3. Write a backup of the original config.
4. Write backup metadata.
5. Write the onboarding manifest entry.
6. Write the modified config.
7. Re-read the config.
8. Verify that the intended servers are wrapped.

If post-write verification fails, MNDe restores the original config and reports the failure.

## Wrapped Server Shape

The wrapped server command points to the MNDe MCP proxy:

```text
node mcp/mnde-mcp-proxy.mjs
```

The original command, original arguments, and sidecar URL are preserved in environment variables:

```text
MNDE_PROXY_UPSTREAM_COMMAND
MNDE_PROXY_UPSTREAM_ARGS
MNDE_SIDECAR_URL
_mnde_wrapped=1
```

The marker prevents double-wrapping.

## Restore Flow

`mnde uninstall` reads the onboarding manifest and restores each config from the recorded backup.

The original bytes are restored from the backup file. Tests verify byte-for-byte restoration.

## Logging

Onboarding writes local wiring events to:

```text
~/.mnde/logs/onboarding.log
```

Set `MNDE_STATE_DIR` to use a different state location.

## Security Boundary

Wiring does not grant authority. It only changes how a supported MCP client reaches a tool server.

If a caller bypasses the configured MCP client or runs the original tool server directly, MNDe cannot evaluate that action. Production deployments should combine wiring with normal endpoint control, access control, and operational monitoring.
