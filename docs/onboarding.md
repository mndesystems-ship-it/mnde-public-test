# MNDe Onboarding

MNDe onboarding helps an evaluator or operator place MNDe in front of existing MCP tool servers without changing the authority layer.

The onboarding flow discovers known MCP client configuration files, drafts a wiring plan, creates backups, applies only explicit wiring changes, and can restore the original configuration.

## Commands

Run from the repository root:

```bash
npm run mnde -- init
npm run mnde -- init --dry-run
npm run mnde -- init --apply
npm run mnde -- status
npm run mnde -- uninstall
```

If the package is installed as a command, the same flow is available as:

```bash
mnde init
mnde init --dry-run
mnde init --apply
mnde status
mnde uninstall
```

## What Each Command Does

`mnde init` inspects the local project and known MCP client locations. It prints discovered clients, discovered servers, and recommended next steps. It writes nothing.

`mnde init --dry-run` builds the full wiring plan and policy draft preview. It prints `NO CHANGES WRITTEN`.

`mnde init --apply` applies the wiring plan. It creates a backup and backup metadata before changing a config file. It writes a local manifest so `mnde uninstall` can restore the original config.

`mnde status` reports recorded wiring, draft policy status, and read-only authority/receipt readiness.

`mnde uninstall` restores files recorded in the onboarding manifest from their backups.

## What Onboarding Changes

For supported MCP client configs, onboarding replaces the configured server command with the MNDe MCP proxy:

```text
node mcp/mnde-mcp-proxy.mjs
```

The original upstream command and arguments are preserved in environment variables so the proxy can ask MNDe for an authorization decision before forwarding the tool call.

## What Onboarding Does Not Change

Onboarding does not:

- activate a policy
- alter authority keys
- alter authority manifests
- change receipt signing logic
- change replay verification logic
- change decision semantics
- grant roles
- send telemetry
- call external services

Policy output from onboarding is a draft only. A human must review it before use.

## Backups

Backups are stored under the MNDe state directory:

```text
~/.mnde/backups/
```

Set `MNDE_STATE_DIR` to use a different state location.

Each backup has a companion metadata file:

```text
<backup>.metadata.json
```

The metadata records the original config path, client name, protected servers, original file hash, creation time, and restore command.

## Recovery

Run:

```bash
npm run mnde -- uninstall
```

The uninstall command restores each recorded config from its backup and clears the onboarding manifest.

If a config cannot be restored because its backup is missing, the command reports the missing backup instead of inventing a new state.

## Authority Boundary

Onboarding is wiring assistance. It is not the authority system.

MNDe still makes decisions through the normal sidecar decision path. Receipts, signatures, replay, policy hashes, and verifier behavior remain owned by the existing authority and verification code.
