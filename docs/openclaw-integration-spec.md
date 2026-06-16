# MNDe Guard for OpenClaw

Status: Integration target specification

Product name: MNDe Guard for OpenClaw

Type: OpenClaw Skill first. OpenClaw Plugin later.

## Purpose

MNDe Guard for OpenClaw is a proposed OpenClaw skill that teaches OpenClaw to ask MNDe before performing risky actions.

The core promise:

```text
Before OpenClaw performs a risky action, MNDe checks the action, returns ALLOW or REFUSE, and writes a receipt.
```

The skill is not a replacement for MNDe enforcement integrations. It is a first distribution path for OpenClaw users and a way to make pre-execution checks natural inside OpenClaw workflows.

## Why Start With A Skill

OpenClaw skills are folder-based instruction packages with a `SKILL.md` file.

That makes a skill the lowest-friction starting point:

- it fits OpenClaw's existing model
- it can be installed locally or per workspace
- it can teach the agent when to check MNDe
- it can include policy examples and receipts
- it avoids building a deeper plugin before the behavior is proven

A plugin can come later if deeper tool interception is needed.

## User-Facing Pitch

Protect OpenClaw from dangerous actions before they run.

OpenClaw gives agents power. MNDe adds execution control.

## Target User

People using OpenClaw with:

- file access
- terminal access
- browser automation
- shell commands
- local scripts
- APIs
- third-party skills
- package installers
- git operations
- cloud or database tools

## Integration Model

```text
OpenClaw Agent
      |
      v
Risky action request
      |
      v
MNDe Guard Skill
      |
      v
POST /v1/decisions
      |
      v
MNDe sidecar
      |
      +-- ALLOW  -> OpenClaw may proceed
      |
      +-- REFUSE -> OpenClaw must stop
      |
      v
Signed receipt saved locally
```

MNDe core returns only:

- `ALLOW`
- `REFUSE`

If the skill presents a "review required" experience, that is an OpenClaw-side workflow choice before execution. It must not be represented as a third MNDe decision state unless MNDe itself later adds that state.

## Skill Folder

```text
mnde-openclaw-guard/
  SKILL.md
  README.md
  examples/
    protected-file-delete.md
    protected-shell-command.md
    protected-browser-action.md
  scripts/
    check-mnde.js
    install-mnde.js
  policy/
    personal-default.json
    strict-local.json
  package.json
```

## SKILL.md Frontmatter

```yaml
---
name: mnde-openclaw-guard
description: Adds pre-execution safety checks for OpenClaw actions through the local MNDe execution firewall.
version: 0.1.0
author: MNDe Systems
tags:
  - security
  - execution-firewall
  - openclaw
  - agent-safety
requirements:
  - node >= 18
  - local MNDe sidecar running on http://127.0.0.1:8787
environment:
  MNDE_URL: optional, default http://127.0.0.1:8787
  MNDE_POLICY: optional, default personal-default
---
```

## Skill Instructions

When the user asks OpenClaw to perform an action that affects files, shell commands, browser sessions, credentials, APIs, network calls, package installs, git state, cloud resources, wallets, keys, secrets, databases, or system settings, check with MNDe before execution.

Never execute a risky action first.

Send MNDe:

- action name
- tool name
- target path or URL
- arguments
- risk category
- user request summary
- workspace path
- agent name
- timestamp

Respect the MNDe response:

`ALLOW`

Proceed with the action.

`REFUSE`

Do not perform the action. Show the refusal reason and receipt path.

MNDe unavailable:

Fail closed for destructive or external actions. Allow read-only local actions only if policy permits.

## Risk Categories

- `file_read`
- `file_write`
- `file_delete`
- `recursive_delete`
- `shell_command`
- `package_install`
- `git_change`
- `network_request`
- `browser_action`
- `credential_access`
- `secret_access`
- `cloud_action`
- `database_action`
- `wallet_action`
- `unknown_high_risk`

## Default Policy Direction

Allow:

- `read_status`
- `list_files`
- read file under workspace
- `git status`
- `npm test`
- safe local diagnostics

Require user review before asking MNDe to allow:

- file write
- git commit
- package install
- browser form submit
- API `POST`
- network download
- moving files

Refuse:

- recursive delete
- credential exfiltration
- reading `.env` without direct user request
- writing `authorized_keys`
- curl pipe to shell
- download and execute
- modifying shell profile
- deleting project root
- accessing wallet files
- sending secrets to an external URL

## MNDe API Contract

Endpoint:

```text
POST http://127.0.0.1:8787/v1/decisions
```

**The request is the canonical MNDe execution-request envelope** — the same one every other MNDe caller uses. It is documented and drift-tested in [API Contract](api-contract.md), with runnable copies in [`examples/decisions/`](../examples/decisions/). OpenClaw does **not** invent its own body shape; it maps its proposed action into the envelope:

| OpenClaw | MNDe envelope field |
| --- | --- |
| action id | `execution_request.request_id` |
| tool name | `execution_request.tool_calls[0].tool` |
| command / args | `execution_request.tool_calls[0].parameters` (e.g. `{ "script": "rm -rf ./project" }`) |
| integration id | `execution_request.parameters.installation_id` |

Request (the OpenClaw guard builds this and POSTs it):

```json
{
  "execution_request": {
    "request_id": "openclaw-rmrf",
    "actor": { "user_id": "openclaw" },
    "parameters": { "tester_id": "openclaw", "installation_id": "mnde-openclaw-guard" },
    "tool_calls": [ { "tool": "recursive_delete", "priority": 1, "parameters": { "script": "rm -rf ./project" } } ],
    "release_request": { "execution_id": "openclaw-rmrf", "hold_state": "APPROVED", "already_consumed": false }
    /* ...resources, execution, orbit_intent, runtime_observation — see API Contract... */
  },
  "pricing_data": { "gpu_hour_cents": 500 }
}
```

Response (the real fields MNDe returns):

```json
{
  "decision": "REFUSE",
  "reason_code": "ERR_FORBIDDEN_ACTION_IN_PARAMETERS",
  "request_hash": "…",
  "decision_hash": "…",
  "receipt": { "schema_version": "ecs.receipt.v2", "...": "..." }
}
```

> The decision is about **what the action does**: `recursive_delete` carrying `rm -rf` is REFUSED via destructive-parameter detection (`ERR_FORBIDDEN_ACTION_IN_PARAMETERS`); the same tool with no destructive parameters may ALLOW. The active policy is limits-based plus destructive-parameter detection — not a tool-name denylist.

ALLOW returns an inline signed receipt; REFUSE persists one (visible at `GET /receipts/recent`). Verify any receipt with `POST /console/verify` (or `node tools/verify.mjs <file>` offline) and replay with `POST /console/replay`.

This integration is proven end-to-end against a live sidecar by `npm run test:openclaw` (real ALLOW, real REFUSE, receipt verification, deterministic replay, and rejection of the older flat request shape).

## OpenClaw Behavior Examples

User:

```text
Clean this repo.
```

OpenClaw with MNDe:

```text
I need to remove generated files. MNDe requires review before deleting files. Proposed action: delete /dist and /coverage only.
```

User:

```text
Delete everything and start over.
```

OpenClaw with MNDe:

```text
MNDe refused this action because it would recursively delete the active workspace.
```

User:

```text
Install this skill from GitHub.
```

OpenClaw with MNDe:

```text
MNDe requires review before installing third-party executable code.
```

## Distribution Targets

Skill package:

```text
mnde-openclaw-guard
```

GitHub repository:

```text
mndesystems-ship-it/mnde-openclaw-guard
```

README title:

```text
Protect OpenClaw with MNDe
```

README opening:

```text
OpenClaw gives agents power. MNDe adds execution control.
```

Install:

```bash
openclaw skill install mnde-openclaw-guard
```

Manual install:

```text
copy mnde-openclaw-guard to ~/.openclaw/skills
```

Workspace install:

```text
copy mnde-openclaw-guard to ./skills
```

## Activation Test

Ask OpenClaw:

```text
Use MNDe to check if deleting this workspace is allowed.
```

Expected result:

- MNDe refuses.
- OpenClaw does not run the delete command.
- A receipt appears.

## Minimum Viable Release

- `SKILL.md` instructions
- local MNDe health check
- default personal policy
- strict local policy
- three examples
- receipt verification command
- README with install and demo
- one screenshot or terminal capture

## Non-Goals For The First Release

The first release should not start as a deep plugin.

It should not claim OS-level enforcement.

It should not claim OpenClaw cannot bypass MNDe.

It should not introduce a third MNDe decision state.

It should not generate policy dynamically.

It should not execute tools.

## Reviewer Questions

A reviewer should be able to answer:

- Does the skill instruct OpenClaw to ask MNDe before risky actions?
- Does it fail closed when MNDe is unavailable?
- Does it preserve MNDe's `ALLOW` / `REFUSE` model?
- Does it show receipt paths for refused actions?
- Does it avoid overclaiming enforcement?
- Does it make the bypass boundary clear?

## Implementation Order

1. Create the `mnde-openclaw-guard/` skill folder.
2. Write `SKILL.md` with strict pre-execution instructions.
3. Add `scripts/check-mnde.js` for sidecar health.
4. Add `policy/personal-default.json`.
5. Add `policy/strict-local.json`.
6. Add examples for file delete, shell command, and browser action.
7. Add README install and activation test.
8. Add receipt verification instructions.
9. Test manually with OpenClaw.
10. Publish only after the skill reliably refuses destructive actions before execution.
