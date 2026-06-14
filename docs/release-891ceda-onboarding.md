# MNDe Onboarding Arrives

Commit: `891ceda`

## Problem Before This Release

MNDe already had the core proof path: a caller asks before execution, MNDe returns `ALLOW` or `REFUSE`, and the result is recorded in a signed receipt that can be replayed and verified later.

That part mattered most, and it held up under review.

But there was still a practical gap.

If someone already had MCP tools, they still had to answer a basic question themselves:

```text
How do I put MNDe in front of the tools I already use?
```

The reviewer kit proved the authority model. The executor and MCP demos proved the enforcement pattern. What was missing was the safer setup path between those two things.

This release adds that missing layer.

## What This Release Changes

MNDe now has an onboarding command that can inspect a local MCP environment, explain what it found, show exactly what it would wire, apply that wiring only when asked, and restore the original configuration later.

The new commands are:

```bash
npm run mnde -- init
npm run mnde -- init --dry-run
npm run mnde -- init --apply
npm run mnde -- status
npm run mnde -- uninstall
```

This is not a new authority path. It is setup infrastructure around the existing authority path.

The code is split into separate layers:

- `src/discovery/`
- `src/wiring/`
- `src/onboarding/`
- `src/policy-drafting/`

The docs were added alongside it:

- `docs/onboarding.md`
- `docs/discovery.md`
- `docs/wiring.md`
- `docs/policy-drafting.md`
- `docs/security-model.md`

## Before vs After Experience

Before this release, a tester could run the reviewer kit and prove MNDe worked, but wiring an existing MCP client was still mostly manual.

After this release, the path is more direct:

1. Ask MNDe what it can see.
2. Review the exact wiring plan.
3. Apply it only if it looks right.
4. Keep a backup of what changed.
5. Undo it with one command if needed.

The important part is that MNDe does not quietly take over a machine. It shows its work first.

`init` writes nothing.

`init --dry-run` writes nothing.

`init --apply` is the first command that modifies supported MCP configs, and it creates restore material before it writes.

## What MNDe Changes

MNDe currently discovers these MCP locations:

- Claude Desktop MCP configuration
- Cursor MCP configuration
- project `.mcp.json`

Discovery also records local environment details that help explain the result:

- operating system
- Node.js version
- package manager hints
- project type hints
- already-wrapped MCP servers
- malformed or unreadable MCP configs

When `npm run mnde -- init --apply` is used, MNDe places the MNDe MCP proxy in front of supported MCP servers:

```text
node mcp/mnde-mcp-proxy.mjs
```

The original upstream server command is preserved:

```text
MNDE_PROXY_UPSTREAM_COMMAND
MNDE_PROXY_UPSTREAM_ARGS
MNDE_SIDECAR_URL
_mnde_wrapped=1
```

Before changing a config, MNDe creates:

- a backup of the original config
- backup metadata
- an onboarding manifest entry

After writing, MNDe reads the config back and verifies that the intended servers are wrapped.

## What MNDe Does Not Change

This release keeps a hard line between setup and authority.

Onboarding does not:

- activate policy
- change authority keys
- change authority manifests
- change receipt signing logic
- change replay verification logic
- change decision semantics
- grant roles
- send telemetry
- call external services

The policy file produced during onboarding is a draft. It is review material, not an active production policy.

MNDe still decides through the normal sidecar decision path. Receipts still verify through the existing verifier. Replay still uses the existing replay behavior.

## Why The Architecture Matters

MNDe is supposed to sit before execution.

That means the setup path has to be careful. If onboarding becomes a hidden shortcut around the authority layer, it defeats the point of the system.

This release keeps onboarding boring on purpose:

- discovery is local and deterministic
- planning is inspectable
- apply is explicit
- backups happen before writes
- restore is built in
- malformed configs are skipped
- already-wrapped servers are not wrapped again

The result is a cleaner path from:

```text
I have MCP tools.
```

to:

```text
Those tool calls now ask MNDe before execution.
```

That is the point of the feature.

## Verification And Test Evidence

The onboarding work was verified without removing the existing proof path.

These commands passed:

```text
npm install                         PASS
npm run tester:init -- TESTER-001   PASS
npm run test:onboarding             PASS
npm run test:correctness            PASS
npm run test:receipt-verifier       PASS
npm run test:trust-anchor           PASS
npm run test:fresh-setup            PASS
npm run reviewer-kit                PASS
npm run test:reviewer-kit           PASS
npm run test:executor               PASS
npm run test:mcp                    PASS
npm run test:mcp-proxy              PASS
npm run test:shell                  PASS
npm run test:sidecar                PASS
```

The onboarding-specific suite passed:

```text
PASS onboarding tests (9/9)
```

The reviewer kit still produced the expected final verdict:

```text
MNDe External Review Complete
Environment: PASS
ALLOW: PASS
REFUSE: PASS
Receipt Verification: PASS
Replay Verification: PASS
Hostile Inputs: PASS
Executor Blocked: PASS

FINAL VERDICT: PASS
```

Generated reviewer-kit receipts still verified offline:

```text
Schema: PASS
Canonicalization: PASS
Request Hash: PASS
Decision Hash: PASS
Policy Hash: PASS
Signature: PASS
Replay Determinism: PASS
FINAL VERDICT: VERIFIED
```

## How To Try It

From a fresh clone:

```bash
npm install
npm run tester:init -- TESTER-001
npm run reviewer-kit
```

Then inspect onboarding:

```bash
npm run mnde -- init
npm run mnde -- init --dry-run
npm run mnde -- status
```

Only apply wiring when you want MNDe to modify supported MCP client configs:

```bash
npm run mnde -- init --apply
```

Restore original configs:

```bash
npm run mnde -- uninstall
```

## What Reviewers Should Inspect

Start with the CLI:

- `bin/mnde.mjs`

Then check the separation between layers:

- `src/discovery/index.mjs`
- `src/wiring/index.mjs`
- `src/onboarding/index.mjs`
- `src/onboarding/context.mjs`
- `src/policy-drafting/index.mjs`

Then check the tests:

- `tests/test_onboarding.mjs`
- `tests/fixtures/onboarding/`

Then check the docs:

- `docs/onboarding.md`
- `docs/discovery.md`
- `docs/wiring.md`
- `docs/policy-drafting.md`
- `docs/security-model.md`

After an apply run, inspect the generated local artifacts:

- onboarding manifest under the MNDe state directory
- backups under the MNDe state directory
- backup metadata next to each backup
- `policy.draft.json` in the working project

## Closing Statement

This release does not make MNDe more permissive. It does not add a second decision path. It does not weaken receipts, replay, signatures, authority manifests, or policy hashing.

It makes the first setup step safer and more inspectable.

MNDe still has one job:

```text
Decide whether execution is allowed before execution occurs.
```

Onboarding now helps existing MCP tools reach that decision point without asking the operator to hand-wire everything from scratch.
