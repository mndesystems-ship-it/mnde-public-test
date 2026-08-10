# MNDe CLI v1 Specification (First Iteration)

Status: **Draft / proposed first iteration.** This document specifies a single,
coherent `mnde` command-line interface, modeled on the ergonomics of `git` and
`docker`. It describes the target v1 surface. It is a design contract, not a
claim that every command below is implemented today; the
[Implementation status](#12-implementation-status) section maps each command to
the code that exists now.

- Audience: operators, integrators, and reviewers.
- Scope: the `mnde` command tree — grammar, global options, configuration,
  output contract, and exit codes.
- Non-goals: this does not change the decision engine, receipt format, authority
  model, or ledger format. Those are specified elsewhere (see
  [References](#13-references)). The CLI is a surface over the existing audited
  modules; it introduces no new trust path.

---

## 1. Design goals

The repository today exposes its capabilities through several disjoint entry
points: `bin/mnde.mjs` (onboarding + `decide` + `status`), `bin/mnde-sidecar.mjs`
(`init` / `doctor` / `start` / `smoke`), `bin/mnde-authority.mjs`
(`rotate` / `revoke`), `src/receipt-index/cli.mjs`
(`index` / `find` / `show` / `stats`), and a set of `scripts/*.mjs` reached only
through `npm run` (ledger verify/head/export/prove, receipt verify). Each has its
own flag style, output format, and exit-code convention.

v1 unifies these behind one binary with a predictable grammar. The design goals,
in priority order:

1. **One binary, one grammar.** Everything is `mnde <group> <verb> [args]`
   (`git`/`docker` noun-verb structure). No capability requires knowing which
   underlying script implements it.
2. **Fail closed, everywhere.** Any error, missing trust material, or ambiguous
   state resolves to a non-zero exit and no side effect. This mirrors the
   decision engine's own posture.
3. **Deterministic, script-friendly output.** Every command that returns data
   supports `--json` with a stable schema on `stdout`; human-readable text is the
   default. Diagnostics always go to `stderr`.
4. **Reversibility for anything that writes.** Commands that modify a caller's
   environment (onboarding) create backups first and are undoable. Commands that
   modify trust material (authority) never overwrite their input and verify their
   output before writing.
5. **No hidden state.** All state lives under a single, inspectable home
   directory (`MNDE_HOME`), and the CLI writes nowhere else.

### 1.1 Porcelain vs. plumbing

Following `git`, the surface is split into two tiers:

- **Porcelain** — the commands operators use day to day. Human-friendly output
  by default, stable flags. `init`, `status`, `up`, `decide`, `verify`, `doctor`.
- **Plumbing** — lower-level, composable commands with machine-first output,
  intended for scripts and other tooling. `receipt`, `ledger`, `authority`,
  `policy` subtrees lean plumbing; they default to structured output under
  `--json` and keep their schemas stable across patch releases.

Porcelain may change presentation between minor versions; plumbing output schemas
are covered by the [compatibility policy](#11-compatibility-and-versioning).

---

## 2. Invocation grammar

```text
mnde [global-options] <command> [<subcommand>] [command-options] [arguments]
```

- `command` is a top-level verb (`init`, `decide`, `status`, `up`, `doctor`,
  `version`) or a **group** noun (`sidecar`, `receipt`, `ledger`, `authority`,
  `policy`).
- Group nouns require a `subcommand` verb (e.g. `mnde receipt verify`).
- Options may appear before or after positionals. Long options use `--name` or
  `--name=value`; the space form `--name value` is also accepted. Short options
  are single-dash single-letter (`-q`, `-v`, `-h`).
- `--` terminates option parsing; everything after it is positional.

Ambiguity is an error, not a guess: an unknown command, an unknown option, or a
missing required argument exits `2` (usage error) and prints usage to `stderr`.

### 2.1 Aliases

A small set of aliases smooths the transition from the current scripts and
matches muscle memory from `git`/`docker`:

| Alias            | Canonical form            |
| ---------------- | ------------------------- |
| `mnde start`     | `mnde sidecar start`      |
| `mnde up`        | `mnde sidecar start`      |
| `mnde down`      | `mnde sidecar stop`       |
| `mnde logs`      | `mnde sidecar logs`       |
| `mnde ps`        | `mnde sidecar status`     |
| `mnde verify <f>`| `mnde receipt verify <f>` |

Aliases are resolved before dispatch and are never ambiguous with a real
command. `mnde help <alias>` shows the canonical command's help.

---

## 3. Global options

These apply to every command and are parsed regardless of position.

| Option              | Env                    | Default            | Meaning                                                                 |
| ------------------- | ---------------------- | ------------------ | ----------------------------------------------------------------------- |
| `--home <dir>`      | `MNDE_HOME`            | `./.mnde`          | Root for all CLI-owned state (keys, policy, receipts, config). The **only** directory the CLI writes to. |
| `--config <file>`   | `MNDE_CONFIG`          | `<home>/config.json` | Path to the config file (see [§5](#5-configuration)).                  |
| `--json`            | —                      | off                | Emit a single stable JSON document on `stdout`; suppress human text.    |
| `--quiet`, `-q`     | —                      | off                | Suppress non-essential `stdout`; errors still print to `stderr`.        |
| `--verbose`, `-v`   | `MNDE_VERBOSE`         | off                | Extra diagnostics on `stderr`. Repeatable (`-vv`) for more detail.      |
| `--no-color`        | `NO_COLOR`             | auto (TTY-aware)   | Disable ANSI color. Color is off automatically when `stdout` is not a TTY. |
| `--yes`, `-y`       | —                      | off                | Assume "yes" for interactive confirmations (non-interactive use).       |
| `--help`, `-h`      | —                      | —                  | Show help for the current command and exit `0`.                         |
| `--version`         | —                      | —                  | Print version (see [`mnde version`](#67-mnde-version)) and exit `0`.     |

Rules:

- `--json` and `--quiet` are compatible; `--json` wins for `stdout` content.
- `--json` and human output never mix on `stdout`. A command invoked with
  `--json` that fails still emits a JSON error object (see [§8.2](#82-json-error-object)).
- Unknown global options are a usage error (exit `2`).

---

## 4. Command reference

The surface is organized as five top-level verbs plus five groups.

```text
mnde
├── init                 wire MNDe in front of local MCP clients (reversible)
├── uninstall            restore configs from backups
├── status               what is protected + policy/authority readiness
├── decide               evaluate a request against a policy -> signed receipt
├── verify   (alias)     -> receipt verify
├── up/start (alias)     -> sidecar start
├── doctor               fail-closed readiness check
├── version              version + build/runtime info
│
├── sidecar   up|start | stop|down | status|ps | logs | init | smoke
├── receipt   verify | show | find | index | stats
├── ledger    verify | head | export | prove | verify-proof
├── authority init | rotate | revoke | export | show
└── policy    draft | verify | show
```

### 4.1 `mnde init` — onboard local MCP clients

Discovers MCP clients/servers and (optionally) wires MNDe in front of them. This
is the current `bin/mnde.mjs init`, unchanged in behavior.

```text
mnde init                 discovery + recommendations (no changes)
mnde init --dry-run       full wiring plan (no changes)
mnde init --apply         apply the plan (creates backups first)
```

- `--dry-run` and no-flag are read-only.
- `--apply` writes backups before modifying any config and records the wiring so
  `mnde uninstall` can reverse it. It also writes a **policy draft** that is
  never enforced.
- Onboarding does not activate policy, change authority material, alter receipt
  signing, or change replay verification.

Exit: `0` on success (including "nothing to do"); `1` on write failure.

### 4.2 `mnde uninstall` — reverse onboarding

Restores original MCP client configurations from the backups `init --apply`
created. Backups that are missing are reported and left untouched (fail closed:
never fabricate a "restore"). Exit `0` if all recorded wiring was restored or
there was nothing to restore; `1` otherwise.

### 4.3 `mnde status` — protection + readiness

Shows which clients/servers are wired, whether a policy draft exists (drafts are
never enforced), local authority readiness, and whether a sample receipt
verifies. `--json` emits the structured status object. Read-only; exit `0`.

### 4.4 `mnde decide` — evaluate and receipt

Runs a request + policy through the deterministic policy engine and emits a
**signed receipt** on the shared authority chain. The decision logic is the
authority layer; this command only produces and verifies the receipt for it.

```text
mnde decide --request <request.json> --policy <policy.json>
            [--authorities <auth.json>]
            [--trust-anchors <anchors.json>]
            [--approvals <approvals.json>]
            [--approval-trust-anchors <anchors.json>]
            [--out <receipt.json>]
```

- `--request` and `--policy` are required.
- Without `--out`, the receipt is printed to `stdout` (or emitted as the `--json`
  payload).
- The command verifies the receipt offline before reporting success.

Exit (see [§8.3](#83-decision-aware-exit-codes)):

- `0` — decision is `ALLOW` **and** the receipt verified offline.
- `10` — decision is `REFUSE` (verified). This is a *successful evaluation with a
  refuse outcome*, distinguished from an error so scripts can branch on it.
- `11` — decision requires manual approval (`APPROVAL_REQUIRED` / hold) and none
  was supplied.
- `3` — a receipt was produced but failed offline verification (treat as
  untrusted).
- `1` — the evaluation could not be performed (bad input, unreadable policy).

### 4.5 `mnde doctor` — readiness check

Fail-closed environment and trust-material check: Node version, key presence and
permissions, authority manifest validity, and that a sample decision produces a
verifiable receipt. Prints one line per check. **Exit `1` on any FAIL**; `0` only
when every check passes. `--json` emits `{ checks: [...], ok: bool }`.

### 4.6 `mnde version` — version and build info

Prints the CLI version, the receipt/ledger/authority schema versions it speaks,
the resolved `MNDE_HOME`, and the Node runtime. `--json` emits the structured
form. Always exit `0`.

---

## 5. `mnde sidecar` — run the decision service

The sidecar is the local decision service (`docker`-style lifecycle verbs).

| Command                 | Purpose                                                                 |
| ----------------------- | ----------------------------------------------------------------------- |
| `sidecar init`          | Generate local keys + authority + starter policy under `MNDE_HOME`. Idempotent; reuses existing material. |
| `sidecar start` (`up`)  | Run the sidecar in the foreground. Bootstraps missing assets, validates the environment, prints a `Status: READY` banner, streams logs until `Ctrl+C`. |
| `sidecar stop` (`down`) | Signal a running foreground/detached sidecar to shut down.              |
| `sidecar status` (`ps`) | Report whether the sidecar is reachable and on which bind address.      |
| `sidecar logs`          | Tail the sidecar log stream (`--follow`/`-f` to stream).               |
| `sidecar smoke`         | End-to-end proof: one decision → signed receipt → verified. Exit `0` only if the receipt verifies. |

Relevant environment: `MNDE_BIND_PORT` (default `8787`), `MNDE_SMOKE_PORT`
(default `8788`), `MNDE_RECEIPTS_DIR` (default `<home>/receipts`).

`start` is a foreground service by design; process supervision (systemd, a
container runtime, `&`) is the operator's responsibility. v1 does not daemonize.

---

## 6. `mnde receipt` — verify and search receipts

Plumbing group over the unified verifier (`tools/verify.mjs`) and the receipt
index (`src/receipt-index/`).

### 6.1 `receipt verify <file>`

Verifies any MNDe receipt regardless of which engine produced it (auto-detects
`mnde.signed-receipt.v1`, `mnde.pe.receipt.v1/v2`, and the legacy pipeline
format). Trust material:

```text
mnde receipt verify <receipt.json>
    [--authority-bundle <bundle.json>]
    [--policy-bundle <bundle.json> --policy-authority-bundle <bundle.json>
     --policy-root-fingerprint <hex>]
    [--trusted-root-fingerprint <hex>]
```

`--home`/`MNDE_HOME` matters here: a policy-engine receipt signed under a
particular home must be verified with that same home so the local authority
bundle resolves. Exit `0` = VERIFIED, `3` = verification failed/tampered,
`1` = could not read/parse the receipt.

### 6.2 `receipt show`

Displays a single receipt by content address or path:

```text
mnde receipt show --request-hash <hex64>
mnde receipt show --path <file> [--line N]
```

`--path` needs no index. Emits the receipt plus its verification status.

### 6.3 `receipt find`

Queries the index (or scans directly with `--no-index`):

```text
mnde receipt find [filters...] [--verified-only] [--limit N] [--cursor C]
                  [--format json|table]
```

Filters (repeatable, comma-splittable): `--decision`, `--reason-code`,
`--tenant`, `--actor`, `--tool`, `--request-id`, `--request-hash`,
`--policy-hash`, `--policy-version`, `--rule-id`, `--key-id`, `--region`,
`--surface`, `--schema-version`, plus ranges `--since`, `--until`, `--min-cost`,
`--max-cost`.

Exit: `0` ok; `2` when `--verified-only` dropped at least one hit (preserving the
current CLI's convention); `1` on error.

### 6.4 `receipt index`

Builds or syncs the on-disk index:

```text
mnde receipt index [--rebuild] [--root <dir-or-file>]... [--db <file>] [--status]
```

Default roots: `./mnde-receipts`. Default db:
`<first-root>/.receipt-index/receipts.db`.

### 6.5 `receipt stats`

```text
mnde receipt stats --group-by decision|reason_code|schema_version|surface|tenant_id|actor
```

Emits deterministic grouped counts.

---

## 7. `mnde ledger` — execution-ledger operations

Plumbing group over the execution ledger (`src/execution-ledger/`). The ledger is
an append-only Merkle log of decisions; v2 entries are signed.

| Command                 | Purpose                                                                        |
| ----------------------- | ----------------------------------------------------------------------------- |
| `ledger verify`         | Verify the whole chain. Exit `1` on any failure.                              |
| `ledger head`           | Print the current chain head.                                                 |
| `ledger export`         | Print the ledger as a JSON export object.                                     |
| `ledger prove`          | Emit a single-receipt offline **inclusion proof** from an anchored ledger.    |
| `ledger verify-proof`   | Verify an inclusion-proof bundle fully offline against a trusted public bundle.|

Shared options: `--ledger <path>`, `--receipt-root <dir>`, `--bundle <path>`
(trusted public authority bundle that signs v2 entries), `--legacy` (accept
unsigned v1 entries for audit/migration reads). Environment overrides:
`MNDE_EXECUTION_LEDGER_PATH`, `MNDE_RECEIPT_LOG`, `MNDE_AUTHORITY_BUNDLE`.

`prove`/`verify-proof` specifics:

```text
mnde ledger prove --ledger <file> --checkpoints <file> --receipt-store <file>
                  --bundle <public-bundle> --receipt-hash sha256:...
                  [--out <proof.json>]

mnde ledger verify-proof <proof.json> --bundle <public-bundle>
```

`verify-proof` reads only its two inputs — no network, no filesystem beyond
them, no trust in whoever produced the proof.

---

## 8. `mnde authority` — trust-material lifecycle

Plumbing group over the custody lifecycle (`src/custody/`,
`bin/mnde-authority.mjs`). Operates on a **published authority bundle's** signing
keys. The root private key is used only to re-sign the bundle; output is verified
before it is written; **the input bundle is never overwritten unless `--force`,
and nothing is written on any error** (fail closed).

| Command             | Purpose                                                              |
| ------------------- | ------------------------------------------------------------------- |
| `authority init`    | Provision a production authority bundle + root key.                 |
| `authority rotate`  | Introduce a new signing key and retire the prior one.              |
| `authority revoke`  | Mark a key revoked (`revoked_at`).                                 |
| `authority export`  | Export the public authority bundle for distribution to verifiers.  |
| `authority show`    | Print the bundle's keys, roles, fingerprints, and validity windows. |

`rotate`:

```text
mnde authority rotate --bundle <in> --root-key <root.pem> --key-id <id>
    (--new-public <pub.pem> | --generate --new-private-out <priv.pem>)
    [--role receipt] [--valid-until <iso>] [--now <iso>] --out <out> [--force]
```

`revoke`:

```text
mnde authority revoke --bundle <in> --root-key <root.pem> --key-id <id>
    [--now <iso>] --out <out> [--force]
```

`--out` must differ from `--bundle` unless `--force` (keep the prior bundle for
rollback). Revoking a key with no successor is refused.

### 8.1 Standard output contract

- Human output is the default and goes to `stdout`.
- `--json` produces exactly one JSON document on `stdout` and nothing else there.
- All diagnostics, progress, and warnings go to `stderr`.
- Output is deterministic where the underlying data is deterministic (canonical
  JSON, stable key ordering) so it can be diffed and hashed.

### 8.2 JSON error object

Under `--json`, a failing command still emits a single object on `stdout`:

```json
{
  "ok": false,
  "error": {
    "code": "ERR_RECEIPT_SIGNING_KEYS_MISSING",
    "message": "human-readable summary",
    "command": "receipt verify"
  }
}
```

`code` reuses the repository's existing `ERR_*` / `reason_code` vocabulary where
one applies.

### 8.3 Decision-aware exit codes

The exit-code space distinguishes *errors* from *legitimate non-allow outcomes*
so callers can branch without parsing text.

| Code | Class            | Meaning                                                              |
| ---- | ---------------- | ------------------------------------------------------------------- |
| `0`  | success          | Command succeeded; for `decide`, decision is `ALLOW` and verified.  |
| `1`  | error            | Operation failed (bad input, I/O, internal error). Fail closed.    |
| `2`  | usage / partial  | Usage error, **or** a partial-result signal (`find --verified-only` dropped hits). |
| `3`  | verification     | A receipt/proof/ledger was produced or read but failed verification. |
| `10` | refuse           | `decide` produced a verified `REFUSE`.                              |
| `11` | approval         | `decide` requires manual approval; none supplied.                   |

Codes `10`–`11` are specific to `decide`. Every other command uses `0`–`3`.
`ledger verify` and `receipt verify` use `3` for verification failure, `1` for
I/O failure.

---

## 9. Configuration

Precedence, highest wins:

1. Command-line flags.
2. Environment variables (table in [§3](#3-global-options) and per-group notes).
3. Config file (`--config`, default `<home>/config.json`).
4. Built-in defaults.

The config file is optional JSON. Recognized keys mirror the global options and a
few group defaults:

```json
{
  "home": "./.mnde",
  "json": false,
  "sidecar": { "bindPort": 8787, "receiptsDir": "./.mnde/receipts" },
  "receipt": { "roots": ["./mnde-receipts"] },
  "ledger":  { "bundle": "./authority/public-bundle.json" }
}
```

Unknown keys are ignored with a `--verbose` warning (forward-compatible), not an
error. No secret material is ever read from or written to the config file; keys
live only under `<home>/shared/receipt_keys/` with `0600` permissions.

---

## 10. Help and discoverability

- `mnde` with no arguments prints the top-level command list and exits `0`.
- `mnde help` and `mnde --help` are equivalent.
- `mnde <group>` with no subcommand prints that group's subcommands and exits `2`
  (a group requires a verb).
- `mnde help <command>` and `mnde <command> --help` print the same detailed help.
- Help text names, for each command: synopsis, the options, the exit codes it can
  return, and the env vars it honors.

---

## 11. Compatibility and versioning

- The CLI carries its own semantic version, reported by `mnde version`.
- **Plumbing `--json` schemas** and **exit codes** are stable within a major
  version. Additive fields may appear in minor versions; existing fields do not
  change type or meaning without a major bump.
- **Porcelain human output** may be refined between minor versions; scripts must
  use `--json`.
- The CLI version is independent of the receipt/ledger/authority *schema*
  versions, which are governed by their own specs; `mnde version` reports both.

---

## 12. Implementation status

This maps the specified surface to code that exists today. "Exists" means the
behavior is already implemented (possibly under a different entry point);
"new wiring" means the behavior exists but must be re-exposed under the unified
grammar; "proposed" means not yet built.

| Spec command            | Today                                                      | Status       |
| ----------------------- | --------------------------------------------------------- | ------------ |
| `mnde init/uninstall/status` | `bin/mnde.mjs`                                        | Exists       |
| `mnde decide`           | `bin/mnde.mjs decide`                                      | Exists (exit codes `10`/`11` proposed) |
| `mnde sidecar *`        | `bin/mnde-sidecar.mjs`, `scripts/start-sidecar.mjs`       | New wiring (`init`/`start`/`doctor`/`smoke` exist; `stop`/`logs`/`status` proposed) |
| `mnde doctor`           | `bin/mnde-sidecar.mjs doctor`                              | New wiring   |
| `mnde receipt verify`   | `tools/verify.mjs`, `tools/verify-receipt.mjs`            | New wiring   |
| `mnde receipt find/show/index/stats` | `src/receipt-index/cli.mjs`                  | New wiring   |
| `mnde ledger verify/head/export` | `scripts/verify-ledger.mjs`                      | New wiring   |
| `mnde ledger prove/verify-proof` | `scripts/ledger-proof.mjs`                       | New wiring   |
| `mnde authority rotate/revoke` | `bin/mnde-authority.mjs`                            | New wiring   |
| `mnde authority init`   | `scripts/init-production-authority.mjs`                    | New wiring   |
| `mnde authority export` | `scripts/export-authority-bundle.mjs`                     | New wiring   |
| `mnde authority show`   | —                                                         | Proposed     |
| `mnde policy draft/verify/show` | `src/policy-drafting/`, `src/policy-engine/receipt.mjs` | New wiring / proposed |
| `mnde version`          | —                                                         | Proposed     |
| Global `--json`/`--home`/exit-code contract | partial per entry point                        | Proposed (unification) |

The first implementation iteration is a **dispatcher**: `bin/mnde.mjs` grows a
command router that delegates to the existing modules (not the scripts) behind the
grammar above, normalizing option parsing, `--json`, and exit codes. No decision,
receipt, authority, or ledger logic is reimplemented — the CLI is a thin,
audited-module-only surface, consistent with goal #1 and the "no new trust path"
constraint the sidecar CLI already follows.

---

## 13. References

- [Pre-execution authorization overview](execution-firewall-overview.md)
- [Execution receipt spec v1](execution-receipt-spec-v1.md)
- [Execution request v1](execution-request-v1.md)
- [MNDe Policy Engine production spec v1](mnde-policy-engine-production-spec-v1.md)
- [Execution ledger](execution-ledger.md)
- [Authority grant v1](authority-grant-v1.md)
- [Key custody](key-custody.md)
- [Receipt search spec](RECEIPT_SEARCH_SPEC.md)
- [Onboarding](onboarding.md) · [Discovery](discovery.md) · [Wiring](wiring.md)
- [Production readiness](production-readiness.md)
