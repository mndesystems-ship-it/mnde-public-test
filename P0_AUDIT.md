# P0 Architecture Freeze — Audit

Scope audited: the P0 architecture-freeze blockers (canonical engine, canonical
receipt, canonical number model). Per decision, the **chained execution ledger is
deferred** as a tracked follow-on (its primitive is absent from this checkout and
it is additive/envelope-level — it does not change the now-frozen receipt or
canonical bytes). No P1 work has been started.

Base: `6289d72`. P0 commits: `35be225` (plan) → `29577e5` (1a) → `eff77a2` (1b) →
`a704097` (2) → `3c617d7` (3).

## Verdict

**The architecture freeze is clean and audited.** The canonical decision engine,
the canonical receipt, and the canonical number model are frozen, fail-closed,
and covered by tests. One P0 line item (the chained ledger) is explicitly
deferred — not silently dropped.

## Blocker resolution

| P0 item | Status | Evidence |
|---|---|---|
| Pick one canonical v1 engine (policy-engine default; legacy opt-in; stop "legacy by default") | **RESOLVED** | `shared/decision-engine.mjs` (unset→policy-engine, unknown→fail-closed); `mnde-local-sidecar.mjs` primary guard; `test:engine-default` (unknown refuses boot; default = PE). Commit `eff77a2`. |
| Zero-config operability without weakening fail-closed | **RESOLVED** | Built-in `mnde.system.default_deny.v1` (`src/policy-engine/default-deny.mjs`); deterministic REFUSE/`NO_MATCHING_RULE` with a verifiable `mnde.pe.receipt.v1`; `NO_POLICY_CONFIGURED` surfaced via API/logs only, never the receipt. `test:engine-default`. |
| Consolidate receipt schemas (canonical = pe.receipt.v1 + signed envelope) | **RESOLVED** | `docs/receipt-formats.md` lifecycle table; `tools/verify.mjs` auto-detects + reports kind. Commit `a704097`. |
| Mark `ecs.receipt.v2` legacy / migration | **RESOLVED** | Reclassified legacy verify-only, feature-frozen (`contracts.ts` marker); still verifies (kind `pipeline`); migration bridge deferred post-P0 per decision. `test:engine-default` verify-only assertion. |
| Resolve canonical JSON number model before freeze | **RESOLVED** | Integer-only frozen + documented (`docs/number-model.md`); distinct `NON_INTEGER_NUMBER` at the library boundary; `ERR_INVALID_JSON_NUMBER` at the wire boundary; `canonicalizeJson` bytes unchanged. `test:number-model` (19/19). Commit `3c617d7`. |
| Wire hash-chained execution ledger by default | **DEFERRED (tracked)** | Primitive `src/execution-gate/` absent from this checkout (re-verified ×4). Additive/envelope-level; does not change frozen receipt/canonical bytes. To be built or integrated against the now-frozen interfaces. |

## Verification (this audit run)

| Check | Result |
|---|---|
| `npm test` (full suite) | PASS — 37/37 scripts |
| `npm run reviewer-kit` | PASS |
| `npm run check:whitespace` | PASS (228 files) |
| `npm run test:replay` | PASS — 11/11 |
| `npm run test:conformance` | PASS — 5/5, **byte-identical** (no canonical/receipt bytes changed across P0) |
| `npm run test:ci-contract` | PASS |
| `git diff --check` | CLEAN |
| working tree | clean, 0 uncommitted |

New hostile gates added in P0: `test:engine-default` (6), `test:number-model` (19);
plus updated `test:production-posture`. All green.

## Behavior changes (for release notes)

1. **Default decision engine is now the policy engine** (`mnde.pe.receipt.v1`).
   Zero-config sidecars boot with a built-in default-deny policy and REFUSE every
   action until a real policy is installed. Set `MNDE_DECISION_ENGINE=legacy` for
   the legacy GPU/cost pipeline. Unknown engine values fail closed at startup.
   (See `docs/receipt-formats.md` migration note.)
2. **`ecs.receipt.v2` is legacy** — verify-only, feature-frozen, emitted only under
   the explicit legacy profile.
3. **Number model is frozen integer-only** — decimals must be scaled integers or
   strings (see `docs/number-model.md`). Non-integers are refused distinctly.
4. Production behavior is **unchanged**: the production posture gate still requires
   an explicit, fully-configured policy engine + signed bundle; default-deny
   applies only to non-production.

## Remaining / known items

- **Chunk 4 — chained ledger:** deferred by decision; build or integrate against
  the frozen `mnde.pe.receipt.v1`. Tamper tests (delete/reorder/dup-seq/bad-prev/
  genesis) to accompany it.
- **`test:production-signing` flakiness:** observed one transient `21/22` in a full
  run (passed in isolation + re-run). Pre-existing port/timing flakiness, not from
  P0 changes. Tracked for P2 release-eng (test isolation / port allocation).
- **Public reviewer-kit/demos still showcase the legacy pipeline** (pinned explicit
  in 1a). Migrating them to PE is post-P0 docs/SDK work.

## Status

P0 architecture freeze: **clean and audited.** Ledger: **deferred (tracked).**
P1: **not started.** All commits are local; nothing pushed.
