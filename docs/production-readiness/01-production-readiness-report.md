# 1. Production Readiness Report (Product Stability)

Audit of the entire codebase for production stability. Findings are evidence-based; absence claims come from repository-wide pattern sweeps.

## Method & coverage

- 14,284 LOC (`*.mjs` + `*.ts`, excl. `node_modules`); 81 `.mjs`, 21 `.ts`; 20 test suites.
- Sweeps run for each requested smell category (commands reproducible from repo root).

## Stability sweep results

| Category | Result | Evidence |
| --- | --- | --- |
| Placeholder implementations | **None** in product code | only `src/custody/index.mjs:23` documents *future* provider slots, explicitly out of scope |
| Demo-only logic in the authority path | **None** | demo material is isolated (`authority/` fixtures, `examples/`, `cosmetic/`) and never imported by engines |
| Mock / fake / dummy data | **None** (outside tests) | `grep -niE "\b(mock\|fake\|dummy)\b"` empty in non-test code |
| Temporary workarounds (TODO/FIXME/HACK/XXX) | **None** | sweep returns only "temp directory" prose, no markers |
| Incomplete error handling | **Low** | core paths return typed `ERR_*` codes; see notes below |
| Silent failures (empty `catch`) | **None found** | no empty `catch {}`; swallow-only catches are deliberate (`socket.on("error", () => {})`) |
| Stray debug logging | **None in runtime** | `console.*` only in CLIs (`tools/reviewer-kit.mjs`, `bin/`, `scripts/`) |
| Unhandled edge cases | **Low** | fail-closed defaults; see findings P-04/P-07 |
| Startup race conditions | **Low** | see P-06 |
| Configuration corruption risk | **Medium** | see P-07 |
| Upgrade risk | **High** | see P-02 / Operational report |

This is an unusually clean result for a system described as a prototype: the code does not carry the typical markers of unfinished work.

## Confirmed strengths (cited)

- **One execution call site, reachable only after ALLOW.** `executor/index.mjs:6-15` states the safety invariant; the wrapped function is invoked at exactly one place after a well-formed `ALLOW`. Every other path (REFUSE, unreachable sidecar, malformed decision, timeout, throw) returns without executing.
- **Unsigned ALLOW is blocked.** `mnde-local-sidecar.mjs:768-771` refuses an `ALLOW` that lacks a signature (`ERR_RECEIPT_SIGNATURE_INVALID`), counted as `unsigned_allows_blocked`.
- **Worker auto-restart, fail-closed.** `mnde-local-sidecar.mjs:252` restarts a crashed worker without dropping the fail-closed posture.
- **Graceful shutdown.** `mnde-local-sidecar.mjs:1332-1342` drains the receipt queue, worker pool, and sockets on `SIGINT`/`SIGTERM`.
- **Durable receipt persistence.** `sidecar/receipt_persistence_queue.mjs` with a `strict_audit` durability mode awaited before responding.

## Findings

### P-01 (Critical) — Live signing uses development keys by default
`scripts/bootstrap_dev_receipt_keys.mjs` generates Ed25519 receipt keys into `shared/receipt_keys/` and a dev root authority. Live receipt signing mode defaults to `legacy` (production custody is opt-in via `MNDE_RECEIPT_SIGNING_MODE=custody`). A default deployment therefore signs with non-production keys.
- **Risk:** receipts are technically signed but not under a production trust root; "verifiable" is undermined if the root is a dev key.
- **Fix:** make custody the documented production path; add a startup pre-flight that refuses a "production profile" when dev keys are detected. (See Security report S-02.)
- **Status: MITIGATED.** `MNDE_PROFILE=production` now runs a deterministic trust-root pre-flight (`src/authority-signing/preflight.mjs`) that refuses startup unless explicit `file-backed-production` custody is configured and no demo/dev key material is in use. Local/demo mode is unchanged. Proof: `npm run test:trust-root`. Remaining: publish the production authority bundle through a trusted channel (operational).

### P-02 (High) — No runtime upgrade/migration/rollback path
There is no installer or upgrade tooling for the sidecar/runtime itself (`installer/` is a download README). Config migration and rollback for the runtime are undefined.
- **Risk:** unpredictable upgrades; no defined recovery.
- **Fix:** install/upgrade scripts with config backup + migration + rollback (Operational report O-01).

### P-03 (High) — Receipt log unbounded; demo-named default path
`mnde-local-sidecar.mjs:66` defaults `RECEIPT_LOG_PATH` to `hostile-verifier-proof-bundle/receipts.jsonl`, append-only, with no rotation/retention.
- **Risk:** disk exhaustion over time; a proof-bundle path name misleads operators.
- **Fix:** rotation + retention + a stable production data directory default (Operational report O-03).

### P-04 (Medium) — Error handling completeness on secondary endpoints
Core decision/receipt paths are typed and fail-closed. Some administrative/secondary handlers (e.g. `/replay/recent`) fall back to defaults inside `catch` rather than surfacing a typed error to the caller (`mnde-local-sidecar.mjs` replay handler). Behavior is safe (no execution effect) but less explainable.
- **Fix:** return explicit reason codes from all admin endpoints.

### P-06 (Low) — Startup ordering depends on key bootstrap
Receipt/authority keys must exist before signing; if absent, receipt build fails closed (`ERR_AUTHORITY_NO_ACTIVE_KEY`). Tests call `bootstrapReceiptKeys` explicitly. There is no first-run pre-flight that provisions/validates keys for an operator.
- **Fix:** a `mnde doctor`/pre-flight that validates keys, policy, paths, and ports before serving (Operational report O-05).

### P-07 (Medium) — Runtime policy file load lacks backup/checksum
`mnde-local-sidecar.mjs:91` loads the active policy via `JSON.parse(readFileSync(...))` at startup; a corrupt file aborts startup (fail-closed, good) but there is no checksum or last-known-good backup of the *runtime* policy file. Candidate policies submitted via `/policy/activate` *are* validated before taking effect.
- **Fix:** validate + back up the runtime policy on load; refuse activation that would replace a valid policy with an unverifiable one (already partly enforced).

### P-08 (Low) — Pre-1.0 version signals prototype
`package.json` is `0.1.0`; the runtime does not surface a version/build hash.
- **Fix:** adopt a pilot semver, embed version+commit, expose in `/identity` and receipt metadata (Operational report O-04).

## Verdict

Stability of the **core enforcement and evidence path is pilot-ready**. The blocking stability items are P-01 (trust-root provisioning) and the operational items P-02/P-03. None are correctness defects in the decision/receipt/replay path.
