# P0 Architecture Freeze Plan — MNDe v1

Status: PROPOSED (awaiting sign-off on the 4 decisions in §8 before implementation)
Scope: P0 architectural blockers only. No cloud, no UI, no billing, no unrelated features.
Hard rule in force: fail closed by default; no signature/canonicalization change without new tests + regenerated conformance vectors; no casual JS float canonicalization.

This plan is evidence-based against the working tree at `git HEAD` (`6289d72`). Every claim cites a file.

---

## 1. Current state (verified)

### 1.1 Two decision engines, one sidecar
- Default engine is **legacy**: `mnde-local-sidecar.mjs:315` → `const DECISION_ENGINE = resolveDecisionEngine(process.env)`, and `shared/decision-engine.mjs` resolves unset/unknown → `"legacy"`. Policy-engine is opt-in (`MNDE_DECISION_ENGINE=policy-engine`).
- **Legacy** = a GPU/compute-cost governor: `preflight/engine.ts`, `orbit/engine.ts`, `arm/engine.ts`, `ram0na/engine.ts`, orchestrated by `audit/node_runtime.ts`. Its request model (`shared/contracts.ts:49-116`) is `gpu_count`/`hours`/`cost_cents`/`auto_scale`/`kill_switch`/`runtime_observation`. It enforces cost/resource/runtime-drift, not general authz.
- **Policy-engine** = general principal/agent/tool/resource authz: `src/policy-engine/index.mjs` (rules, `all/any/not`, 7 operators, cryptographic authority chain `src/policy-engine/trust.mjs`, authenticated approvals `src/policy-engine/authenticated-approvals.mjs`), wired via `src/policy-engine/sidecar-adapter.mjs`.
- The two enforce **different things**. The adapter `toPolicyEngineRequest` (`src/policy-engine/sidecar-adapter.mjs:79`) can translate a legacy envelope into a PE request, but **lossily**: it keeps only `tool_calls[0]` and drops every GPU/cost/runtime field. A legacy caller routed through PE loses cost/resource/kill-switch enforcement.

### 1.2 Three receipt schemas
- `ecs.receipt.v2` (legacy) — `shared/contracts.ts:180`, verified by `tools/verify-receipt.mjs` (7 checks incl. replay).
- `mnde.pe.receipt.v1` (policy-engine) — `src/policy-engine/receipt.mjs`, verified by `verifyPolicyReceipt` (replays the engine).
- `mnde.signed-receipt.v1` (custody envelope wrapping an inner receipt) — `src/authority-signing/index.mjs`.
- Unified, **Node-only**, offline verifier auto-detects all three: `tools/verify.mjs`.

### 1.3 Canonical JSON is integer-only
- `shared/json.ts:79-99` (`parseNumber`) rejects any decimal/exponent (`invalid_json_number`); `shared/json.ts:230-238` (`serializeNumber`) throws on non-safe-integers. There is no float in the canonical form by construction.
- Consequence in PE: a request whose `parameters` contain a decimal throws inside `canonicalHash` and is caught at `src/policy-engine/index.mjs:338-341` → `REFUSE INVALID_POLICY`. It fails closed, but the failure is **indistinct** (looks like a policy error, not a number-model violation).

### 1.4 Persistence is an unchained append log
- Decision paths end in `receiptQueue.enqueue(signed.receipt)`: PE at `mnde-local-sidecar.mjs:640`, legacy at `:838`. Refusals at `:450`.
- `sidecar/receipt_persistence_queue.mjs` is a durable append queue (modes `strict_audit`/`throughput`, backpressure). Receipts are individually Ed25519-signed but **not** hash-linked. No `prev_entry_hash`/sequence/chain-tip exists anywhere (verified by grep across `src/ shared/ sidecar/ tools/`).
- **`src/execution-gate/` does not exist in this checkout, any branch, the archive branches, `origin/feature/first-user-production`, or the sibling repo.** (Re-verified at `6289d72`, clean tree.) The chained-ledger primitive referenced in the roadmap is **not present here**.

### 1.5 Conformance freeze machinery (already exists)
- `conformance/manifest.json` (vectors: `id, schema_version, path, sha256, expected_kind`) + `conformance/manifest.lock.json` (approved root fingerprint + vector hashes) + `.gitattributes` (forces LF). Enforced by `tests/test_conformance_vectors.mjs`, which **requires vectors for all 5 schemas**: `ecs.receipt.v2`, `mnde.pe.receipt.v1`, `mnde.signed-receipt.v1`, `mnde.authority.bundle.v1`, `mnde.policy.bundle.v1`, and checks each receipt verifies + its `expected_kind`.
- **Any schema/canonicalization change requires regenerating vectors and re-approving `manifest.lock.json`.**

---

## 2. Files involved

| Area | Primary files |
|---|---|
| Engine selection | `shared/decision-engine.mjs`, `mnde-local-sidecar.mjs:315-327,570-669,745-870`, `src/production-posture-preflight.mjs` |
| Legacy pipeline | `preflight/engine.ts`, `orbit/engine.ts`, `arm/engine.ts`, `ram0na/engine.ts`, `audit/node_runtime.ts`, `tools/verify-receipt.mjs` |
| Policy engine | `src/policy-engine/{index,receipt,trust,authenticated-approvals,sidecar-adapter}.mjs` |
| Receipt schemas / verify | `shared/contracts.ts`, `tools/verify.mjs`, `src/authority-signing/index.mjs` |
| Number model | `shared/json.ts`, `src/policy-engine/index.mjs` |
| Ledger | `sidecar/receipt_persistence_queue.mjs`, `mnde-local-sidecar.mjs` (enqueue sites), `tools/verify.mjs` (+ new ledger verifier) |
| Conformance | `conformance/manifest.json`, `conformance/manifest.lock.json`, `.gitattributes`, `tests/test_conformance_vectors.mjs` |
| Harnesses that assume legacy default | `executor/sidecar-harness.mjs`, `scripts/start-sidecar.mjs`, reviewer-kit + many `tests/test_*` (see §4) |

---

## 3. Proposed final v1 shape

1. **Canonical engine = policy-engine.** It is the default authority path. Legacy is reachable only via an explicit `MNDE_DECISION_ENGINE=legacy` **compatibility profile**, documented as legacy/experimental. Unset → policy-engine. Unknown value → fail closed at startup (no silent fallback).
2. **Canonical receipt = `mnde.pe.receipt.v1`**, optionally wrapped in `mnde.signed-receipt.v1` (custody). `ecs.receipt.v2` is reclassified **legacy/experimental**; it remains verifiable (no break to existing receipts) but is not the v1 story. No new feature work is added to it.
3. **Number model = frozen integer-only**, made explicit: canonical JSON permits only safe integers; **decimals must be represented as scaled integers or strings** at the application boundary. A non-integer number yields a **distinct, documented reason code** (e.g. `ERR_NON_INTEGER_NUMBER`) instead of being conflated with `INVALID_POLICY`. We do **not** add float/decimal canonicalization in P0 (it would change every hash and is explicitly out of scope per the hard rules).
4. **Ledger = hash-chained by default.** Each persisted entry commits to the prior entry (`prev_entry_hash` + monotonic `sequence`), the queue enforces the link on append (fail closed on a broken link), and the verifier gains a chain-walk that detects deletion / reordering / duplicate sequence / bad previous hash. Built on top of the existing per-receipt Ed25519 signatures (does not change receipt bytes).

---

## 4. Compatibility impact

- **Flipping the default engine changes enforcement semantics** for any deployment that ran with no engine set and relied on legacy GPU/cost governance. They must now set `MNDE_DECISION_ENGINE=legacy` to keep that behavior. This is the single biggest behavioral change in P0.
- **Zero-config behavior changes.** Legacy decides with the policy embedded in the request; PE requires a configured policy (`MNDE_PE_POLICY` or a signed bundle). With PE as default and no policy configured, the sidecar fails closed (refuses all decisions with a clear reason). This is *more* fail-closed, but it breaks the implicit "just works" demo path.
- **Internal harnesses/tests that start the sidecar with no engine and expect legacy** must be updated to set the legacy profile explicitly (or migrate to PE with a default policy). Confirmed affected by grep (`MNDE_DECISION_ENGINE` absent, legacy-shaped requests): `executor/sidecar-harness.mjs` consumers, `scripts/start-sidecar.mjs`, `tests/test_dashboard.mjs`, `tests/test_executor.mjs`, `tests/test_sidecar_launcher.mjs`, reviewer-kit flow, demo scripts. PE-mode tests already set the engine and are unaffected.
- **Existing `ecs.receipt.v2` receipts keep verifying** — `tools/verify.mjs` and its conformance vector are untouched. No receipt is invalidated.
- **Ledger chaining changes the on-disk log format** (adds chain fields per line). Old unchained logs become "pre-chain" history; the chain starts at a genesis entry. This is additive to receipt bytes (the receipt is embedded unchanged) but changes the persistence record envelope.

## 5. Migration impact

- **Operators:** document a one-line migration — "to keep GPU/cost governance, set `MNDE_DECISION_ENGINE=legacy`; otherwise configure a policy (`MNDE_PE_POLICY` / signed bundle) for the new default." Add to `docs/`.
- **Receipts:** add a short legacy→v1 receipt migration note (the two are different shapes/semantics; this is a re-platform, not a field rename). Verification remains backward-compatible.
- **Conformance:** vectors are regenerated only where bytes change (number-model reason code if it touches a vector; ledger envelope). The 5 receipt/bundle vectors themselves do not change unless we alter canonicalization (we are not).
- **Ledger:** existing append logs are not retro-chained; a documented genesis boundary marks where chaining begins.

## 6. Test plan

Per-chunk: read → smallest change → hostile tests → regenerate conformance vectors only if bytes change → targeted tests → full `npm test` before commit.

- **Engine default:** hostile tests proving (a) unset → policy-engine, (b) explicit `legacy` → legacy, (c) unknown → fail-closed startup refusal, (d) PE default with no policy → fail closed with a clear reason (not a crash, not legacy fallback), (e) production posture still coherent. Update every harness/test in §4 and re-run full suite green.
- **Schema consolidation:** assert `tools/verify.mjs` still verifies all three schemas; add a test asserting `ecs.receipt.v2` is reported as legacy/experimental kind; conformance test stays green.
- **Number model:** hostile tests — integer ok; decimal/exponent/`-0`/unsafe-integer → distinct `ERR_NON_INTEGER_NUMBER` (fail closed), at both parse and canonicalize boundaries; string/scaled-integer representations pass. Fuzz a handful of numeric edge cases. Conformance vectors unchanged (we are not changing canonical bytes, only the error classification surfaced above the canonicalizer).
- **Ledger:** hostile tests for deletion, reordering, duplicate sequence, bad `prev_entry_hash`, genesis tampering, and that the receipt inside each entry still verifies independently. End-to-end: decision → chained entry → offline chain-walk verifies; one tampered link fails closed.

## 7. Risk list

1. **Wide test blast radius from the default flip** (§4). Mitigation: stage as 1a (relabel + make legacy explicit, zero behavior change) then 1b (flip default). Each stays green independently.
2. **Hidden legacy-default dependencies** in demos/installer/reviewer-kit not caught by grep. Mitigation: full `npm test` + reviewer-kit + conformance before each commit.
3. **Number-model change accidentally altering canonical bytes.** Mitigation: the change must live *above* `canonicalizeing` (classify-then-reject), never inside it; conformance vectors must remain byte-identical (asserted by `test:conformance`).
4. **Ledger envelope change breaking durability/throughput semantics or replay.** Mitigation: embed the receipt unchanged; chain fields are envelope-only; keep `strict_audit`/`throughput` behavior; add chain verification as an additive check.
5. **Ledger primitive does not exist here** (§1.4). This is a build, not an integrate. If the roadmap's `src/execution-gate/` exists in another working copy, supplying it converts Chunk 4 from build→integrate. Until then Chunk 4 is scoped as build-then-integrate. **Decision D4 below.**
6. **Production posture coupling:** `isPolicyEnforcementEnabled` reads the raw env, not the resolved default. Flipping the default must keep the production gate coherent (production should still require an explicit, fully-configured engine). Mitigation: covered by engine-default hostile tests (d)/(e).

## 8. Decisions — RESOLVED (signed off)

- **D1 — Default engine flip: YES.** Unset `MNDE_DECISION_ENGINE` → **policy-engine**; legacy only via explicit `=legacy`; unknown value → fail-closed startup refusal.
- **D2 — Zero-config PE behavior: ship a built-in default-deny policy** (not a hidden code path). A real, evaluable policy:
  - `policy_id: mnde.system.default_deny.v1`, `schema_version: 1.0`, `state: ACTIVE`, `rules: []`.
  - Result: every decision matches no ALLOW rule → `REFUSE` with reason `NO_POLICY_CONFIGURED` (mapped from the engine's `NO_MATCHING_RULE`), producing a normal `mnde.pe.receipt.v1` that replays and verifies offline. No special-case verifier path. Installing a real policy changes behavior without changing the authority model.
- **D3 — `ecs.receipt.v2`: reclassify legacy now** (verify-only, feature-frozen). No bridge in P0. Add the lifecycle table (below).
- **D4 — Ledger: defer to end of P0.** Build (or integrate, if you supply `src/execution-gate/`) the chained ledger **after** the engine, receipt, and number model are frozen, so it links the final artifacts and avoids rework. Order: engine → receipt → number model → ledger → conformance → full verify.

### Receipt lifecycle table (frozen for v1)

| Schema | Status | Use |
|---|---|---|
| `mnde.pe.receipt.v1` | **Stable / canonical** | New development; default sidecar output |
| `mnde.signed-receipt.v1` | **Stable / canonical** | Production custody signing envelope (wraps the canonical receipt) |
| `ecs.receipt.v2` | **Legacy** | Verify-only, feature-frozen; emitted only under the explicit `=legacy` compat profile |

---

## 9. Exact implementation chunks (ordered, smallest-change, independently committable)

- **Chunk 1a — Make legacy explicit (no behavior change).** Add `"legacy"` as an explicitly recognized profile in `shared/decision-engine.mjs`; update internal harnesses/tests/demos that rely on the implicit legacy default to set `MNDE_DECISION_ENGINE=legacy`. Default still legacy. Full suite green. *(Zero behavioral change; pure de-risking.)*
- **Chunk 1b — Flip the default to policy-engine.** Change resolution: unset → `policy-engine`; `legacy` → legacy compat; unknown → fail-closed startup. Implement D2 (default-deny policy or fail-closed). Update production-posture coherence. Hostile tests (a–e). Full suite green.
- **Chunk 2 — Consolidate receipt story.** Mark `ecs.receipt.v2` legacy/experimental in `shared/contracts.ts` + docs; confirm `tools/verify.mjs` reports kinds; assert PE receipt is the canonical default output. No byte changes to receipts. Conformance green.
- **Chunk 3 — Freeze + harden the number model.** Surface a distinct `ERR_NON_INTEGER_NUMBER` above the canonicalizer (parse + canonical boundaries), keep canonical bytes identical, document the scaled-integer/string convention in `docs/`. Hostile + fuzz tests. Conformance byte-identical.
- **Chunk 4 — Chained ledger by default.** Build (D4) a `prev_entry_hash`+`sequence` chain in `sidecar/receipt_persistence_queue.mjs`; enforce the link on append (fail closed); add a chain-walk verifier to `tools/verify.mjs`; wire it into the default persistence/export path; receipts embedded unchanged. Hostile tamper tests (delete/reorder/dup-seq/bad-prev/genesis). Full suite green.
- **Chunk 5 — P0 audit.** Re-run full suite + reviewer-kit + conformance + replay; produce a P0 readiness audit (every blocker resolved, evidence cited). Stop. Do not start P1.

Each chunk reports: files changed, tests run/added, conformance status, remaining risks.
