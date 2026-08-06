# MNDe Receipt Formats — v1 Lifecycle

This is the authoritative status of each MNDe receipt schema for v1. It tells a
developer which format to produce and guarantees what stays verifiable.

## Lifecycle table

| Schema | Status | Role | Produced by |
|---|---|---|---|
| `mnde.pe.receipt.v1` | **Stable / canonical** | The v1 execution-authority receipt. New development targets this. | Policy engine (the default decision engine) |
| `mnde.signed-receipt.v2` | **Stable / canonical** | Explicit authority-only or executor-and-authority custody envelope. | `file-backed-production` / external-signer custody |
| `mnde.signed-receipt.v1` | **Stable / verify-only** | Historical authority-only custody envelope. | Earlier custody-signing releases |
| `ecs.receipt.v2` | **Legacy — verify-only, feature-frozen** | The legacy GPU/compute-cost pipeline receipt. No new fields/features. Kept verifiable for historical receipts. | Legacy pipeline, only under `MNDE_DECISION_ENGINE=legacy` |

Definitions:

- **Stable / canonical** — the supported target for new integrations; covered by
  conformance vectors; the format MNDe emits by default.
- **Legacy — verify-only, feature-frozen** — still verifies (so existing receipts
  and audits keep working), but is not extended and is not produced by default.

## What is guaranteed

- A zero-config / default sidecar emits `mnde.pe.receipt.v1`.
- Every schema above continues to verify offline through `tools/verify.mjs`
  (`node tools/verify.mjs <receipt.json>`), which auto-detects the schema and
  reports a `kind` (`policy-engine` / `custody-signed` / `pipeline`).
- Existing conformance vectors remain locked in `conformance/manifest.lock.json`
  and enforced by `npm run test:conformance`; the executor-bound v2 process test
  independently exercises live issuance and verification. Reclassifying
  `ecs.receipt.v2` as legacy does **not** change historical bytes or invalidate
  any existing receipt.
- Executor-bound v2 structure, startup behavior, verification states, key-path
  restrictions, and exact non-claims are documented in
  [`executor-bound-receipts.md`](executor-bound-receipts.md).

## Operator migration note (v1 default change)

The default decision engine is now the **policy engine** (`mnde.pe.receipt.v1`),
not the legacy GPU pipeline. This affects zero-config deployments:

- `npm run sidecar` (or any sidecar started with no `MNDE_DECISION_ENGINE`) now
  runs the policy engine with a **built-in default-deny policy**
  (`mnde.system.default_deny.v1`). It boots normally, health/readiness work, and
  **every decision is a deterministic `REFUSE`** (`reason_code NO_MATCHING_RULE`)
  until a real policy is installed. The API response surfaces the deployment
  state `NO_POLICY_CONFIGURED`; this label is **never** written into the signed
  receipt (the receipt records decision facts only).
- To keep the legacy GPU/cost/runtime-drift governance behavior, set
  `MNDE_DECISION_ENGINE=legacy` explicitly.
- To enforce real authorization, configure a policy (`MNDE_PE_POLICY` for local,
  or a signed policy bundle `MNDE_PE_POLICY_BUNDLE` — required in
  `MNDE_PROFILE=production`).
- An unrecognized `MNDE_DECISION_ENGINE` value fails closed at startup.

A formal legacy→canonical receipt migration/translation tool, if needed, is
tracked for after P0 (no production users depend on `ecs.receipt.v2` translation
today).
