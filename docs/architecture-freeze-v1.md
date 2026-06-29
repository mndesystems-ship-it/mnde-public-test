# MNDe v1 — What Is Frozen

**Baseline:** tag `v1-architecture-freeze` → commit `3c6b109`
**Status:** frozen, fail-closed, independently audited.

This document states the contracts that downstream integrators, reviewers, and
future MNDe work may now build against without expecting them to shift. "Frozen"
means: the shape and the security outcome are stable; changes require a new
version, not an in-place edit.

## Frozen surfaces

### 1. Default authority path = the policy engine
`MNDE_DECISION_ENGINE` resolves as:

| Value | Result |
|---|---|
| unset / empty | `policy-engine` (the canonical v1 authority path) |
| `policy-engine` | policy engine |
| `legacy` | legacy GPU/compute pipeline (explicit opt-in compatibility profile) |
| anything else | **refuses to start** (fail-closed; never silently picks an engine) |

The legacy pipeline is no longer the default. Zero-config sidecars boot with a
built-in `mnde.system.default_deny.v1` policy and **REFUSE every action** until a
real policy is installed. Production posture is unchanged: it still requires an
explicit, fully-configured policy engine plus a signed bundle — the default-deny
convenience applies only outside production.

### 2. Canonical receipt = `mnde.pe.receipt.v1`
The canonical execution receipt is `mnde.pe.receipt.v1`, optionally wrapped in a
`mnde.signed-receipt.v1` envelope under custody signing.

`ecs.receipt.v2` is **legacy: verify-only, feature-frozen.** It still verifies
(reported as kind `pipeline`) so no historical receipt is invalidated, but it
gains no new fields and is emitted only under the explicit `=legacy` profile. A
migration bridge is deferred post-v1 (no production consumer depends on
translation today).

### 3. Canonical number model = integer-only
JSON numbers in policy/decision payloads must be safe integers. Decimals must be
sent as scaled integers (e.g. cents) or as strings.

| Boundary | Rejection |
|---|---|
| Library / SDK call | `NON_INTEGER_NUMBER` |
| Wire / parse | `ERR_INVALID_JSON_NUMBER` |

`canonicalizeJson` serializes integers deterministically (`-0` → `0`) and throws
on non-integers.

### 4. Canonical bytes are stable
No canonical or receipt bytes changed while reaching this freeze. The conformance
suite pins SHA-256 vectors for all five schemas (`ecs.receipt.v2`,
`mnde.pe.receipt.v1`, `mnde.signed-receipt.v1`, `mnde.authority.bundle.v1`,
`mnde.policy.bundle.v1`) against an approved lock; it passes byte-identical.

## What is NOT frozen (deferred / tracked)

- **Chained execution ledger (Chunk 4).** Hash-chained, per-execution ledger by
  default. Deferred by decision — its primitive is absent from this baseline and
  it is additive/envelope-level: it does not alter the now-frozen receipt or
  canonical bytes. It will be built or integrated against the frozen
  `mnde.pe.receipt.v1` interface, with tamper tests (delete / reorder / dup-seq /
  bad-prev / genesis).
- **Public reviewer-kit and demos** still showcase the legacy pipeline (pinned to
  the explicit `=legacy` engine). Migrating them to the policy engine is post-v1
  docs/SDK work.
- **`ecs.receipt.v2` → `mnde.pe.receipt.v1` migration bridge.** Deferred post-v1.

## How this baseline was verified

Independent post-push audit at `3c6b109`:

- `npm test` — 37/37 scripts pass
- `test:engine-default` — 6/6 (default = policy-engine; unknown refuses boot;
  legacy receipt still verifies)
- `test:number-model` — 19/19 (integer-only at both boundaries)
- `test:conformance` — 5/5, byte-identical
- P0 commit range touched no conformance vectors or canonicalization code —
  changes are additive guards and docs only
- No live code references the deferred ledger primitive (clean absence, not
  half-wiring)
