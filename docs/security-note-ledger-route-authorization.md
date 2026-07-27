# Security note — ledger route authorization (P0 hotfix)

**Date:** 2026-07-27
**Severity:** P0 (critical) — unauthenticated authorization bypass
**Baseline:** `main` @ `3c07011` (PR #7, "execution-ledger anchoring Phase 1")
**Fix branch:** `hotfix/ledger-route-authorization`
**Assurance label unchanged:** `operator-signed-inclusion`

## What was vulnerable

PR #7 added three anchoring endpoints to the local sidecar:

| Route | Method | Operation |
| --- | --- | --- |
| `/ledger/checkpoint` | GET | read the signed checkpoint head |
| `/ledger/proof` | GET | read a single-receipt inclusion proof |
| `/ledger/anchor` | POST | mint a signed checkpoint (state-changing) |

These routes were **absent from the capability map** (`SENSITIVE_PATHS` in
[`sidecar/auth_authority.mjs`](../sidecar/auth_authority.mjs)). Because
`requiredCapabilityForPath()` returns `null` for any unmapped path, and
`authorizeAuthorityAction()` treated a `null` capability as *"no authority
required"* and returned `{ ok: true }`, the authorization check on each route was
a silent no-op.

## Why the lookup failed (root cause)

```
requiredCapabilityForPath("/ledger/anchor")  ->  null     // not in SENSITIVE_PATHS
authorizeAuthorityAction("/ledger/anchor", <no assertion>)
    -> capability === null  ->  return { ok: true }        // FAIL-OPEN
```

The request handlers *did* call the authorization helpers, so the code looked
protected on inspection — but with no mapped capability the helpers authorized
everyone. In production this meant an **unauthenticated caller could read
checkpoint state, read inclusion proofs, and trigger on-demand anchoring**.

Reproduced at `3c07011`: all three routes returned `{ ok: true, capability: null }`
for a request carrying no authority assertion.

## Security impact

* Unauthenticated disclosure of checkpoint head and per-receipt inclusion proofs.
* Unauthenticated triggering of anchoring work (Merkle computation + a signed
  checkpoint advance) — a state-changing, resource-consuming operation.

## The fix

1. **Explicit least-privilege capabilities** for each route, drawn from the
   existing vocabulary and mirroring the closest existing sibling route:

   | Route | Operation class | Required capability | Held by |
   | --- | --- | --- | --- |
   | `/ledger/checkpoint` | read (head) | `inspect_receipts` | ADMIN, OPERATOR, AUDITOR |
   | `/ledger/proof` | read (proof) | `verify_receipts` | ADMIN, OPERATOR, AUDITOR |
   | `/ledger/anchor` | **state-changing** | `manage_runtime` | **ADMIN only** |

   `manage_runtime` is strictly stronger than the read capabilities, so a
   read-only authority (e.g. an AUDITOR holding `inspect_receipts` /
   `verify_receipts`) can **never** trigger anchoring.

2. **Fail closed at the authorization boundary (order-independent).**
   `authorizeAuthorityAction()` evaluates `requiredCapabilityForPath()` first and,
   when it is `null` **and** the normalized pathname is in a sensitive namespace
   (`isSensitiveNamespacePath()` → `/ledger/*`), refuses with a stable
   `{ ok: false, reason: "ERR_AUTH_CAPABILITY_UNMAPPED", status: 403, capability: null }`.
   This holds regardless of the caller's credentials (absent, invalid, or a valid
   admin) and regardless of where a handler sits relative to the post-dispatch
   namespace guard. **A ledger handler registered without a `SENSITIVE_PATHS`
   entry can therefore never receive an allow result — route ordering cannot
   recreate the bypass.** Unmapped paths *outside* a sensitive namespace keep their
   historical "no authority required" behavior.

3. **Defense-in-depth namespace guard.** The production-only post-dispatch guard
   for unmatched `/ledger/*` routes (403 instead of a bare `404`) is retained as a
   second layer. It is **no longer the primary protection** — the boundary check in
   (2) is — but it still catches truly-unrouted sensitive paths (no handler) with
   the uniform `ERR_AUTH_REFUSED`.

4. **Authorization before work.** Each guard runs before any anchoring, proof
   load, or checkpoint read, so an unauthorized caller causes no Merkle work and
   no ledger mutation.

### The order-independence invariant

* **Known ledger routes are explicitly mapped** in `SENSITIVE_PATHS`
  (checkpoint → `inspect_receipts`, proof → `verify_receipts`, anchor →
  `manage_runtime`).
* **Registered-but-unmapped sensitive routes are rejected inside authorization**
  (`ERR_AUTH_CAPABILITY_UNMAPPED`, 403), before the handler body executes.
* **The guarantee does not depend on route ordering** — it lives at the shared
  authorization boundary, not in the dispatcher.
* **The final namespace guard is defense in depth**, kept as a backstop.

This change does **not** alter the Merkle construction, trust roots, receipt
formats, checkpoint formats, or the Phase 1 assurance level
(`operator-signed-inclusion`).

### Environment behavior (unchanged posture)

* **Production** (`MNDE_PROFILE=production`): fail closed — every route requires
  its mapped capability; unknown `/ledger/*` is denied.
* **Local/dev** (`MNDE_PROFILE=local`, the default): the localhost dev
  pass-through for these local operations is preserved (the existing
  `tests/test_ledger_anchor.mjs` round-trip continues to work without an
  authority assertion). This mirrors how the sibling `/ledger/head` read already
  behaves and is explicitly environment-gated.

## Error hygiene

Denials use the repository's uniform external auth error
(`ERR_AUTH_REFUSED`) and never reveal the internal reason (missing/expired/
replay/authz), the required capability, existence of a receipt or checkpoint,
Merkle state, or filesystem paths.

## What this fix does **not** change

* The **Merkle construction was not modified**. The assurance label remains
  `operator-signed-inclusion`. This is **not** a witnessed log.
* Fixing this bypass does **not** make the Phase 1 ledger production-ready. The
  remaining Phase 1 trust and parsing findings are unresolved and tracked in
  [`ledger-phase1-followup-findings.md`](./ledger-phase1-followup-findings.md)
  (independent proof trust root, duplicate-key JSON rejection, legacy receipt
  authority-context binding, `log_id` scoping).

## Tests

`tests/test_ledger_auth.mjs` (`npm run test:ledger-auth`) — 22 cases covering the
authorization-unit layer and the live production request path: unauthenticated
denial, invalid/tampered/expired/wrong-capability denial, query-string and
trailing-slash handling, hostile path normalization, unknown-namespace
fail-closed, authorized success for each route, read-only-cannot-anchor, and
no-mutation-on-unauthorized-anchor.

Order-independence is proven two ways: (a) unit assertions that
`authorizeAuthorityAction()` refuses an unmapped sensitive path with
`ERR_AUTH_CAPABILITY_UNMAPPED` even for a valid admin assertion; and (b) a live
test that wires a **registered-but-unmapped** `/ledger/__authz_probe` handler
(behind the `MNDE_TEST_UNMAPPED_LEDGER_PROBE` flag, inert in real deployments)
**before** the namespace guard, whose body appends to an observable file only on
allow — the request returns `403 ERR_AUTH_CAPABILITY_UNMAPPED` and the file is
never written, proving the refusal comes from authorization, not from the later
unknown-route guard.
