# Execution Grant (`mnde.execution-grant.v1`) — CAP-1

An **execution grant** is a cryptographically signed, independently verifiable
capability representing permission for **one bounded execution**. It is the first
building block of MNDe's Rung 1 architecture (un-bypassable pre-execution gating
through a mandated egress boundary).

CAP-1 delivers only the **artifact** and proves exactly one statement:

> MNDe can mint and independently verify a signed capability that represents
> permission for a single bounded execution, cryptographically bound to a
> specific ALLOW decision receipt.

CAP-1 deliberately does **not**:

- decide *who* may request a grant (**CAP-2**),
- require possession of a grant at any execution boundary (**CAP-3**),
- enforce single-use / redemption (**CAP-3**),
- prevent bypassing the boundary at the network/deployment layer (**CAP-4**), or
- remove the remaining standing-credential bypass (**CAP-5**).

Nothing in CAP-1 is wired into a runtime path. `src/grants/{issue,verify}.mjs` are
library functions with no side effects and no network access.

## What a grant binds

A grant extends a signed decision receipt. It pins the receipt's four binding
hashes so a grant can never be paired with a different decision:

| Field | Meaning |
|---|---|
| `execution_id` | the exact invocation the decision authorized |
| `decision_hash` | the exact signed decision |
| `request_hash` | the exact request bytes |
| `policy_hash` | the policy that authorized it |

Plus the capability's own bounds:

| Field | Meaning |
|---|---|
| `scope.protocol` / `scope.resource` / `scope.target` | where the grant may act. For database protocols the target **must** name `database` + `operation` (e.g. `DELETE`, `DROP`, `TRUNCATE`). |
| `limits.max_cost_cents` | hard cost ceiling (non-negative integer) |
| `limits.max_calls` | call ceiling (≥1; single-use by default, enforced in CAP-3) |
| `limits.not_before` / `limits.not_after` | validity window (short TTL) |
| `signature` | Ed25519, produced by the **same custody authority** that signs receipts — no new PKI |

The signature covers every field **except** `issuer_key_id` and `signature`
themselves. `canonicalGrantPayload()` returns exactly those signed bytes, and
`shared/json.canonicalizeJson` gives a deterministic serialization (sorted keys,
safe-integer numbers), so the same grant always produces the same bytes and the
same Ed25519 signature.

## API

```js
import { issueExecutionGrant } from "./src/grants/issue.mjs";
import { verifyExecutionGrant } from "./src/grants/verify.mjs";

// Mint (server side): sign an ALLOW receipt into a bounded grant.
const { ok, grant } = await issueExecutionGrant({
  receipt,                       // an ALLOW decision receipt (legacy/PE/custody)
  request: {
    scope:  { protocol: "postgres", resource: "db/prod/orders",
              target: { database: "prod", table: "orders", operation: "DELETE" } },
    limits: { max_cost_cents: 0, not_after: "2026-08-10T00:01:00.000Z" }
  },
  signer: provider.signReceipt, // custody Ed25519 signer (loadSigningConfig)
  bundle: provider.getPublicBundle()
});

// Verify (anywhere, offline): no issuer, no network.
const v = await verifyExecutionGrant(grant, {
  authorityBundle: bundle,
  trustedRootFingerprint: fingerprint,
  receipt                       // optional: enforce the exact receipt binding
});
// -> { ok: true, verified: true, grant_id, execution_id, scope, limits, issuer_key_id }
```

## Security invariants (all covered by `test:execution-grant`)

1. **Independently verifiable** offline against a published authority bundle — no
   issuer involvement, no network.
2. **Tamper-evident.** Mutating any signed field (scope, a binding hash, a cost
   cap) after signing → `ERR_GRANT_INVALID_SIGNATURE`. Escalating `DELETE` → `DROP`
   is a signature break.
3. **Bound to one decision.** Verifying a valid grant against a different receipt
   → `ERR_GRANT_REQUEST_MISMATCH`.
4. **Time-bounded.** Outside `[not_before, not_after]` → `ERR_GRANT_NOT_YET_VALID`
   / `ERR_GRANT_EXPIRED`.
5. **Root-anchored trust.** Missing bundle → `ERR_GRANT_BUNDLE_REQUIRED`; wrong
   trusted root → `ERR_GRANT_BUNDLE_UNTRUSTED`; a grant from another authority does
   not verify → `ERR_GRANT_INVALID_SIGNATURE`.
6. **Fail-closed issuance.** A non-ALLOW receipt (`ERR_GRANT_RECEIPT_NOT_ALLOW`),
   an unbindable receipt (`ERR_GRANT_RECEIPT_UNBINDABLE`), a malformed DB scope
   (`ERR_GRANT_SCOPE_INVALID`), or invalid limits (`ERR_GRANT_LIMITS_INVALID`)
   cannot mint a grant.
7. **Deterministic.** Same inputs → identical canonical bytes → identical Ed25519
   signature.

## Stable failure codes

`ERR_GRANT_MALFORMED`, `ERR_GRANT_SCHEMA_UNSUPPORTED`, `ERR_GRANT_SCOPE_INVALID`,
`ERR_GRANT_LIMITS_INVALID`, `ERR_GRANT_NOT_YET_VALID`, `ERR_GRANT_EXPIRED`,
`ERR_GRANT_BUNDLE_REQUIRED`, `ERR_GRANT_BUNDLE_UNTRUSTED`,
`ERR_GRANT_INVALID_SIGNATURE`, `ERR_GRANT_REQUEST_MISMATCH`,
`ERR_GRANT_RECEIPT_NOT_ALLOW`, `ERR_GRANT_RECEIPT_UNBINDABLE`,
`ERR_GRANT_SIGNING_FAILED`, `ERR_GRANT_SIGNING_KEY_INVALID`.

These strings are part of the artifact contract; CAP-3's redemption proxy branches
on them, so they do not change without a schema bump.
