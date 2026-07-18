# Policy-engine receipt versioning: `mnde.pe.receipt.v1` → `v2`

This document defines the compatibility boundary between the two policy-engine
receipt formats and the rule that keeps both cryptographically honest.

## Why two versions

`mnde.pe.receipt.v1` is **frozen**. Its decision output and `decision_hash`
material are fixed by the 2026-06-25 conformance vectors, which are permanent
compatibility evidence (`conformance/README.md`). v1 decisions never carry a
`rule_id`.

`mnde.pe.receipt.v2` adds the matched **`rule_id`** to the decision — the id of
the single ALLOW/REFUSE rule that decided the request (`null` when no single
rule decided). `rule_id` exists for receipt search, audit explanation, and
operator visibility, so it must be a real cryptographic commitment, not a
cosmetic display field. In v2 it is therefore bound into `decision_hash`.

Adding `rule_id` to the decision output under the *existing* v1 schema would
silently change v1's `decision_hash` and break the frozen vectors. That is the
mistake this versioning prevents: **new decision material means a new version.**

## The two formats

| Aspect | `mnde.pe.receipt.v1` | `mnde.pe.receipt.v2` |
| --- | --- | --- |
| receipt `schema_version` | `mnde.pe.receipt.v1` | `mnde.pe.receipt.v2` |
| `decision_output.schema_version` | `1.0` | `2.0` |
| `decision_output.rule_id` | absent | present (string or `null`) |
| `rule_id` in `decisionMaterial` | no | yes |
| bound into `decision_hash` | n/a | yes |
| replay drift fields | decision, reason_code, request_hash, policy_hash, authority_chain_hash, decision_hash | the v1 set **plus** `rule_id` |

`decisionMaterial` is the object hashed into `decision_hash`. For identical
inputs, v1 and v2 material differ by exactly one key — `rule_id` — because
canonical JSON sorts keys, so v2's `decision_hash` differs from v1's and any
change to `rule_id` changes `decision_hash`.

## Routing is explicit, never inferred

Both minting (`buildPolicyReceipt`) and verification (`verifyPolicyReceipt`) map
the receipt `schema_version` to a decision-output version through a single table
(`RECEIPT_TO_DECISION_SCHEMA` in `src/policy-engine/receipt.mjs`):

- `mnde.pe.receipt.v1` → decision `1.0`
- `mnde.pe.receipt.v2` → decision `2.0`

A receipt schema with no entry has no contract and **fails closed** — unknown or
future versions are rejected, never guessed from which fields are present. The
engine emits a v2 shape only when explicitly asked
(`evaluatePolicyRequest(..., { decisionSchemaVersion: "2.0" })`); its default is
the frozen v1 shape.

## Fail-closed guarantees (see `tests/test_pe_receipt_v2.mjs`)

1. The frozen v1 vector still verifies unchanged; v1 output has no `rule_id`.
2. v1 replay still rejects decision drift (drift set not weakened).
3. v2 verifies the bound `rule_id`.
4. Tampering with v2 `rule_id` fails on `decision drift: rule_id` (and, because
   it is hashed, `decision_hash` too).
5. Changing only `rule_id` changes `decision_hash`.
6. The verifier rejects a v1 decision body under a v2 header and vice versa
   (`decision schema mismatch`) — the paths never cross-accept.
7. Unknown/future receipt versions fail closed on both verify and mint.

## Conformance

v1 is frozen against the original `mnde-conformance-authority`. v2 has its own
frozen vector (`conformance/vectors/mnde.pe.receipt.v2.allow.json`) signed by a
**dedicated** authority, `mnde-conformance-authority-v2`, whose public bundle
(`conformance/vectors/mnde.authority.bundle.v2.json`) is pinned by an
independent trust root (`trust_roots.conformance_authority_v2`). v2 is verified
through the same offline root-pinned path as v1, under that distinct anchor. The
v1 vectors and their trust root are untouched.

## Receipt search / indexing

The untrusted receipt index reads `decision_output.rule_id` for v2 and tolerates
its absence for v1. It never fabricates a `rule_id` for a v1 receipt. See
`src/receipt-index/extract.mjs` (`KNOWN_SCHEMAS` must include
`mnde.pe.receipt.v2`, and the policy-engine extractor reads `rule_id` only when
present).
