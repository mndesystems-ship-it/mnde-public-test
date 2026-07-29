# Ledger anchoring Phase 1 — follow-up security findings

These findings were identified while remediating the P0 ledger route
authorization bypass (see
[`security-note-ledger-route-authorization.md`](./security-note-ledger-route-authorization.md)).
They are **out of scope for the P0 hotfix** and are recorded here so they are not
silently folded into the authorization patch. Each should be tracked as its own
issue/PR.

Fixing the authorization bypass does **not** resolve any of these. The Phase 1
ledger remains at assurance `operator-signed-inclusion` and is not
production-ready on the strength of the auth fix alone.

---

## P1

### P1-1 — Proof CLI must require an independently supplied trust root

* **Security impact:** If the proof verifier trusts a root embedded in (or
  travelling with) the bundle it is checking, a forged bundle can carry its own
  root and self-verify. Verification must be anchored to a root supplied
  out-of-band by the verifier.
* **Affected components:** `scripts/ledger-proof.mjs`,
  `src/execution-ledger/proof.mjs` (`verifyProofBundle`), any CLI/docs that
  demonstrate proof verification.
* **Acceptance criteria:** The CLI refuses to verify unless the caller supplies a
  trusted root fingerprint (e.g. `--trusted-root <fingerprint>` or an explicit
  trusted authority bundle path); a bundle whose root does not match the supplied
  fingerprint fails closed with a distinct reason code.
* **Migration concerns:** Existing scripted invocations without a trust-root flag
  will start failing — intended. Update runbooks and reviewer-kit flows.
* **Required tests:** verify passes with correct supplied root; fails with
  `NO_TRUST_BUNDLE`/root-mismatch when the root is absent or attacker-substituted.
* **Serialized format / compatibility:** No wire-format change; CLI contract
  change only.

### P1-2 — Reject duplicate JSON keys in all trust artifacts

* **Security impact:** Duplicate-key JSON lets a producer and a verifier disagree
  on a field's value (last-wins vs first-wins), enabling canonicalization/
  signature-scope confusion across receipts, checkpoints, anchors, proofs,
  manifests, and authority/trust bundles.
* **Affected components:** every parse path for the above artifacts
  (`shared/json.*`, `src/execution-ledger/*`, custody/authority bundle loaders,
  policy-bundle loaders).
* **Acceptance criteria:** A strict parser rejects any object containing a
  duplicate key with a deterministic reason code, applied uniformly to all
  security-relevant artifacts.
* **Migration concerns:** Legitimate artifacts never contain duplicate keys, so
  no valid input regresses; watch for lenient producers.
* **Required tests:** each artifact type rejects a duplicate-key payload; valid
  payloads still parse; canonicalization is unchanged for valid inputs.
* **Serialized format / compatibility:** No format change; stricter acceptance.

### P1-3 — Legacy receipt verification must bind to the same authority context

* **Security impact:** If legacy receipt verification is not bound to the same
  authority context as the checkpoint and proof, a receipt validated under one
  authority could be presented as included under another, decoupling receipt
  trust from ledger trust.
* **Affected components:** legacy receipt verification path, proof/checkpoint
  authority binding in `src/execution-ledger/*` and receipt verification in
  `sidecar/production_api.mjs`.
* **Acceptance criteria:** Receipt verification, checkpoint verification, and
  proof verification all resolve against one authority context; a mismatch fails
  closed.
* **Migration concerns:** Ensure historical receipts signed under a prior (still
  trusted) authority key remain verifiable via the authority bundle's key
  validity windows.
* **Required tests:** cross-authority receipt/proof mismatch is rejected;
  same-authority happy path still verifies; historical-key receipts still pass.
* **Serialized format / compatibility:** Possible additive binding field; assess
  backward compatibility for already-issued receipts.

---

## P2 / design review

### P2-1 — `log_id` scoping to a security domain

* **Security impact:** A globally reused `log_id` cannot distinguish deployments,
  tenants, or environments, so a proof from one domain could be presented as
  authoritative in another.
* **Affected components:** ledger identity / `log_id` derivation, checkpoint and
  proof schemas, anything asserting stable-identity guarantees.
* **Acceptance criteria:** `log_id` is scoped to an explicit security domain
  (deployment / tenant / environment) **without** breaking the stable-identity
  requirements that downstream consumers depend on.
* **Migration concerns:** This likely touches a serialized/identity field and is
  therefore a compatibility-sensitive change — design review required before
  implementation; may need a migration/versioning story for existing logs.
* **Required tests:** proofs from one domain do not verify as another; stable
  identity within a domain is preserved across restarts.
* **Serialized format / compatibility:** **Yes — affects serialized identity.**
  Treat as a format-versioned change.

---

*Not implemented in the P0 branch. The P0 branch changes only the route
authorization map, adds fail-closed handling for unknown sensitive routes, and
adds regression tests.*
