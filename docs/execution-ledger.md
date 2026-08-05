# MNDe Execution Ledger

The execution ledger is an append-only, **signed** hash chain over finalized
receipts, with a Phase-1 Merkle transparency layer that produces offline-verifiable
inclusion proofs. It is a separate integrity layer: it does not change the canonical
receipt format, the signed envelope, the receipt signing path, or standalone receipt
verification. Every finalized receipt gets one ledger entry; the entries form a hash
chain **and each entry is Ed25519-signed by the custody `ledger` key**, so deleting,
editing, reordering, or replacing a receipt (or a ledger line) fails verification
closed, and a forged-but-internally-consistent chain fails on the signature.

This document describes the verified current implementation (entry schema
`mnde.execution_ledger.entry.v2`).

## 1. What the ledger proves

Given an intact ledger, its receipt store, and the trusted authority bundle,
verification proves:

- **Completeness & order** — receipts were recorded in an unbroken, monotonically
  increasing sequence with no gaps and no duplicates.
- **Linkage** — each entry commits to the previous entry's hash, so the history
  cannot be silently truncated, reordered, or spliced.
- **Receipt integrity** — each entry's `receipt_hash` still matches the canonical
  bytes of the referenced receipt; a single changed byte in any recorded receipt
  is detected.
- **Entry integrity** — each `entry_hash` recomputes from its own body.
- **Entry authenticity** — each entry carries an Ed25519 `signature` by the custody
  `ledger` key, verified against the trusted authority bundle. A writer who can
  edit the store cannot mint a chain that verifies without the ledger signing key.
- **Anchored inclusion (Phase 1)** — a single receipt can be proven included in a
  signed checkpoint via an offline Merkle inclusion proof, without downloading the
  ledger and without trusting the proof generator.

## 2. What it does **not** prove

See the [threat model](#9-threat-model). In short: it is a *detection* layer, not
a prevention layer. It cannot defend against an attacker who holds the ledger
signing key, nor — in Phase 1 — against an operator who controls both the ledger
store and the signing key and presents different checkpoint histories to different
parties. See the security and witness boundaries in §9.

## 3. Ledger entry format (v2)

Schema: `mnde.execution_ledger.entry.v2`. One JSON object per line (JSONL).

```json
{
  "schema": "mnde.execution_ledger.entry.v2",
  "sequence": 1,
  "created_at": "2026-06-29T00:00:00.000Z",
  "receipt_hash": "sha256:<hex>",
  "previous_entry_hash": null,
  "entry_hash": "sha256:<hex>",
  "receipt_ref": { "storage": "local", "path": "<safe-relative-path>", "receipt_id": "<id-or-null>" },
  "engine": { "name": "mnde-policy-engine", "version": "<version-or-null>" },
  "signature": { "algorithm": "ED25519", "key_id": "<ledger-key-id>", "value": "<sig>" }
}
```

Rules:

- `sequence` starts at 1 and increments by exactly 1.
- The first entry's `previous_entry_hash` is `null`; every later entry's
  `previous_entry_hash` equals the prior entry's `entry_hash`.
- `receipt_hash` = `sha256:` + SHA-256 of `canonicalizeJson(receipt)` — the **same**
  canonicalization the receipt signature is taken over.
- `entry_hash` = `sha256:` + SHA-256 of `canonicalizeJson(body)` where `body` is the
  entry **without** its `entry_hash` and `signature` fields.
- `signature` is an Ed25519 signature over the canonical signable payload of the
  entry, produced by the custody `ledger` role key. **v2 entries are always signed;
  an append without a `signLedger` custody function fails closed
  (`ERR_LEDGER_SIGNER_REQUIRED`).**
- `receipt_ref.path` must be a safe relative path (no traversal, absolute, drive,
  UNC, or encoded-traversal forms).

## 4. Canonical signed fields, key lookup, revocation, validity

- **Canonical signed payload.** The entry signature covers the canonical
  (`canonicalizeJson`) form of the entry body including `entry_hash` and excluding
  the `signature` object itself. No new canonicalizer is introduced; it is the same
  one used for receipts.
- **Trust-bundle key lookup.** The signature is verified with the `ledger`-role key
  named by `signature.key_id`, resolved in the trusted authority bundle
  (`mnde.authority.bundle.v1`). A trusted bundle is **required** to verify a v2
  entry; without one, verification fails `ERR_LEDGER_NO_TRUST_BUNDLE`.
- **Revocation.** A key revoked as of the entry's `created_at` fails closed. The
  underlying custody verdict (`KEY_REVOKED`) surfaces as
  `ERR_LEDGER_SIGNATURE_KEY_UNTRUSTED`.
- **Validity window.** A key used outside its `valid_from` / `valid_until` window
  (custody verdicts `KEY_EXPIRED`) likewise surfaces as
  `ERR_LEDGER_SIGNATURE_KEY_UNTRUSTED`. Bytes that simply do not verify surface as
  `ERR_LEDGER_SIGNATURE_INVALID`.

## 5. Strict verification (default)

- **Strict is the default.** In strict mode a v2 entry with a valid signature is
  mandatory; a legacy `mnde.execution_ledger.entry.v1` entry is rejected
  (`ERR_LEDGER_LEGACY_ENTRY_REJECTED`). Non-strict mode exists only for reading a
  legacy chain during rollover and still signature-checks any v2 entry present.
- A signature is never accepted as valid without a trusted bundle key.

## 6. Checkpoints, Merkle roots, inclusion proofs (Phase 1)

- **Checkpoint** (`mnde.execution_ledger.checkpoint.v1`) — a ledger-signed statement
  over a Merkle root of the entry hashes for a prefix of the chain
  (`tree_size` entries). Checkpoints are minted off the append lock by the anchor
  scheduler and on demand.
- **Merkle root** — an RFC 6962-style domain-separated tree over the per-entry leaf
  hashes.
- **Inclusion proof** (`mnde.execution_ledger.inclusion_proof.v1`) — a bundle
  carrying the receipt, its entry, the audit path, and the signed checkpoint. A
  fresh offline verifier, given only the proof bundle and a fresh copy of the public
  authority bundle, checks the whole chain:

  ```
  receipt signature -> receipt-to-entry binding -> entry signature
    -> Merkle inclusion -> signed checkpoint -> authority-bundle key validity
  ```

  with no ledger download, no network, and no trust in the proof generator. The
  reported assurance is `operator-signed-inclusion` and the time basis is
  `operator-asserted`.

## 7. Operational modes

- **Default-on.** The ledger is enabled unless explicitly disabled.
- **Signing key required.** The custody `ledger` key must be provisioned
  (`MNDE_LEDGER_SIGNING_KEY`); the production preflight requires it and append fails
  closed without a signer.
- **Storage.** Append-only JSONL, serialized across processes by an exclusive lock
  file (`<ledger>.lock`). The read-modify-write (including signing) happens under the
  lock, so concurrent workers can never mint the same sequence. If the lock cannot
  be acquired within a bounded retry budget, the append fails closed
  (`ERR_LEDGER_LOCK_FAILED`).
- **Env:** `MNDE_EXECUTION_LEDGER_PATH` (explicit path); `MNDE_EXECUTION_LEDGER=off`
  (disable — development only).

## 8. Protected ledger routes

All `/ledger/*` routes are authority-gated. An unmapped sensitive `/ledger/*` route
fails closed at the authorization boundary
(`ERR_AUTH_CAPABILITY_UNMAPPED`, HTTP 403).

| Route | Method | Operation | Required capability |
| --- | --- | --- | --- |
| `/ledger/head` | GET | read the chain head | `inspect_receipts` |
| `/ledger/verify` | GET | verify the chain | `verify_receipts` |
| `/ledger/export` | GET | export all entries | `export_audit` |
| `/ledger/checkpoint` | GET | read the signed checkpoint head | `inspect_receipts` |
| `/ledger/proof` | GET | read a single-receipt inclusion proof | `verify_receipts` |
| `/ledger/anchor` | POST | mint a signed checkpoint (state-changing) | `manage_runtime` (ADMIN only) |

CLI: `npm run ledger:verify`, `npm run ledger:head`, `npm run ledger:export`,
`npm run ledger:prove`, `npm run ledger:verify-proof`.

## 9. Threat model

**The ledger detects:**

- receipt deletion, editing, or replacement
- ledger line editing, deletion, or reordering
- a broken append sequence or missing referenced receipt
- a forged chain minted without the ledger signing key (signature fails)
- a receipt not included in a signed checkpoint (inclusion proof fails)

**The ledger does not prevent:**

- an attacker who holds the ledger signing key
- an attacker with full host control replacing the whole data directory
- pre-ledger tampering before the first trusted checkpoint
- authorized policy mistakes

**Security boundary (Phase 1).** Phase-1 anchoring proves inclusion in an
operator-signed checkpoint. It does not prevent an operator controlling both the
ledger store and signing key from presenting conflicting histories to different
parties.

**Witness boundary.** MNDe detects conflicting or rewritten checkpoint histories
after an independent witness has observed and signed a prior checkpoint. Independent
witnessing is not implemented in Phase 1. (The `witnessed` assurance value and the
`ERR_LEDGER_CHECKPOINT_EQUIVOCATION` code exist as forward-looking scaffolding; the
default assurance today is `operator-signed-inclusion`.)

## 10. Error codes

Stable codes (`LEDGER_ERRORS`):

Chain / entry: `ERR_LEDGER_PARSE`, `ERR_LEDGER_SCHEMA`, `ERR_LEDGER_SEQUENCE`,
`ERR_LEDGER_CHAIN_BROKEN`, `ERR_LEDGER_ENTRY_HASH`, `ERR_LEDGER_RECEIPT_REF_UNSAFE`,
`ERR_LEDGER_RECEIPT_MISSING`, `ERR_LEDGER_RECEIPT_HASH`,
`ERR_LEDGER_DUPLICATE_SEQUENCE`, `ERR_LEDGER_DUPLICATE_ENTRY_HASH`,
`ERR_LEDGER_APPEND_FAILED`, `ERR_LEDGER_LOCK_FAILED`,
`ERR_LEDGER_DISABLED_IN_PRODUCTION`.

Signing / trust: `ERR_LEDGER_SIGNER_REQUIRED`, `ERR_LEDGER_SIGNATURE_MISSING`,
`ERR_LEDGER_SIGNATURE_INVALID`, `ERR_LEDGER_SIGNATURE_KEY_UNTRUSTED`,
`ERR_LEDGER_NO_TRUST_BUNDLE`, `ERR_LEDGER_LEGACY_ENTRY_REJECTED`.

Anchoring / proofs: `ERR_LEDGER_ANCHOR_FAILED`, `ERR_LEDGER_ANCHOR_KEY_UNRESOLVED`,
`ERR_LEDGER_CHECKPOINT_MALFORMED`, `ERR_LEDGER_CHECKPOINT_SIGNATURE_INVALID`,
`ERR_LEDGER_CHECKPOINT_KEY_UNTRUSTED`, `ERR_LEDGER_CHECKPOINT_LOG_ID_MISMATCH`,
`ERR_LEDGER_CHECKPOINT_KEY_EPOCH_MISMATCH`, `ERR_LEDGER_CHECKPOINT_ROLLBACK`,
`ERR_LEDGER_CHECKPOINT_EQUIVOCATION`, `ERR_LEDGER_RECEIPT_INVALID`,
`ERR_LEDGER_RECEIPT_BINDING`, `ERR_LEDGER_INCLUSION_INVALID`,
`ERR_LEDGER_NOT_ANCHORED`, `ERR_LEDGER_PROOF_MALFORMED`.

## 11. Known limitations

- **Operator-signed, not witnessed (Phase 1).** Trust in the checkpoint head depends
  on the operator's ledger key. Independent witnessing is future work — see the
  witness boundary in §9.
- **Whole-store deletion is out of scope.** A missing or empty ledger verifies as
  "0 entries, ok" by design; anchor/retain the checkpoint head out of band to detect
  this class.
- **Stale lock files.** A process that crashes while holding the lock leaves a
  `<ledger>.lock`; subsequent appends fail closed until it is cleared (fail-closed
  over silent unlocked writes).
- **Crash during append.** A partial trailing JSONL line fails verification with
  `ERR_LEDGER_PARSE`; the ledger is never auto-repaired silently.
