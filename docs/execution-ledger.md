# MNDe Execution Ledger (V1)

The execution ledger is a tamper-evident, append-only hash chain **over** finalized
receipts. It is a separate integrity layer: it does not change the canonical
receipt format, the signed envelope, the receipt signing path, or standalone
receipt verification. Every finalized receipt gets one ledger entry; the entries
form a hash chain so that deleting, editing, reordering, or replacing a receipt
(or a ledger line) makes verification fail closed.

## 1. What the ledger proves

Given an intact ledger and its receipt store, verification proves:

- **Completeness & order** — receipts were recorded in an unbroken, monotonically
  increasing sequence with no gaps and no duplicates.
- **Linkage** — each entry commits to the previous entry's hash, so the history
  cannot be silently truncated, reordered, or spliced.
- **Receipt integrity** — each entry's `receipt_hash` still matches the canonical
  bytes of the referenced receipt; a single changed byte in any recorded receipt
  is detected.
- **Entry integrity** — each `entry_hash` recomputes from its own body, so a
  ledger line cannot be edited without breaking the chain.

## 2. What it does **not** prove

See the [threat model](#9-threat-model). In short: it is a *detection* layer, not
a prevention layer, and it cannot defend against an attacker who controls the host
well enough to replace the entire ledger **and** receipt store at once, or who
holds the signing keys.

## 3. Ledger entry format

Schema: `mnde.execution_ledger.entry.v1`. One JSON object per line (JSONL).

```json
{
  "schema": "mnde.execution_ledger.entry.v1",
  "sequence": 1,
  "created_at": "2026-06-29T00:00:00.000Z",
  "receipt_hash": "sha256:<hex>",
  "previous_entry_hash": null,
  "entry_hash": "sha256:<hex>",
  "receipt_ref": { "storage": "local", "path": "<safe-relative-path>", "receipt_id": "<id-or-null>" },
  "engine": { "name": "mnde-policy-engine", "version": "<version-or-null>" }
}
```

Rules:

- `sequence` starts at 1 and increments by exactly 1.
- The first entry's `previous_entry_hash` is `null`; every later entry's
  `previous_entry_hash` equals the prior entry's `entry_hash`.
- `receipt_hash` = `sha256:` + SHA-256 of `canonicalizeJson(receipt)` — the **same**
  canonicalization the receipt signature is taken over. No new canonicalizer is
  introduced.
- `entry_hash` = `sha256:` + SHA-256 of `canonicalizeJson(body)` where `body` is the
  entry **without** its `entry_hash` field.
- `created_at` is UTC ISO-8601 with millisecond precision.
- `receipt_ref.path` must be a safe relative path (no traversal, absolute, drive,
  UNC, or encoded-traversal forms).

## 4. Verification result format

Schema: `mnde.execution_ledger.verify_result.v1`.

```json
{ "schema": "mnde.execution_ledger.verify_result.v1", "ok": true, "entries_checked": 10,
  "head": { "sequence": 10, "entry_hash": "sha256:<hex>", "receipt_hash": "sha256:<hex>", "created_at": "..." },
  "errors": [] }
```

On failure, `ok` is `false`, `head` is `null`, and `errors` carries one or more
`{ code, sequence, message }` entries. Stable error codes:

`ERR_LEDGER_PARSE`, `ERR_LEDGER_SCHEMA`, `ERR_LEDGER_SEQUENCE`,
`ERR_LEDGER_CHAIN_BROKEN`, `ERR_LEDGER_ENTRY_HASH`, `ERR_LEDGER_RECEIPT_REF_UNSAFE`,
`ERR_LEDGER_RECEIPT_MISSING`, `ERR_LEDGER_RECEIPT_HASH`,
`ERR_LEDGER_DUPLICATE_SEQUENCE`, `ERR_LEDGER_DUPLICATE_ENTRY_HASH`,
`ERR_LEDGER_APPEND_FAILED`, `ERR_LEDGER_LOCK_FAILED`,
`ERR_LEDGER_DISABLED_IN_PRODUCTION`.

## 5. Operational modes

- **Default-on.** The ledger is enabled unless explicitly disabled.
- **Storage.** Append-only JSONL, serialized across processes by an exclusive lock
  file (`<ledger>.lock`). The read-modify-write happens entirely under the lock, so
  concurrent workers can never mint the same sequence. If the lock cannot be
  acquired within a bounded retry budget, the append fails closed
  (`ERR_LEDGER_LOCK_FAILED`) — it never writes without the lock.
- **Location.** By default the ledger lives next to the receipt store it references
  (`<receipt-log-dir>/mnde-execution-ledger.jsonl`), so a `receipt_ref` is just the
  receipt file's basename resolved against that directory. The library default for
  standalone/CLI use is `.data/mnde-execution-ledger.jsonl`.
- **Env:**
  - `MNDE_EXECUTION_LEDGER_PATH` — explicit ledger file path.
  - `MNDE_EXECUTION_LEDGER=off` — disable the ledger (development only).

## 6. Production fail-closed rule

- If `MNDE_PROFILE=production` and `MNDE_EXECUTION_LEDGER=off`, the sidecar
  **refuses to start** (`ERR_LEDGER_DISABLED_IN_PRODUCTION`).
- In production, if a ledger append fails for a finalized receipt, the request
  **fails closed** (`ERR_LEDGER_APPEND_FAILED`). No successful production receipt
  exists without a corresponding ledger entry.
- In development/local mode, an append failure is logged and surfaced in response
  metadata (`"ledger": { "appended": false }`); it never mutates the receipt.

Ledger status is always reported **outside** the receipt, in the API response
metadata — never inside the signed receipt:

```json
"ledger": { "enabled": true, "appended": true, "sequence": 12, "entry_hash": "sha256:<hex>" }
```

## 7. How to verify

```bash
npm run ledger:verify          # verify the chain (exit 1 on failure)
npm run ledger:head            # print the current head
```

Over HTTP (authority-gated like the receipt endpoints):

```
GET /ledger/head      # inspect_receipts
GET /ledger/verify    # verify_receipts
GET /ledger/export    # export_audit
```

## 8. How to export

```bash
npm run ledger:export
```

or `GET /ledger/export`, which returns a `mnde.execution_ledger.export.v1` object
containing every entry. Export is never exposed without authority gating.

## 9. Threat model

**The ledger detects:**

- receipt deletion
- receipt editing
- receipt replacement
- ledger line editing
- ledger line deletion
- ledger reordering
- broken append sequence
- missing referenced receipt

**The ledger does not prevent:**

- an attacker deleting the entire ledger and receipt store
- an attacker with full host control replacing the whole data directory
- pre-ledger tampering before the first trusted export
- compromise of signing keys
- authorized policy mistakes

The ledger raises the cost of *selective, undetectable* tampering: an attacker can
no longer quietly remove or alter one receipt and have everything still verify. The
strong follow-on is to export or anchor the chain head somewhere the attacker does
not control — once the head is witnessed, even a wholesale replacement is detectable.

## 10. Known limitations

- **No remote notarization / transparency log in V1.** Integrity is local; trust in
  the head depends on exporting/anchoring it out of band.
- **Whole-store deletion is out of scope.** A missing or empty ledger verifies as
  "0 entries, ok" by design — deleting everything is not the same as tampering with
  something. Anchor the head to detect this class.
- **Stale lock files.** A process that crashes while holding the lock leaves a
  `<ledger>.lock` file; subsequent appends fail closed until it is cleared. This is
  deliberate (fail-closed over silent unlocked writes); operators clear stale locks.
- **Crash during append.** A partial trailing JSONL line fails verification with
  `ERR_LEDGER_PARSE`; the ledger is never auto-repaired silently.
