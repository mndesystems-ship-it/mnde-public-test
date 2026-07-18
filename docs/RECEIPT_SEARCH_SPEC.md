# MNDe Receipt Search — Feature Spec

Status: DRAFT
Implements: the `find`, `index`, `show`, and `stats` endpoints reserved in `RECEIPT_API_CONTRACT.md`
Depends on: receipt schema `mnde.receipt.v2_5`, key registry, RFC8785 canonicalization

## 1. Problem

Receipts are write-optimized and read-hostile. Each decision produces one JSON file
in a per-surface directory (`mnde-receipts/<surface>/receipt-<tool>-<ts>-<pid>-<seq>.json`,
plus `failclosed-*.json` refusal receipts), and the custody CLI separately appends
`.jsonl` receipt logs. Answering "show me the receipt for the delete_backups run
last Tuesday" requires knowing which directory to grep and what the filename
encoding means. There is no way to ask by actor, decision, reason code, policy
version, or time range.

The Receipt API contract already reserves `POST /receipts/find|index|show|stats`.
This spec defines the feature behind those endpoints plus its CLI.

## 2. Goals

- Look up receipts by what an operator actually knows: request id, tool name,
  actor, decision (ALLOW/REFUSE), reason code, tenant, policy version, key id,
  time range, projected cost.
- Every returned receipt is re-verified before display. Search must never
  become a path that launders unverified data into "trusted" output.
- Works across multiple receipt roots (per-surface dirs and `.jsonl` logs).
- Deterministic output: identical query over identical stores yields
  byte-identical JSON (contract rule: API JSON == CLI JSON).

## 3. Non-goals

- Not a system of record. Receipt files remain the only canonical artifact;
  everything this feature builds is derived and disposable.
- No cloud/hosted component. Local, same trust posture as the sidecar.
- No full-text search in v1 (no searching inside arbitrary payload fields).
- Not a transparency log. Signed proofs of inclusion/absence are future work
  (see §11) — v1 explicitly does NOT prove a receipt does not exist.

## 4. Design principles

1. **The index is untrusted.** It is a lookup accelerator, never an authority.
   Verification always happens against the receipt file on disk plus the key
   registry, at read time. A poisoned index can waste time; it cannot forge a
   VERIFIED result.
2. **Fail-closed presentation.** Every hit carries a verification status:
   `VERIFIED`, `TAMPERED` (payload hash or signature check failed),
   `UNVERIFIABLE` (key id not in registry, unknown schema version, or quorum
   not met). `--verified-only` drops non-VERIFIED hits and exits nonzero if
   any were dropped.
3. **Absence is not evidence.** Zero results is a statement about the index,
   not the world. Output always includes coverage metadata (§8) so "not found"
   can be distinguished from "not indexed."
4. **Strict inputs per contract.** JSON bodies only; unknown fields, duplicate
   keys (`ERR_DUPLICATE_JSON_KEYS`), and paths outside allowed roots
   (`ERR_PATH_NOT_ALLOWED`, `ERR_PATH_TRAVERSAL`) are refused.

## 5. Architecture

```
receipt files (canonical)          .jsonl receipt logs (canonical)
        │                                   │
        └────────────┬──────────────────────┘
                     ▼
           receipt-index library            ← src/receipt-index/index.mjs
           (scan, parse, extract, upsert)
                     │
                     ▼
        mnde-receipts/.index/receipts.db    ← SQLite via node:sqlite
                     │
      ┌──────────────┼────────────────┐
      ▼              ▼                ▼
   CLI (find/       sidecar POST     Authority Console
   show/stats/      /receipts/*      search panel (later)
   index)
```

- **Storage: SQLite via `node:sqlite`.** The bundled runtime is Node 24, where
  `node:sqlite` is built in — zero new dependencies, real range queries, and
  1M+ receipts without loading anything into memory. The DB file lives beside
  the receipts it indexes and is listed in `.gitignore` (derived data).
- **Ingest paths:**
  - Hook in `sidecar/receipt_persistence_queue.mjs`: after a receipt file is
    durably written, enqueue an index upsert. Index failures are logged and
    never block or fail receipt persistence (the receipt is the product; the
    index is a convenience).
  - `receipts index --rebuild`: full scan of configured roots, rebuilds from
    zero. This is the recovery story for any index corruption — delete and
    rebuild, nothing of value is lost.
  - `receipts index --sync`: incremental scan by file mtime/size for stores
    written by processes that don't run the hook (e.g. custody CLI `.jsonl` logs).
- **Configured roots:** an explicit allowlist of receipt directories/log files
  (config file, no auto-discovery). Anything outside the allowlist is refused
  with the contract's path error codes.

## 6. Indexed fields

From the receipt envelope (`mnde.receipt.v2_5`):

| Field | Type | Notes |
|---|---|---|
| `schema_version` | text | adapter selector |
| `tenant_id` | text | |
| `request_hash` | text (64 hex) | unique key together with file path |
| `decision` | ALLOW / REFUSE | |
| `reason_code` | text | |
| `policy_hash`, `policy_version` | text | |
| `key_set_version`, `key_id` | text | |
| `timestamp` | ISO 8601 | indexed for range queries |
| `projected_cost_micro_usd` | integer | range queries |
| signer ids | text[] | from `signatures[].signer_id` |
| quorum `valid/required` | integers | |

Extracted once at index time from `canonical_request` (parsed, not trusted):

| Field | Source |
|---|---|
| `request_id` | `execution_request.request_id` |
| `actor_user_id` | `execution_request.actor.user_id` |
| `tools` | `execution_request.tool_calls[].tool` (array) |
| `submitted_region` | `execution_request.submitted_region` |
| `boundary` | `orbit_intent.boundary` |

Provenance (always recorded): absolute file path (or log path + line number),
surface directory name, file size, file mtime, indexed-at monotonic counter.

Unknown `schema_version` values are still indexed (envelope fields only) and
always surface as `UNVERIFIABLE(schema_unknown)` — never silently dropped.

## 7. Query interface

### CLI

```
mnde receipts find [filters] [--verified-only] [--no-index] [--limit N] [--cursor C] [--format json|table]
mnde receipts show --request-hash <hex64> | --file <path>
mnde receipts stats [--since --until --group-by decision|reason_code|tool|tenant]
mnde receipts index --rebuild | --sync | --status
```

Filters (all AND-combined; array values are any-of):

```
--decision ALLOW|REFUSE        --reason-code <code>[,<code>...]
--tenant <id>                  --actor <user_id>
--tool <name>[,<name>...]      --request-id <id>
--request-hash <hex64>         --policy-version <v>
--policy-hash <hex64>          --key-id <id>
--signer <signer_id>           --region <region>
--since <ISO8601>              --until <ISO8601>
--min-cost <micro_usd>         --max-cost <micro_usd>
--surface <dir-name>
```

### Sidecar API (per existing contract)

`POST /receipts/find` with a JSON body mirroring the flags 1:1 (snake_case
keys). Unknown fields refused. Response JSON is byte-identical to
`mnde receipts find --format json` for the same input. Same for `/show`,
`/stats`, `/index` (index accepts `{"mode": "rebuild"|"sync"|"status"}`).

### Result shape

```json
{
  "ok": true,
  "schema_version": "mnde.receipts.find.v1",
  "query": { "...normalized filters..." },
  "hits": [
    {
      "verification": "VERIFIED",
      "receipt": { "...full receipt envelope..." },
      "provenance": { "path": "...", "surface": "...", "line": null }
    }
  ],
  "summary": { "returned": 12, "verified": 11, "tampered": 0, "unverifiable": 1 },
  "coverage": { "roots_configured": 4, "roots_scanned": 4, "files_on_disk": 18211, "files_indexed": 18211, "index_synced_at_counter": 90412 },
  "cursor": "..."
}
```

Ordering is fixed and total: `timestamp ASC, request_hash ASC, path ASC`.
No other orderings in v1 (determinism over flexibility). Pagination via opaque
cursor encoding the last (timestamp, request_hash, path) triple; `limit`
defaults to 100, max 1000.

## 8. Verification semantics (per hit, at read time)

1. Load the receipt file (or log line) from provenance path. Missing file →
   the hit is dropped from `hits`, counted in `summary.index_orphans`, and the
   response gains `"index_dirty": true`. With `--verified-only`, exit nonzero.
2. Validate against the schema for its `schema_version`.
3. Recompute `decision_payload_hash` over the RFC8785-canonicalized payload;
   compare. Mismatch → `TAMPERED`.
4. Verify each `signatures[]` entry (Ed25519) against the key registry;
   key id absent from registry → `UNVERIFIABLE(key_unknown)`; signature
   invalid → `TAMPERED`.
5. Check `quorum.valid_signatures >= quorum.required_signatures` recomputed
   from step 4 results (do not trust the stored quorum counts). Not met →
   `UNVERIFIABLE(quorum_not_met)`.
6. Cross-check indexed envelope fields against file contents; any divergence →
   the file wins, the row is repaired, and the hit is flagged
   `"index_repaired": true`.

`--no-index` bypasses the index entirely and scans the configured roots
directly (slow path). This is the escape hatch that makes the index honestly
optional and the recovery path when `index_dirty` appears.

Error codes reuse the contract set (`ERR_RECEIPT_SIGNATURE_INVALID`,
`ERR_INVALID_JSON`, `ERR_DUPLICATE_JSON_KEYS`, `ERR_PATH_TRAVERSAL`,
`ERR_PATH_NOT_ALLOWED`, `ERR_ROUTE_NOT_FOUND`) plus new:
`ERR_RECEIPT_INDEX_UNAVAILABLE` (index missing/corrupt and `--no-index` not
given), `ERR_RECEIPT_QUERY_INVALID` (bad filter values), `ERR_CURSOR_INVALID`.

## 9. Failure modes

| Failure | Behavior |
|---|---|
| Index file corrupt/missing | `ERR_RECEIPT_INDEX_UNAVAILABLE`; operator runs `index --rebuild` or query runs with `--no-index` |
| Receipt file deleted after indexing | hit dropped, `index_orphans` counted, `index_dirty: true` |
| Receipt file modified after indexing | file wins; verification runs on file contents; envelope divergence auto-repairs the row |
| Mixed/unknown schema versions | indexed envelope-only, surfaced as `UNVERIFIABLE(schema_unknown)` |
| Ingest hook failure | receipt persistence unaffected; warning logged; `index --status` shows lag |
| Two processes writing the index | SQLite WAL mode; ingest hook and `--sync` are idempotent upserts keyed on (path, request_hash) |

## 10. Hostile tests (acceptance gate — must all pass before merge)

Per the mandatory security workflow, each is an executable test, not a review item:

1. Flip one byte in a receipt's `decision_payload` → hit reports `TAMPERED`.
2. Swap the `signature` from a different (valid) receipt → `TAMPERED`.
3. Set stored `quorum.valid_signatures` to a satisfying number while only one
   of two required signatures verifies → `UNVERIFIABLE(quorum_not_met)`
   (proves quorum is recomputed, not read).
4. Insert a forged index row pointing at a nonexistent file → dropped,
   `index_dirty: true`, nonzero exit with `--verified-only`.
5. Edit an indexed envelope column (e.g. flip REFUSE→ALLOW in the DB) → file
   wins; hit shows REFUSE; row repaired.
6. Query JSON with duplicate keys → `ERR_DUPLICATE_JSON_KEYS`.
7. Configure a root, then query with a path filter escaping it (`..\`) →
   `ERR_PATH_TRAVERSAL`.
8. Receipt signed by a key id absent from the registry →
   `UNVERIFIABLE(key_unknown)`, never VERIFIED.
9. Same query twice over an unchanged store → byte-identical output.
10. `--no-index` and indexed query over the same store and filters → identical
    `hits` (index adds speed, never changes answers).

## 11. Future work (explicitly out of v1)

- **Transparency log:** append-only Merkle log over receipt hashes, enabling
  signed inclusion proofs and — the piece v1 cannot offer — verifiable
  statements of absence ("no receipt exists for request X"). This is the
  standards-grade version of search and belongs in the receipt *language*,
  not just the tooling.
- Authority Console search panel over `POST /receipts/find`.
- `stats` time-bucketing for dashboard sparklines.
- Cross-store federation (query multiple machines' stores through one CLI).

## 12. Milestones

1. `src/receipt-index/` library + `receipts index --rebuild/--sync/--status` + hostile tests 4, 5, 9.
2. `receipts find/show/stats` CLI with full verification semantics + remaining hostile tests.
3. Sidecar `POST /receipts/*` endpoints (thin wrappers per contract determinism rule: handlers wrap library functions only).
4. Ingest hook in `receipt_persistence_queue.mjs`.
5. Console UI (separate spec).
