# Receipt Search — Integration Guide

Spec: `docs/RECEIPT_SEARCH_SPEC.md`. Implementation: `src/receipt-index/`
(scan, extract, db, find, cli) with hostile and PE-version integration tests.

The index is integrated with both frozen `mnde.pe.receipt.v1` and rule-bound
`mnde.pe.receipt.v2`. The index remains derived and untrusted; verification
always reads the receipt from disk and routes PE receipts through the committed
policy-engine verifier.

```
node ./src/receipt-index/cli.mjs index --rebuild            # index ./mnde-receipts
node ./src/receipt-index/cli.mjs find --decision REFUSE --since 2026-07-01T00:00:00Z --format table
node ./src/receipt-index/cli.mjs show --request-hash <hex64>
node ./src/receipt-index/cli.mjs stats --group-by reason_code
node ./tests/test_receipt_index.mjs                         # 12 hostile tests
node ./tests/test_receipt_index_pe_v2.mjs                  # PE v1/v2 + migration tests
```

The repository scripts and CI contract are wired as follows.

## 1. package.json scripts (2 lines)

```json
"receipts": "node ./src/receipt-index/cli.mjs",
"test:receipt-index": "node ./tests/test_receipt_index.mjs && node ./tests/test_receipt_index_pe_v2.mjs",
```

## 2. tests/expected-test-scripts.json (1 line)

Add `"test:receipt-index"` in alphabetical position. Required by
`test:ci-contract` once the script above lands — add both together.

## 3. Generated database

The existing `mnde-receipts/` ignore rule already covers
`mnde-receipts/.receipt-index/`. The database is derived and disposable.
Opening a v1 index adds a nullable `rule_id` column and its lookup index,
updates the metadata version to `mnde.receipt-index.v2`, and leaves existing
rows NULL. The migration and subsequent reopens are idempotent.

## 4. bin/mnde.mjs subcommand (optional, ~3 lines)

```js
if (command === "receipts") {
  const { main } = await import("../src/receipt-index/cli.mjs");
  process.exit(await main(process.argv.slice(3)));
}
```

Gives `npm run mnde -- receipts find --decision REFUSE ...`.

## 5. Sidecar ingest hook (optional)

The queue in `sidecar/receipt_persistence_queue.mjs` appends receipts to a
JSONL path. After a successful flush, an incremental sync keeps the index
warm; sync is idempotent, keyed on (path, line):

```js
import { openIndex } from "../src/receipt-index/db.mjs";
import { ingestRoots } from "../src/receipt-index/find.mjs";

// after flush succeeds (debounce as desired):
const index = openIndex(indexDbPath);
try { ingestRoots(index, [receiptLogPath]); } finally { index.close(); }
```

Index failures must never block receipt persistence — the receipt is the
product, the index is a convenience. Wrap in try/catch, log, move on.

## 6. Sidecar HTTP endpoints (future, per RECEIPT_API_CONTRACT)

`POST /receipts/find` should be a thin wrapper: parse strict JSON body →
`findReceipts({...})` → emit. No business logic in the handler (contract
determinism rule). `findReceipts` already returns the response shape.

## Operational notes

- **Verification statuses:** every hit is `VERIFIED`, `TAMPERED`, or
  `UNVERIFIABLE(reason)`. The index is untrusted; the file always wins
  (see hostile tests). Pass trust material with `--authority-bundle` /
  `--trusted-root-fingerprint` where receipts require it.
- **PE receipt versions:** v1 extraction ignores `rule_id` even if a malformed
  v1 object carries it. V2 extracts, persists, returns, and filters by the
  signed `decision_output.rule_id`. Unknown versions remain unverifiable.
- **Node prints** `ExperimentalWarning: SQLite` on Node 24 — cosmetic; the
  CLI's JSON goes to stdout, warnings to stderr.
