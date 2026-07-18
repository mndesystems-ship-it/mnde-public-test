# Receipt Search — Integration Guide

Spec: `docs/RECEIPT_SEARCH_SPEC.md`. Implementation: `src/receipt-index/`
(scan, extract, db, find, cli) + `tests/test_receipt_index.mjs`.

Everything ships as NEW files only — nothing existing was modified, so this
work cannot conflict with in-flight changes. It is fully usable today without
any integration:

```
node ./src/receipt-index/cli.mjs index --rebuild            # index ./mnde-receipts
node ./src/receipt-index/cli.mjs find --decision REFUSE --since 2026-07-01T00:00:00Z --format table
node ./src/receipt-index/cli.mjs show --request-hash <hex64>
node ./src/receipt-index/cli.mjs stats --group-by reason_code
node ./tests/test_receipt_index.mjs                         # 12 hostile tests
```

The steps below wire it into the repo's conventions. Each is a tiny, isolated
change — apply them whenever the working tree is quiet.

## 1. package.json scripts (2 lines)

```json
"receipts": "node ./src/receipt-index/cli.mjs",
"test:receipt-index": "node ./tests/test_receipt_index.mjs",
```

## 2. tests/expected-test-scripts.json (1 line)

Add `"test:receipt-index"` in alphabetical position. Required by
`test:ci-contract` once the script above lands — add both together.

## 3. .gitignore (1 line)

```
mnde-receipts/.receipt-index/
```

The index DB is derived and disposable; it must never be committed.
(Until this lands, keep the DB elsewhere via `--db <path>`.)

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
- **Known finding:** existing demo receipts in `mnde-receipts/` report
  `decision drift: rule_id` under the current unified verifier — the present
  policy engine replays them to a different rule_id than recorded. They index
  and surface fine (as UNVERIFIABLE); regenerate demo receipts
  (`npm run receipts:refresh`) if VERIFIED demo output is wanted.
- **Node prints** `ExperimentalWarning: SQLite` on Node 24 — cosmetic; the
  CLI's JSON goes to stdout, warnings to stderr.
