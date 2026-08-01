// Idempotent JSONL -> SQLite ledger migration.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { appendLedgerEntry } from "../src/execution-ledger/append.mjs";
import {
  appendSqliteEntry,
  openSqliteLedger,
  readLedgerHead,
  verifySqliteLedger
} from "../src/execution-ledger/sqlite-ledger.mjs";
import { migrateJsonlLedger } from "../src/execution-ledger/migrate-jsonl.mjs";

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ok - ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`  FAIL - ${name}`);
    console.error(`        ${error instanceof Error ? error.message : String(error)}`);
  }
}

const work = mkdtempSync(join(tmpdir(), "mnde-migrate-"));
const NOW = "2026-06-15T12:00:00.000Z";
let counter = 0;
function paths() {
  counter += 1;
  return { jsonl: join(work, `src-${counter}.jsonl`), db: join(work, `dst-${counter}.db`) };
}

async function buildJsonl(jsonlPath, n) {
  for (let i = 1; i <= n; i += 1) {
    const r = await appendLedgerEntry({
      ledgerPath: jsonlPath,
      receipt: { schema_version: "mnde.execution_gate.receipt.v1", execution_id: `e-${i}`, decision: "ALLOW" },
      receiptRef: { path: `receipts/r-${i}.json`, receipt_id: `rcp-${i}` },
      engine: { name: "mnde-policy-engine", version: "1.0.0" },
      createdAt: `2026-06-15T10:00:0${i}.000Z`
    });
    assert.equal(r.ok, true, `jsonl append ${i}`);
  }
}

console.log("JSONL -> SQLite ledger migration\n");

await test("migrates a valid JSONL ledger, preserving order and passing verify", async () => {
  const p = paths();
  await buildJsonl(p.jsonl, 3);
  const db = openSqliteLedger(p.db);
  const result = migrateJsonlLedger({ jsonlPath: p.jsonl, db, now: NOW });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.status, "MIGRATED");
  assert.equal(result.imported, 3);
  const v = verifySqliteLedger(db);
  assert.equal(v.ok, true, JSON.stringify(v));
  assert.equal(v.entry_count, 3);
  const rows = db.prepare("SELECT entry_type, trust_epoch FROM ledger_entries").all();
  assert.ok(rows.every((r) => r.entry_type === "legacy_jsonl_receipt" && r.trust_epoch === "legacy-shared-key"));
  db.close();
});

await test("is idempotent — a second run does not double-import", async () => {
  const p = paths();
  await buildJsonl(p.jsonl, 3);
  const db = openSqliteLedger(p.db);
  const first = migrateJsonlLedger({ jsonlPath: p.jsonl, db, now: NOW });
  assert.equal(first.status, "MIGRATED");
  const second = migrateJsonlLedger({ jsonlPath: p.jsonl, db, now: NOW });
  assert.equal(second.ok, true);
  assert.equal(second.status, "ALREADY_MIGRATED");
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM ledger_entries").get().c, 3);
  db.close();
});

await test("native appends continue the chain from the last legacy entry", async () => {
  const p = paths();
  await buildJsonl(p.jsonl, 2);
  const db = openSqliteLedger(p.db);
  migrateJsonlLedger({ jsonlPath: p.jsonl, db, now: NOW });
  const head = readLedgerHead(db);
  const appended = appendSqliteEntry(db, {
    receipt: { schema_version: "mnde.execution_gate.receipt.v1", execution_id: "native-1" },
    receiptId: "rcp-native-1",
    trustEpoch: "executor-identity-v1",
    executorId: "mnde:local:prod:executor:codex:01",
    executorSignatureStatus: "present",
    createdAt: NOW
  });
  assert.equal(appended.sequence, 3);
  // Its parent is the last legacy entry's hash.
  const row = db.prepare("SELECT previous_entry_hash FROM ledger_entries WHERE ledger_sequence = 3").get();
  assert.equal(row.previous_entry_hash, head.entry_hash);
  const v = verifySqliteLedger(db);
  assert.equal(v.ok, true, JSON.stringify(v));
  assert.equal(v.entry_count, 3);
  db.close();
});

await test("a changed source file after a completed migration is a CONFLICT", async () => {
  const p = paths();
  await buildJsonl(p.jsonl, 2);
  const db = openSqliteLedger(p.db);
  migrateJsonlLedger({ jsonlPath: p.jsonl, db, now: NOW });
  await buildJsonl(p.jsonl, 1); // append a 3rd line, changing the file
  const again = migrateJsonlLedger({ jsonlPath: p.jsonl, db, now: NOW });
  assert.equal(again.ok, false);
  assert.equal(again.code, "ERR_LEDGER_MIGRATION_CONFLICT");
  db.close();
});

await test("malformed source input is BLOCKED and nothing is imported", async () => {
  const p = paths();
  await buildJsonl(p.jsonl, 2);
  const good = readFileSync(p.jsonl, "utf8");
  writeFileSync(p.jsonl, `${good}{ this is not json\n`);
  const db = openSqliteLedger(p.db);
  const result = migrateJsonlLedger({ jsonlPath: p.jsonl, db, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.status, "BLOCKED");
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM ledger_entries").get().c, 0);
  db.close();
});

await test("a tampered source entry_hash is BLOCKED (no silent repair)", async () => {
  const p = paths();
  await buildJsonl(p.jsonl, 3);
  const lines = readFileSync(p.jsonl, "utf8").trim().split("\n");
  const entry = JSON.parse(lines[1]);
  entry.entry_hash = "sha256:deadbeef";
  lines[1] = JSON.stringify(entry);
  writeFileSync(p.jsonl, `${lines.join("\n")}\n`);
  const db = openSqliteLedger(p.db);
  const result = migrateJsonlLedger({ jsonlPath: p.jsonl, db, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.status, "BLOCKED");
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM ledger_entries").get().c, 0);
  db.close();
});

await test("the source JSONL file is left byte-for-byte untouched", async () => {
  const p = paths();
  await buildJsonl(p.jsonl, 3);
  const before = readFileSync(p.jsonl);
  const db = openSqliteLedger(p.db);
  migrateJsonlLedger({ jsonlPath: p.jsonl, db, now: NOW });
  db.close();
  const after = readFileSync(p.jsonl);
  assert.ok(before.equals(after), "source file must not be modified");
});

await test("migration refuses a non-fresh ledger", async () => {
  const p = paths();
  await buildJsonl(p.jsonl, 2);
  const db = openSqliteLedger(p.db);
  appendSqliteEntry(db, { receipt: { execution_id: "native-first" }, trustEpoch: "executor-identity-v1", createdAt: NOW });
  const result = migrateJsonlLedger({ jsonlPath: p.jsonl, db, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.status, "BLOCKED");
  db.close();
});

await test("no source file is a clean no-op", async () => {
  const p = paths();
  const db = openSqliteLedger(p.db);
  const result = migrateJsonlLedger({ jsonlPath: p.jsonl, db, now: NOW });
  assert.equal(result.ok, true);
  assert.equal(result.status, "NO_SOURCE");
  db.close();
});

console.log(`\n${failed === 0 ? "PASS" : "FAIL"} ledger migration (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
