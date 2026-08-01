// Transactional SQLite ledger — append, chain integrity, head CAS/uniqueness,
// schema validation, and fail-closed storage handling.

import assert from "node:assert/strict";
import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  SQLITE_LEDGER_SCHEMA,
  appendSqliteEntry,
  openSqliteLedger,
  readLedgerHead,
  verifySqliteLedger
} from "../src/execution-ledger/sqlite-ledger.mjs";

let passed = 0;
let failed = 0;
function test(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`  ok - ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`  FAIL - ${name}`);
    console.error(`        ${error instanceof Error ? error.message : String(error)}`);
  }
}

const work = mkdtempSync(join(tmpdir(), "mnde-ledger-"));
let dbCounter = 0;
function freshDbPath() {
  dbCounter += 1;
  return join(work, `ledger-${dbCounter}.db`);
}

function receipt(n) {
  return { schema_version: "mnde.execution_gate.receipt.v1", execution_id: `exec-${n}`, decision: "ALLOW" };
}
function appendN(db, n, extra = {}) {
  return appendSqliteEntry(db, {
    receipt: receipt(n),
    receiptId: `rcp-${n}`,
    trustEpoch: "executor-identity-v1",
    createdAt: `2026-06-15T10:00:0${n}.000Z`,
    ...extra
  });
}

console.log("Transactional SQLite ledger\n");

test("append allocates sequential ids and links the chain; verify passes", () => {
  const db = openSqliteLedger(freshDbPath());
  const r1 = appendN(db, 1);
  const r2 = appendN(db, 2);
  const r3 = appendN(db, 3);
  assert.equal(r1.sequence, 1);
  assert.equal(r2.sequence, 2);
  assert.equal(r3.sequence, 3);
  const v = verifySqliteLedger(db);
  assert.equal(v.ok, true, JSON.stringify(v));
  assert.equal(v.entry_count, 3);
  const head = readLedgerHead(db);
  assert.equal(head.sequence, 3);
  assert.equal(head.entry_hash, r3.entry_hash);
  db.close();
});

test("executor identity fields are stored on the entry", () => {
  const db = openSqliteLedger(freshDbPath());
  appendN(db, 1, { executorId: "mnde:local:prod:executor:codex:01", executorKeyId: "mnde-exk:abc", executorSignatureStatus: "present", legacySignatureStatus: "none" });
  const row = db.prepare("SELECT executor_id, executor_key_id, executor_signature_status FROM ledger_entries WHERE ledger_sequence = 1").get();
  assert.equal(row.executor_id, "mnde:local:prod:executor:codex:01");
  assert.equal(row.executor_key_id, "mnde-exk:abc");
  assert.equal(row.executor_signature_status, "present");
  db.close();
});

test("ledger persists and re-validates schema on reopen", () => {
  const path = freshDbPath();
  const db = openSqliteLedger(path);
  appendN(db, 1);
  appendN(db, 2);
  db.close();
  const reopened = openSqliteLedger(path);
  const v = verifySqliteLedger(reopened);
  assert.equal(v.ok, true);
  assert.equal(v.entry_count, 2);
  reopened.close();
});

test("tampering with a stored field is detected by verify", () => {
  const db = openSqliteLedger(freshDbPath());
  appendN(db, 1);
  appendN(db, 2);
  // Mutate receipt_hash without recomputing entry_body_hash.
  db.prepare("UPDATE ledger_entries SET receipt_hash = 'sha256:deadbeef' WHERE ledger_sequence = 1").run();
  const v = verifySqliteLedger(db);
  assert.equal(v.ok, false);
  assert.equal(v.code, "ERR_LEDGER_ENTRY_HASH");
  db.close();
});

test("head divergence from the final entry is detected", () => {
  const db = openSqliteLedger(freshDbPath());
  appendN(db, 1);
  db.prepare("UPDATE ledger_head SET sequence = 99 WHERE id = 1").run();
  const v = verifySqliteLedger(db);
  assert.equal(v.ok, false);
  assert.equal(v.code, "ERR_LEDGER_HEAD_MISMATCH");
  db.close();
});

test("unique sequence prevents a forked/duplicate append (rolls back)", () => {
  const db = openSqliteLedger(freshDbPath());
  const r1 = appendN(db, 1);
  // Force the head backwards to simulate a stale writer, then append again.
  db.prepare("UPDATE ledger_head SET sequence = 0, entry_hash = '' WHERE id = 1").run();
  const dup = appendN(db, 2);
  assert.equal(dup.ok, false);
  assert.equal(dup.code, "ERR_LEDGER_APPEND_CONFLICT");
  // The original entry is intact and no partial second entry was written.
  const count = db.prepare("SELECT COUNT(*) AS c FROM ledger_entries").get().c;
  assert.equal(count, 1);
  assert.ok(r1.ok);
  db.close();
});

test("schema-version mismatch fails closed on open", () => {
  const path = freshDbPath();
  const db = openSqliteLedger(path);
  db.prepare("UPDATE ledger_meta SET value = 'mnde.execution_ledger.sqlite.vBOGUS' WHERE key = 'schema_version'").run();
  db.close();
  assert.throws(() => openSqliteLedger(path), (e) => e.code === "ERR_LEDGER_SCHEMA_INVALID");
});

test("symlinked ledger path is rejected (fail closed)", () => {
  const real = freshDbPath();
  writeFileSync(real, "");
  const link = join(work, "ledger-symlink.db");
  try {
    symlinkSync(real, link);
  } catch {
    console.log("        (skipped: symlink creation not permitted on this host)");
    return;
  }
  assert.throws(() => openSqliteLedger(link), (e) => e.code === "ERR_LEDGER_PATH_UNSAFE");
});

console.log(`\n${failed === 0 ? "PASS" : "FAIL"} sqlite ledger (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
