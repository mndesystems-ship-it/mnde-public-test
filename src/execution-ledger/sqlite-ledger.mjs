// Transactional SQLite execution ledger (node:sqlite, zero dependencies).
//
// Replaces the JSONL + lockfile append as the AUTHORITATIVE ledger. Every append
// runs inside a BEGIN IMMEDIATE write transaction that: reads the current head,
// allocates the next sequence, links previous_entry_hash, inserts the entry, and
// updates the head with a compare-and-swap against the expected prior head. A
// moved head fails closed (ERR_LEDGER_HEAD_MISMATCH); the caller rebuilds against
// the new head. Unique constraints on sequence and entry id make a duplicate or
// forked append impossible to commit.
//
// Storage is fail-closed: WAL, synchronous=FULL, foreign_keys ON, busy_timeout,
// an integrity_check on open, explicit schema-version validation, and rejection
// of symlinked database paths. Any failure returns/throws a stable code and never
// leaves a partial entry (transactions roll back).
//
// Hashing reuses the SAME canonicalizer and sha256 helper as the receipt/JSONL
// ledger — no new canonicalizer is invented.

import { existsSync, lstatSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

import { canonicalizeJson } from "../../shared/json.ts";
import { canonicalReceiptHash, sha256Prefixed } from "./index.mjs";

export const SQLITE_LEDGER_SCHEMA = "mnde.execution_ledger.sqlite.v1";
export const LEDGER_ENTRY_BODY_VERSION = "mnde.execution_ledger.entry_body.v1";

export const SQLITE_LEDGER_ERRORS = Object.freeze({
  UNAVAILABLE: "ERR_LEDGER_UNAVAILABLE",
  SCHEMA_INVALID: "ERR_LEDGER_SCHEMA_INVALID",
  INTEGRITY_FAILED: "ERR_LEDGER_INTEGRITY_FAILED",
  HEAD_MISMATCH: "ERR_LEDGER_HEAD_MISMATCH",
  APPEND_CONFLICT: "ERR_LEDGER_APPEND_CONFLICT",
  PATH_UNSAFE: "ERR_LEDGER_PATH_UNSAFE"
});

const CREATE_SQL = `
CREATE TABLE IF NOT EXISTS ledger_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger_entries (
  ledger_sequence INTEGER PRIMARY KEY,
  entry_id TEXT NOT NULL UNIQUE,
  entry_type TEXT NOT NULL,
  state TEXT NOT NULL,
  receipt_id TEXT,
  receipt_hash TEXT NOT NULL,
  executor_id TEXT,
  executor_key_id TEXT,
  previous_entry_hash TEXT,
  entry_body_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  provisional_at TEXT,
  finalized_at TEXT,
  trust_epoch TEXT NOT NULL,
  legacy_signature_status TEXT NOT NULL,
  executor_signature_status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger_head (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  sequence INTEGER NOT NULL,
  entry_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS migration_state (
  source_path TEXT PRIMARY KEY,
  source_hash TEXT NOT NULL,
  imported_count INTEGER NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL
);
`;

class LedgerError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.code = code;
  }
}

function assertSafePath(dbPath) {
  // Reject a database path that is itself a symlink (a redirect to somewhere the
  // operator did not intend). Non-existent paths are fine — they will be created.
  if (existsSync(dbPath)) {
    let st;
    try {
      st = lstatSync(dbPath);
    } catch {
      throw new LedgerError(SQLITE_LEDGER_ERRORS.PATH_UNSAFE, `cannot stat ledger path ${dbPath}`);
    }
    if (st.isSymbolicLink()) throw new LedgerError(SQLITE_LEDGER_ERRORS.PATH_UNSAFE, "ledger path must not be a symlink");
  }
}

// Open (creating if needed) a fail-closed SQLite ledger. Throws a LedgerError on
// unsafe path, integrity failure, or schema mismatch.
export function openSqliteLedger(dbPath) {
  assertSafePath(dbPath);

  let db;
  try {
    db = new DatabaseSync(dbPath);
  } catch (error) {
    throw new LedgerError(SQLITE_LEDGER_ERRORS.UNAVAILABLE, `cannot open ledger: ${error instanceof Error ? error.message : String(error)}`);
  }

  try {
    db.exec("PRAGMA journal_mode = WAL;");
    db.exec("PRAGMA synchronous = FULL;");
    db.exec("PRAGMA foreign_keys = ON;");
    db.exec("PRAGMA busy_timeout = 5000;");

    const integrity = db.prepare("PRAGMA integrity_check;").get();
    const integrityResult = integrity && (integrity.integrity_check ?? Object.values(integrity)[0]);
    if (integrityResult !== "ok") {
      throw new LedgerError(SQLITE_LEDGER_ERRORS.INTEGRITY_FAILED, `integrity_check failed: ${integrityResult}`);
    }

    db.exec(CREATE_SQL);

    // Schema-version validation: set on first creation, enforced thereafter.
    const row = db.prepare("SELECT value FROM ledger_meta WHERE key = 'schema_version'").get();
    if (!row) {
      db.prepare("INSERT INTO ledger_meta (key, value) VALUES ('schema_version', ?)").run(SQLITE_LEDGER_SCHEMA);
    } else if (row.value !== SQLITE_LEDGER_SCHEMA) {
      throw new LedgerError(SQLITE_LEDGER_ERRORS.SCHEMA_INVALID, `ledger schema ${row.value} != ${SQLITE_LEDGER_SCHEMA}`);
    }

    // Seed the head row (genesis) exactly once.
    const head = db.prepare("SELECT sequence, entry_hash FROM ledger_head WHERE id = 1").get();
    if (!head) {
      db.prepare("INSERT INTO ledger_head (id, sequence, entry_hash) VALUES (1, 0, '')").run();
    }
  } catch (error) {
    db.close();
    if (error instanceof LedgerError) throw error;
    throw new LedgerError(SQLITE_LEDGER_ERRORS.UNAVAILABLE, `ledger open failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  return db;
}

// The immutable evidence a ledger entry's entry_body_hash commits to. State and
// transition timestamps are operational and excluded so a future state change
// cannot rewrite historical evidence.
function ledgerEntryBody(fields) {
  return {
    ledger_version: LEDGER_ENTRY_BODY_VERSION,
    ledger_sequence: fields.ledger_sequence,
    entry_type: fields.entry_type,
    receipt_id: fields.receipt_id ?? null,
    receipt_hash: fields.receipt_hash,
    executor_id: fields.executor_id ?? null,
    executor_key_id: fields.executor_key_id ?? null,
    previous_entry_hash: fields.previous_entry_hash ?? null,
    trust_epoch: fields.trust_epoch,
    legacy_signature_status: fields.legacy_signature_status,
    executor_signature_status: fields.executor_signature_status,
    created_at: fields.created_at
  };
}

export function computeLedgerEntryBodyHash(fields) {
  return sha256Prefixed(canonicalizeJson(ledgerEntryBody(fields)));
}

export function readLedgerHead(db) {
  const head = db.prepare("SELECT sequence, entry_hash FROM ledger_head WHERE id = 1").get();
  return head ? { sequence: head.sequence, entry_hash: head.entry_hash } : { sequence: 0, entry_hash: "" };
}

// Append one entry transactionally. Returns { ok, sequence, entry_hash } or
// { ok:false, code, message }. Never leaves a partial entry.
//
// entry:
//   receipt                  the receipt object (hashed via canonicalReceiptHash)
//   receiptId                optional receipt id for lookup
//   entryType                default "execution_receipt"
//   state                    default "provisional"
//   executorId/executorKeyId optional executor identity (null for authority-only)
//   trustEpoch               required trust epoch string
//   legacySignatureStatus    e.g. "none" | "present"
//   executorSignatureStatus  e.g. "none" | "present"
//   createdAt                ISO timestamp (caller-supplied for determinism)
export function appendSqliteEntry(db, entry) {
  const {
    receipt,
    receiptId = null,
    entryType = "execution_receipt",
    state = "provisional",
    executorId = null,
    executorKeyId = null,
    trustEpoch,
    legacySignatureStatus = "none",
    executorSignatureStatus = "none",
    createdAt
  } = entry;

  if (!receipt) return { ok: false, code: SQLITE_LEDGER_ERRORS.APPEND_CONFLICT, message: "receipt is required" };
  if (typeof trustEpoch !== "string" || trustEpoch.length === 0) {
    return { ok: false, code: SQLITE_LEDGER_ERRORS.APPEND_CONFLICT, message: "trustEpoch is required" };
  }
  if (typeof createdAt !== "string" || createdAt.length === 0) {
    return { ok: false, code: SQLITE_LEDGER_ERRORS.APPEND_CONFLICT, message: "createdAt is required" };
  }

  const receiptHash = canonicalReceiptHash(receipt);

  try {
    db.exec("BEGIN IMMEDIATE");
  } catch (error) {
    return { ok: false, code: SQLITE_LEDGER_ERRORS.UNAVAILABLE, message: `cannot begin: ${error instanceof Error ? error.message : String(error)}` };
  }

  try {
    const head = readLedgerHead(db);
    const sequence = head.sequence + 1;
    const previousEntryHash = head.sequence === 0 ? null : head.entry_hash;

    const bodyFields = {
      ledger_sequence: sequence,
      entry_type: entryType,
      receipt_id: receiptId,
      receipt_hash: receiptHash,
      executor_id: executorId,
      executor_key_id: executorKeyId,
      previous_entry_hash: previousEntryHash,
      trust_epoch: trustEpoch,
      legacy_signature_status: legacySignatureStatus,
      executor_signature_status: executorSignatureStatus,
      created_at: createdAt
    };
    const entryBodyHash = computeLedgerEntryBodyHash(bodyFields);

    db.prepare(`
      INSERT INTO ledger_entries (
        ledger_sequence, entry_id, entry_type, state, receipt_id, receipt_hash,
        executor_id, executor_key_id, previous_entry_hash, entry_body_hash,
        created_at, provisional_at, finalized_at, trust_epoch,
        legacy_signature_status, executor_signature_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      sequence, entryBodyHash, entryType, state, receiptId, receiptHash,
      executorId, executorKeyId, previousEntryHash, entryBodyHash,
      createdAt, state === "provisional" ? createdAt : null, null, trustEpoch,
      legacySignatureStatus, executorSignatureStatus
    );

    // Compare-and-swap the head against the exact prior head we read.
    const swap = db.prepare(
      "UPDATE ledger_head SET sequence = ?, entry_hash = ? WHERE id = 1 AND sequence = ? AND entry_hash = ?"
    ).run(sequence, entryBodyHash, head.sequence, head.entry_hash);
    if (swap.changes !== 1) {
      db.exec("ROLLBACK");
      return { ok: false, code: SQLITE_LEDGER_ERRORS.HEAD_MISMATCH, message: "ledger head moved during append" };
    }

    db.exec("COMMIT");
    return { ok: true, sequence, entry_hash: entryBodyHash, receipt_hash: receiptHash };
  } catch (error) {
    try { db.exec("ROLLBACK"); } catch { /* already rolled back */ }
    const message = error instanceof Error ? error.message : String(error);
    // UNIQUE violations (duplicate sequence / entry id) surface as a conflict.
    const code = /UNIQUE|constraint/i.test(message) ? SQLITE_LEDGER_ERRORS.APPEND_CONFLICT : SQLITE_LEDGER_ERRORS.UNAVAILABLE;
    return { ok: false, code, message };
  }
}

// Walk the ledger in order and prove the full integrity contract:
// sequence continuity, previous_entry_hash chain, entry_body_hash recomputation,
// and head == last entry. Returns { ok } or { ok:false, code, detail }.
export function verifySqliteLedger(db) {
  const rows = db.prepare(`
    SELECT ledger_sequence, entry_id, entry_type, receipt_id, receipt_hash,
           executor_id, executor_key_id, previous_entry_hash, entry_body_hash,
           trust_epoch, legacy_signature_status, executor_signature_status, created_at
    FROM ledger_entries ORDER BY ledger_sequence ASC
  `).all();

  let previousHash = null;
  let expectedSequence = 1;
  for (const row of rows) {
    if (row.ledger_sequence !== expectedSequence) {
      return { ok: false, code: "ERR_LEDGER_SEQUENCE", detail: `expected ${expectedSequence}, got ${row.ledger_sequence}` };
    }
    const expectedPrev = expectedSequence === 1 ? null : previousHash;
    if ((row.previous_entry_hash ?? null) !== expectedPrev) {
      return { ok: false, code: "ERR_LEDGER_CHAIN_BROKEN", detail: `sequence ${row.ledger_sequence} parent mismatch` };
    }
    const recomputed = computeLedgerEntryBodyHash({
      ledger_sequence: row.ledger_sequence,
      entry_type: row.entry_type,
      receipt_id: row.receipt_id,
      receipt_hash: row.receipt_hash,
      executor_id: row.executor_id,
      executor_key_id: row.executor_key_id,
      previous_entry_hash: row.previous_entry_hash,
      trust_epoch: row.trust_epoch,
      legacy_signature_status: row.legacy_signature_status,
      executor_signature_status: row.executor_signature_status,
      created_at: row.created_at
    });
    if (recomputed !== row.entry_body_hash) {
      return { ok: false, code: "ERR_LEDGER_ENTRY_HASH", detail: `sequence ${row.ledger_sequence} body hash mismatch` };
    }
    previousHash = row.entry_body_hash;
    expectedSequence += 1;
  }

  const head = readLedgerHead(db);
  const expectedHeadSeq = rows.length;
  const expectedHeadHash = rows.length === 0 ? "" : rows[rows.length - 1].entry_body_hash;
  if (head.sequence !== expectedHeadSeq || head.entry_hash !== expectedHeadHash) {
    return { ok: false, code: SQLITE_LEDGER_ERRORS.HEAD_MISMATCH, detail: "head does not match final entry" };
  }
  return { ok: true, entry_count: rows.length };
}

export { LedgerError };
