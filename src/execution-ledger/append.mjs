// Execution-ledger append path.
//
// Append-only, one JSON line per entry, serialized across processes by an
// exclusive lock file. The read-modify-write (read last entry → compute next →
// append) happens entirely while the lock is held, with no awaits inside the
// critical section, so two concurrent appends can never mint the same sequence.
// If the lock cannot be acquired within a bounded retry budget, the append fails
// closed (ERR_LEDGER_LOCK_FAILED) — it never writes without the lock.

import { openSync, writeSync, fsyncSync, closeSync, readFileSync, existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";

import { canonicalizeJson } from "../../shared/json.ts";
import {
  LEDGER_ENTRY_SCHEMA,
  LEDGER_ERRORS,
  canonicalReceiptHash,
  computeEntryHash
} from "./index.mjs";
import { LEDGER_LOCK_SUFFIX } from "./paths.mjs";

const LOCK_MAX_ATTEMPTS = 100;
const LOCK_RETRY_MS = 5;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Pure entry builder. Given the prior chain head, the receipt, and the ref,
// produce a complete entry including its committed entry_hash. Exported so tests
// can construct entries deterministically (pass createdAt for stable bytes).
export function buildLedgerEntry({ sequence, previousEntryHash, receipt, receiptRef, engine, createdAt }) {
  const body = {
    schema: LEDGER_ENTRY_SCHEMA,
    sequence,
    created_at: createdAt ?? new Date().toISOString(),
    receipt_hash: canonicalReceiptHash(receipt),
    previous_entry_hash: previousEntryHash ?? null,
    receipt_ref: {
      storage: "local",
      path: receiptRef.path,
      receipt_id: receiptRef.receipt_id ?? null
    },
    engine: {
      name: engine?.name ?? "mnde-policy-engine",
      version: engine?.version ?? null
    }
  };
  return { ...body, entry_hash: computeEntryHash(body) };
}

function readChainHead(ledgerPath) {
  if (!existsSync(ledgerPath)) return null;
  const raw = readFileSync(ledgerPath, "utf8");
  const lines = raw.split("\n").filter((line) => line.trim() !== "");
  if (lines.length === 0) return null;
  // Extend only a parseable chain. A corrupt/partial trailing line (e.g. a crash
  // mid-append) fails closed rather than silently chaining onto garbage.
  const last = JSON.parse(lines[lines.length - 1]);
  if (!Number.isSafeInteger(last.sequence) || typeof last.entry_hash !== "string") {
    throw new Error("ledger head is not a well-formed entry");
  }
  return { sequence: last.sequence, entry_hash: last.entry_hash };
}

async function acquireLock(lockPath) {
  for (let attempt = 0; attempt < LOCK_MAX_ATTEMPTS; attempt += 1) {
    try {
      const fd = openSync(lockPath, "wx");
      closeSync(fd);
      return true;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      await sleep(LOCK_RETRY_MS);
    }
  }
  return false;
}

function releaseLock(lockPath) {
  try {
    unlinkSync(lockPath);
  } catch {
    // Best-effort: a missing lock on release is not an error.
  }
}

function appendDurable(ledgerPath, line) {
  const fd = openSync(ledgerPath, "a");
  try {
    writeSync(fd, line);
    try {
      fsyncSync(fd);
    } catch {
      // Best-effort flush; some filesystems reject fsync on append handles.
    }
  } finally {
    closeSync(fd);
  }
}

// Append one ledger entry for a finalized receipt.
//   ledgerPath  absolute or cwd-relative path to the ledger JSONL
//   receipt     the receipt object as persisted (hashed via canonicalizeJson)
//   receiptRef  { path, receipt_id } locating the receipt for the verifier
//   engine      { name, version } provenance
//   createdAt   optional ISO timestamp (defaults to now)
//   lock        set false ONLY in single-writer tests
// Returns { ok, sequence, entry_hash, receipt_hash } or { ok:false, code, message }.
export async function appendLedgerEntry({ ledgerPath, receipt, receiptRef, engine, createdAt, lock = true }) {
  try {
    mkdirSync(dirname(ledgerPath), { recursive: true });
  } catch (error) {
    return { ok: false, code: LEDGER_ERRORS.APPEND_FAILED, message: `mkdir failed: ${error.message}` };
  }

  const lockPath = `${ledgerPath}${LEDGER_LOCK_SUFFIX}`;
  if (lock) {
    let acquired;
    try {
      acquired = await acquireLock(lockPath);
    } catch (error) {
      return { ok: false, code: LEDGER_ERRORS.LOCK_FAILED, message: `lock error: ${error.message}` };
    }
    if (!acquired) {
      return { ok: false, code: LEDGER_ERRORS.LOCK_FAILED, message: "could not acquire ledger lock within retry budget" };
    }
  }

  try {
    const head = readChainHead(ledgerPath);
    const sequence = head ? head.sequence + 1 : 1;
    const previousEntryHash = head ? head.entry_hash : null;
    const entry = buildLedgerEntry({ sequence, previousEntryHash, receipt, receiptRef, engine, createdAt });
    appendDurable(ledgerPath, `${canonicalizeJson(entry)}\n`);
    return { ok: true, sequence, entry_hash: entry.entry_hash, receipt_hash: entry.receipt_hash };
  } catch (error) {
    return { ok: false, code: LEDGER_ERRORS.APPEND_FAILED, message: error.message };
  } finally {
    if (lock) releaseLock(lockPath);
  }
}
