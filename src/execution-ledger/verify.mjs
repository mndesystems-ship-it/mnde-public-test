// Execution-ledger verification.
//
// Walks the ledger in order and proves the full integrity contract: append-only
// monotonic sequence, an unbroken hash chain, each entry_hash recomputing from
// its own body, no duplicate sequence or entry hash, every receipt_ref path safe,
// every referenced receipt present, and every receipt's canonical bytes matching
// the committed receipt_hash. Any deviation fails closed with a stable error code.
//
// A receipt store is the JSONL the receipts were persisted to (the sidecar's
// receipts log). Receipts are matched by receipt_id when the entry carries one,
// otherwise by canonical content hash.

import { existsSync, readFileSync } from "node:fs";

import {
  LEDGER_ENTRY_SCHEMA,
  LEDGER_VERIFY_RESULT_SCHEMA,
  LEDGER_ERRORS,
  canonicalReceiptHash,
  computeEntryHash
} from "./index.mjs";
import { safeResolveReceiptRefPath } from "./paths.mjs";

function loadReceiptStore(absolutePath) {
  if (!existsSync(absolutePath)) return null;
  const raw = readFileSync(absolutePath, "utf8");
  const byId = new Map();
  const hashes = new Set();
  for (const line of raw.split("\n")) {
    if (line.trim() === "") continue;
    let receipt;
    try {
      receipt = JSON.parse(line);
    } catch {
      // A malformed receipt-store line simply won't match anything; entries
      // referencing it surface as RECEIPT_MISSING / RECEIPT_HASH, not a crash.
      continue;
    }
    const hash = canonicalReceiptHash(receipt);
    hashes.add(hash);
    if (typeof receipt.receipt_id === "string" && receipt.receipt_id.length > 0) {
      byId.set(receipt.receipt_id, hash);
    }
  }
  return { byId, hashes };
}

// Verify the ledger at ledgerPath. receiptRoot is the approved root that every
// receipt_ref.path must resolve inside (defaults to the process cwd).
export function verifyLedger({ ledgerPath, receiptRoot = process.cwd() } = {}) {
  const errors = [];
  const done = (ok, entriesChecked, head) => ({
    schema: LEDGER_VERIFY_RESULT_SCHEMA,
    ok,
    entries_checked: entriesChecked,
    head: ok ? head : null,
    errors
  });

  // A missing or empty ledger has nothing to contradict. (Deletion of the entire
  // ledger + receipt store is explicitly outside the threat model.)
  if (!existsSync(ledgerPath)) return done(true, 0, null);
  const raw = readFileSync(ledgerPath, "utf8");
  const lines = raw.split("\n").map((line, index) => [line, index]).filter(([line]) => line.trim() !== "");
  if (lines.length === 0) return done(true, 0, null);

  const storeCache = new Map();
  const seenSequence = new Set();
  const seenEntryHash = new Set();
  let prev = null;
  let checked = 0;
  let head = null;

  for (const [line, index] of lines) {
    const expectedSequence = prev ? prev.sequence + 1 : 1;

    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      errors.push({ code: LEDGER_ERRORS.PARSE, sequence: expectedSequence, message: `ledger line ${index + 1} is not valid JSON` });
      return done(false, checked, null);
    }

    if (entry.schema !== LEDGER_ENTRY_SCHEMA) {
      errors.push({ code: LEDGER_ERRORS.SCHEMA, sequence: entry.sequence ?? null, message: `unexpected schema '${entry.schema}'` });
      return done(false, checked, null);
    }
    if (!Number.isSafeInteger(entry.sequence) || entry.sequence < 1) {
      errors.push({ code: LEDGER_ERRORS.SEQUENCE, sequence: entry.sequence ?? null, message: "sequence must be a positive integer" });
      return done(false, checked, null);
    }
    if (seenSequence.has(entry.sequence)) {
      errors.push({ code: LEDGER_ERRORS.DUPLICATE_SEQUENCE, sequence: entry.sequence, message: "duplicate sequence" });
      return done(false, checked, null);
    }
    if (entry.sequence !== expectedSequence) {
      errors.push({ code: LEDGER_ERRORS.SEQUENCE, sequence: entry.sequence, message: `expected sequence ${expectedSequence}` });
      return done(false, checked, null);
    }

    const expectedPrev = prev ? prev.entry_hash : null;
    if ((entry.previous_entry_hash ?? null) !== expectedPrev) {
      errors.push({ code: LEDGER_ERRORS.CHAIN_BROKEN, sequence: entry.sequence, message: "previous_entry_hash does not match prior entry_hash" });
      return done(false, checked, null);
    }

    if (typeof entry.entry_hash !== "string" || entry.entry_hash.length === 0) {
      errors.push({ code: LEDGER_ERRORS.ENTRY_HASH, sequence: entry.sequence, message: "entry_hash missing" });
      return done(false, checked, null);
    }
    // Checked before recompute so a forged duplicate (copied entry_hash on a
    // distinct sequence) surfaces as DUPLICATE_ENTRY_HASH, not ENTRY_HASH.
    if (seenEntryHash.has(entry.entry_hash)) {
      errors.push({ code: LEDGER_ERRORS.DUPLICATE_ENTRY_HASH, sequence: entry.sequence, message: "duplicate entry_hash" });
      return done(false, checked, null);
    }
    if (computeEntryHash(entry) !== entry.entry_hash) {
      errors.push({ code: LEDGER_ERRORS.ENTRY_HASH, sequence: entry.sequence, message: "entry_hash does not match recomputed body hash" });
      return done(false, checked, null);
    }

    const ref = entry.receipt_ref ?? {};
    const safe = safeResolveReceiptRefPath(ref.path, receiptRoot);
    if (!safe.ok) {
      errors.push({ code: LEDGER_ERRORS.RECEIPT_REF_UNSAFE, sequence: entry.sequence, message: safe.reason });
      return done(false, checked, null);
    }
    if (!storeCache.has(safe.absolutePath)) storeCache.set(safe.absolutePath, loadReceiptStore(safe.absolutePath));
    const store = storeCache.get(safe.absolutePath);
    if (!store) {
      errors.push({ code: LEDGER_ERRORS.RECEIPT_MISSING, sequence: entry.sequence, message: "referenced receipt store not found" });
      return done(false, checked, null);
    }

    const refId = typeof ref.receipt_id === "string" && ref.receipt_id.length > 0 ? ref.receipt_id : null;
    if (refId) {
      if (!store.byId.has(refId)) {
        errors.push({ code: LEDGER_ERRORS.RECEIPT_MISSING, sequence: entry.sequence, message: `receipt_id '${refId}' not found in store` });
        return done(false, checked, null);
      }
      if (store.byId.get(refId) !== entry.receipt_hash) {
        errors.push({ code: LEDGER_ERRORS.RECEIPT_HASH, sequence: entry.sequence, message: "referenced receipt bytes do not match receipt_hash" });
        return done(false, checked, null);
      }
    } else if (!store.hashes.has(entry.receipt_hash)) {
      errors.push({ code: LEDGER_ERRORS.RECEIPT_MISSING, sequence: entry.sequence, message: "no receipt in store matches receipt_hash" });
      return done(false, checked, null);
    }

    seenSequence.add(entry.sequence);
    seenEntryHash.add(entry.entry_hash);
    prev = { sequence: entry.sequence, entry_hash: entry.entry_hash };
    head = { sequence: entry.sequence, entry_hash: entry.entry_hash, receipt_hash: entry.receipt_hash, created_at: entry.created_at };
    checked += 1;
  }

  return done(true, checked, head);
}
