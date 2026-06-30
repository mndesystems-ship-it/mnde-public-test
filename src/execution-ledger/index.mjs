// MNDe V1 Execution Ledger — public surface.
//
// A tamper-evident, append-only hash chain OVER finalized receipts. It is a
// separate integrity layer: it does not change the canonical receipt format, the
// signed envelope, the receipt signing path, or standalone receipt verification.
// Each ledger entry commits to the receipt's canonical hash, the previous entry's
// hash, a monotonic sequence number, a creation timestamp, and the metadata a
// verifier needs to re-find and re-hash the receipt. Delete, edit, reorder, or
// replace a receipt (or a ledger line) and chain verification fails closed.
//
// Hashing reuses the SAME canonicalizer used for receipt signatures
// (canonicalizeJson) and the SAME sha256 helper used elsewhere. No new JSON
// canonicalizer is invented here.

import { canonicalizeJson } from "../../shared/json.ts";
import { sha256Hex } from "../../shared/receipt-replay.mjs";

export const LEDGER_ENTRY_SCHEMA = "mnde.execution_ledger.entry.v1";
export const LEDGER_VERIFY_RESULT_SCHEMA = "mnde.execution_ledger.verify_result.v1";

// Stable, documented error codes. These are part of the ledger's contract.
export const LEDGER_ERRORS = Object.freeze({
  PARSE: "ERR_LEDGER_PARSE",
  SCHEMA: "ERR_LEDGER_SCHEMA",
  SEQUENCE: "ERR_LEDGER_SEQUENCE",
  CHAIN_BROKEN: "ERR_LEDGER_CHAIN_BROKEN",
  ENTRY_HASH: "ERR_LEDGER_ENTRY_HASH",
  RECEIPT_REF_UNSAFE: "ERR_LEDGER_RECEIPT_REF_UNSAFE",
  RECEIPT_MISSING: "ERR_LEDGER_RECEIPT_MISSING",
  RECEIPT_HASH: "ERR_LEDGER_RECEIPT_HASH",
  DUPLICATE_SEQUENCE: "ERR_LEDGER_DUPLICATE_SEQUENCE",
  DUPLICATE_ENTRY_HASH: "ERR_LEDGER_DUPLICATE_ENTRY_HASH",
  APPEND_FAILED: "ERR_LEDGER_APPEND_FAILED",
  LOCK_FAILED: "ERR_LEDGER_LOCK_FAILED",
  DISABLED_IN_PRODUCTION: "ERR_LEDGER_DISABLED_IN_PRODUCTION"
});

// sha256:<hex> of canonical bytes. The "sha256:" prefix names the algorithm in
// the stored ledger so a future hash agility change is explicit, not silent.
export function sha256Prefixed(bytes) {
  return `sha256:${sha256Hex(bytes)}`;
}

// Canonical hash of a receipt object exactly as stored. Reuses canonicalizeJson,
// the same canonicalization the receipt signature is taken over, so re-parsing a
// persisted receipt and re-hashing reproduces this value byte-for-byte (the
// frozen integer-only number model guarantees the round-trip is exact).
export function canonicalReceiptHash(receipt) {
  return sha256Prefixed(canonicalizeJson(receipt));
}

// The body a ledger entry's entry_hash commits to: every field EXCEPT entry_hash
// itself. canonicalizeJson sorts keys, so object construction order is irrelevant.
export function ledgerEntryBody(entry) {
  const { entry_hash: _omit, ...body } = entry;
  return body;
}

export function computeEntryHash(entryWithoutHash) {
  return sha256Prefixed(canonicalizeJson(ledgerEntryBody(entryWithoutHash)));
}

export { resolveLedgerPath, isLedgerDisabled, isProductionProfile, ledgerStartupGate, DEFAULT_LEDGER_PATH } from "./paths.mjs";
export { appendLedgerEntry, buildLedgerEntry } from "./append.mjs";
export { verifyLedger } from "./verify.mjs";
