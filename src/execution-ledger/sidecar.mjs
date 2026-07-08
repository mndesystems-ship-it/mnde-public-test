// Sidecar ↔ execution-ledger integration.
//
// Keeps the wiring out of the sidecar hot path: resolve where the ledger lives,
// and append one entry per finalized receipt with the right fail-closed posture.
//
// Location model: the ledger lives NEXT TO the receipt store it references, so a
// receipt_ref is just the receipt file's basename resolved against that shared
// directory — no path traversal, no cwd coupling, and naturally isolated per
// deployment (and per test). MNDE_EXECUTION_LEDGER_PATH overrides the ledger file
// location explicitly; the receipt root stays the receipt store's directory.

import { existsSync, readFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

import { appendLedgerEntry } from "./append.mjs";
import { verifyLedger } from "./verify.mjs";
import { isLedgerDisabled } from "./paths.mjs";
import { LEDGER_ERRORS } from "./index.mjs";

export const LEDGER_HEAD_SCHEMA = "mnde.execution_ledger.head.v1";
export const LEDGER_EXPORT_SCHEMA = "mnde.execution_ledger.export.v1";

const DEFAULT_LEDGER_FILENAME = "mnde-execution-ledger.jsonl";

// Build the per-worker ledger runtime from env + the worker's receipt store path.
export function resolveLedgerRuntime(env, receiptStorePath) {
  const receiptRoot = dirname(receiptStorePath);
  const override = typeof env.MNDE_EXECUTION_LEDGER_PATH === "string" && env.MNDE_EXECUTION_LEDGER_PATH.trim() !== ""
    ? env.MNDE_EXECUTION_LEDGER_PATH
    : null;
  return {
    enabled: !isLedgerDisabled(env),
    ledgerPath: override ?? join(receiptRoot, DEFAULT_LEDGER_FILENAME),
    receiptRoot,
    receiptStorePath
  };
}

function ledgerFailure(profile, code, message) {
  const failClosed = profile === "production";
  if (!failClosed) {
    // Dev/local: surface the failure in logs (and the caller may add it to
    // response metadata). NEVER mutate the receipt to record ledger status.
    process.stderr.write(`${JSON.stringify({
      ts: new Date().toISOString(),
      event: "mnde.execution_ledger.append_failed",
      code,
      message
    })}\n`);
  }
  return { enabled: true, appended: false, failClosed, code, message };
}

// Append a finalized receipt to the ledger.
//   runtime   from resolveLedgerRuntime
//   receipt   the persisted receipt object (hashed via canonicalizeJson)
//   durable   the receipt queue's durability promise (awaited so the entry only
//             ever references an on-disk receipt); may be null/undefined
//   profile   "production" | "local"
//   engine    { name, version }
// Returns { enabled, appended, sequence?, entry_hash?, failClosed?, code? }.
export async function recordReceiptInLedger({ runtime, receipt, durable, profile, engine, flush }) {
  if (!runtime?.enabled) return { enabled: false };

  // The receipt must exist on disk before we commit to referencing it. If it
  // never becomes durable, do NOT append — fail closed in production. Trigger a
  // flush first so durability does not wait on the batch timer (bounds latency in
  // throughput mode without weakening the on-disk-before-append guarantee).
  if (durable) {
    try {
      if (typeof flush === "function") flush();
      await durable;
    } catch (error) {
      return ledgerFailure(profile, LEDGER_ERRORS.APPEND_FAILED, `receipt not durable: ${error?.message ?? error}`);
    }
  }

  const result = await appendLedgerEntry({
    ledgerPath: runtime.ledgerPath,
    receipt,
    receiptRef: { path: basename(runtime.receiptStorePath), receipt_id: receipt?.receipt_id ?? null },
    engine
  });
  if (!result.ok) return ledgerFailure(profile, result.code, result.message);

  return { enabled: true, appended: true, sequence: result.sequence, entry_hash: result.entry_hash };
}

// Compact response metadata (lives OUTSIDE the receipt). Returns null when the
// ledger is disabled so the caller can omit the field entirely.
export function ledgerResponseMeta(outcome) {
  if (!outcome || outcome.enabled === false) return null;
  return outcome.appended
    ? { enabled: true, appended: true, sequence: outcome.sequence, entry_hash: outcome.entry_hash }
    : { enabled: true, appended: false };
}

// ── Read endpoints (head / verify / export) ──────────────────────────────────

function verifyRuntime(runtime) {
  return verifyLedger({ ledgerPath: runtime.ledgerPath, receiptRoot: runtime.receiptRoot });
}

export function ledgerHeadResponse(runtime) {
  const result = verifyRuntime(runtime);
  return {
    schema: LEDGER_HEAD_SCHEMA,
    ledger_path: runtime.ledgerPath,
    ok: result.ok,
    head: result.head,
    entries_checked: result.entries_checked
  };
}

export function ledgerVerifyResponse(runtime) {
  return verifyRuntime(runtime);
}

export function ledgerExportResponse(runtime) {
  if (!existsSync(runtime.ledgerPath)) {
    return { schema: LEDGER_EXPORT_SCHEMA, ledger_path: runtime.ledgerPath, entry_count: 0, entries: [] };
  }
  const lines = readFileSync(runtime.ledgerPath, "utf8").split("\n").filter((line) => line.trim() !== "");
  const entries = lines.map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return { malformed: true, raw: line };
    }
  });
  return { schema: LEDGER_EXPORT_SCHEMA, ledger_path: runtime.ledgerPath, entry_count: entries.length, entries };
}
