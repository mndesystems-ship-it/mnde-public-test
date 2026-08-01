// Idempotent JSONL -> SQLite ledger migration.
//
// Imports the legacy JSONL execution ledger into the transactional SQLite ledger
// WITHOUT rewriting any original hash. Every imported entry is marked legacy
// (entry_type=legacy_jsonl_receipt, trust_epoch=legacy-shared-key) and keeps its
// original entry_hash as the chain link, so a native append can continue the
// chain from the last legacy entry.
//
// Safety contract:
//   * The source JSONL file is only READ; it is never modified or deleted.
//   * The source chain is fully verified first (sequence continuity, parent
//     links, entry_hash recomputation, duplicate detection). Malformed input is
//     NEVER silently skipped and evidence is NEVER silently repaired — any
//     anomaly returns a clear BLOCKED result.
//   * Import is atomic: a single BEGIN IMMEDIATE transaction inserts every entry,
//     moves the head, and records the migration. A crash rolls the whole thing
//     back, so re-running is safe and never double-imports.
//   * Idempotent: keyed by source_path + source_hash in migration_state. A second
//     run over the same file is a no-op; a changed source file is a CONFLICT.
//   * Migration only runs onto a FRESH ledger (no pre-existing entries).

import { existsSync, readFileSync } from "node:fs";

import { computeEntryHash, LEDGER_ENTRY_SCHEMA, sha256Prefixed } from "./index.mjs";
import { LEGACY_JSONL_ENTRY_TYPE, LEGACY_TRUST_EPOCH, verifySqliteLedger } from "./sqlite-ledger.mjs";

export const MIGRATION_ERRORS = Object.freeze({
  BLOCKED: "ERR_LEDGER_MIGRATION_BLOCKED",
  FAILED: "ERR_LEDGER_MIGRATION_FAILED",
  CONFLICT: "ERR_LEDGER_MIGRATION_CONFLICT"
});

function blocked(code, detail, status = "BLOCKED") {
  return { ok: false, status, code, detail };
}

// Migrate the JSONL ledger at jsonlPath into the open SQLite `db`.
export function migrateJsonlLedger({ jsonlPath, db, now }) {
  if (typeof jsonlPath !== "string" || jsonlPath.length === 0) {
    return blocked(MIGRATION_ERRORS.BLOCKED, "jsonlPath is required");
  }
  if (!existsSync(jsonlPath)) {
    return { ok: true, status: "NO_SOURCE", imported: 0 };
  }

  const bytes = readFileSync(jsonlPath);
  const sourceHash = sha256Prefixed(bytes);

  // Idempotency / conflict.
  const prior = db.prepare("SELECT source_hash, imported_count, status FROM migration_state WHERE source_path = ?").get(jsonlPath);
  if (prior && prior.status === "complete") {
    if (prior.source_hash === sourceHash) {
      return { ok: true, status: "ALREADY_MIGRATED", imported: prior.imported_count, source_hash: sourceHash };
    }
    return blocked(MIGRATION_ERRORS.CONFLICT, "source file changed since a completed migration");
  }
  // A prior non-complete marker means a crashed attempt. The import is atomic, so
  // nothing was durably written; clear the stale marker and retry cleanly.
  if (prior) db.prepare("DELETE FROM migration_state WHERE source_path = ?").run(jsonlPath);

  // Parse — no silent skipping.
  const lines = bytes.toString("utf8").split("\n").map((l) => l.trim()).filter((l) => l !== "");
  const entries = [];
  for (let i = 0; i < lines.length; i += 1) {
    let entry;
    try {
      entry = JSON.parse(lines[i]);
    } catch {
      return blocked(MIGRATION_ERRORS.BLOCKED, `line ${i + 1} is not valid JSON`);
    }
    if (!entry || entry.schema !== LEDGER_ENTRY_SCHEMA) {
      return blocked(MIGRATION_ERRORS.BLOCKED, `line ${i + 1} is not a ${LEDGER_ENTRY_SCHEMA}`);
    }
    if (!Number.isSafeInteger(entry.sequence) || typeof entry.entry_hash !== "string" || typeof entry.receipt_hash !== "string" || typeof entry.created_at !== "string") {
      return blocked(MIGRATION_ERRORS.BLOCKED, `line ${i + 1} is missing required fields`);
    }
    entries.push(entry);
  }

  // Verify the source chain: sequence continuity, parent links, entry_hash
  // recompute, duplicate detection. Never repair — only prove.
  const seenSeq = new Set();
  const seenHash = new Set();
  let prev = null;
  for (let i = 0; i < entries.length; i += 1) {
    const e = entries[i];
    if (e.sequence !== i + 1) return blocked(MIGRATION_ERRORS.BLOCKED, `sequence gap at index ${i}: got ${e.sequence}`);
    if (seenSeq.has(e.sequence)) return blocked(MIGRATION_ERRORS.BLOCKED, `duplicate sequence ${e.sequence}`);
    if (seenHash.has(e.entry_hash)) return blocked(MIGRATION_ERRORS.BLOCKED, `duplicate entry_hash at sequence ${e.sequence}`);
    seenSeq.add(e.sequence);
    seenHash.add(e.entry_hash);
    const expectedPrev = i === 0 ? null : prev;
    if ((e.previous_entry_hash ?? null) !== expectedPrev) return blocked(MIGRATION_ERRORS.BLOCKED, `broken chain at sequence ${e.sequence}`);
    if (computeEntryHash(e) !== e.entry_hash) return blocked(MIGRATION_ERRORS.BLOCKED, `entry_hash mismatch at sequence ${e.sequence}`);
    prev = e.entry_hash;
  }

  // Atomic activation onto a fresh ledger.
  const startedAt = now ?? new Date().toISOString();
  try {
    db.exec("BEGIN IMMEDIATE");
    const existing = db.prepare("SELECT COUNT(*) AS c FROM ledger_entries").get().c;
    if (existing > 0) {
      db.exec("ROLLBACK");
      return blocked(MIGRATION_ERRORS.BLOCKED, "target ledger already has entries; migrate only onto a fresh ledger");
    }

    const insert = db.prepare(`
      INSERT INTO ledger_entries (
        ledger_sequence, entry_id, entry_type, state, receipt_id, receipt_hash,
        executor_id, executor_key_id, previous_entry_hash, entry_body_hash,
        created_at, provisional_at, finalized_at, trust_epoch,
        legacy_signature_status, executor_signature_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const e of entries) {
      insert.run(
        e.sequence, e.entry_hash, LEGACY_JSONL_ENTRY_TYPE, "provisional",
        e.receipt_ref?.receipt_id ?? null, e.receipt_hash, null, null,
        e.previous_entry_hash ?? null, e.entry_hash, e.created_at, e.created_at, null,
        LEGACY_TRUST_EPOCH, "legacy", "none"
      );
    }
    const n = entries.length;
    if (n > 0) {
      db.prepare("UPDATE ledger_head SET sequence = ?, entry_hash = ? WHERE id = 1").run(n, entries[n - 1].entry_hash);
    }
    const finishedAt = now ?? new Date().toISOString();
    db.prepare(
      "INSERT INTO migration_state (source_path, source_hash, imported_count, started_at, finished_at, status) VALUES (?, ?, ?, ?, ?, 'complete')"
    ).run(jsonlPath, sourceHash, n, startedAt, finishedAt);
    db.exec("COMMIT");
  } catch (error) {
    try { db.exec("ROLLBACK"); } catch { /* already rolled back */ }
    return blocked(MIGRATION_ERRORS.FAILED, `import failed: ${error instanceof Error ? error.message : String(error)}`, "FAILED");
  }

  // Post-commit verification: count and full chain integrity.
  const count = db.prepare("SELECT COUNT(*) AS c FROM ledger_entries").get().c;
  if (count !== entries.length) {
    return blocked(MIGRATION_ERRORS.FAILED, `imported count ${count} != ${entries.length}`, "FAILED");
  }
  const verify = verifySqliteLedger(db);
  if (!verify.ok) {
    return blocked(MIGRATION_ERRORS.FAILED, `post-migration verify failed: ${verify.code} ${verify.detail ?? ""}`, "FAILED");
  }

  return {
    ok: true,
    status: "MIGRATED",
    imported: entries.length,
    source_hash: sourceHash,
    manifest: {
      source_path: jsonlPath,
      source_hash: sourceHash,
      imported_count: entries.length,
      first_sequence: entries.length ? 1 : 0,
      last_sequence: entries.length,
      started_at: startedAt,
      status: "complete"
    }
  };
}
