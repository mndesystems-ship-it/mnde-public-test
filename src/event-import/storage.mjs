import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { EVENT_IMPORT_ERRORS, EventImportError } from "./errors.mjs";
import { isPlainObject } from "./util.mjs";

export const EVENT_STORE_SCHEMA_VERSION = "mnde.event-import-store.v1";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS imports (
  import_id TEXT PRIMARY KEY,
  manifest_version TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  source TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  format TEXT NOT NULL,
  received_at TEXT NOT NULL,
  received_from TEXT,
  import_operator TEXT NOT NULL,
  original_filename TEXT NOT NULL,
  warnings_json TEXT NOT NULL DEFAULT '[]',
  errors_json TEXT NOT NULL DEFAULT '[]',
  adapter_name TEXT,
  adapter_version TEXT,
  event_count INTEGER NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, source, evidence_hash)
);
CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT PRIMARY KEY,
  import_id TEXT NOT NULL UNIQUE REFERENCES imports(import_id),
  tenant_id TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  chain_position INTEGER NOT NULL,
  previous_evidence_hash TEXT,
  size_bytes INTEGER NOT NULL,
  raw_path TEXT NOT NULL,
  manifest_path TEXT NOT NULL,
  manifest_hash TEXT NOT NULL,
  media_type TEXT NOT NULL,
  encoding TEXT NOT NULL,
  compression TEXT NOT NULL,
  signature_status TEXT NOT NULL,
  UNIQUE (tenant_id, chain_position)
);
CREATE TABLE IF NOT EXISTS canonical_events (
  event_id TEXT PRIMARY KEY,
  import_id TEXT NOT NULL REFERENCES imports(import_id),
  tenant TEXT NOT NULL,
  source TEXT NOT NULL,
  actor_id TEXT,
  actor_json TEXT NOT NULL,
  resource_id TEXT,
  resource_json TEXT NOT NULL,
  action TEXT NOT NULL,
  action_category TEXT NOT NULL,
  decision TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  duration INTEGER,
  status TEXT NOT NULL,
  result_json TEXT,
  reason_text TEXT,
  reason_json TEXT,
  risk_level TEXT NOT NULL,
  policy_reference_json TEXT,
  evidence_json TEXT NOT NULL,
  relationships_json TEXT NOT NULL,
  attributes_json TEXT NOT NULL,
  tags_json TEXT NOT NULL,
  event_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actors (
  tenant TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_json TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  PRIMARY KEY (tenant, actor_id)
);
CREATE TABLE IF NOT EXISTS resources (
  tenant TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_json TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  PRIMARY KEY (tenant, resource_id)
);
CREATE TABLE IF NOT EXISTS relationships (
  event_id TEXT NOT NULL REFERENCES canonical_events(event_id) ON DELETE CASCADE,
  tenant TEXT NOT NULL,
  relationship_type TEXT NOT NULL,
  target TEXT NOT NULL,
  PRIMARY KEY (event_id, relationship_type, target)
);
CREATE TABLE IF NOT EXISTS timelines (
  timeline_id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL,
  timeline_type TEXT NOT NULL,
  subject_id TEXT,
  created_at TEXT NOT NULL,
  event_ids_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS receipts (
  tenant TEXT NOT NULL,
  event_id TEXT NOT NULL REFERENCES canonical_events(event_id),
  receipt_reference TEXT NOT NULL,
  PRIMARY KEY (tenant, event_id, receipt_reference)
);
CREATE TABLE IF NOT EXISTS simulation_runs (
  run_id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL,
  mode TEXT NOT NULL,
  policy_reference_json TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  status TEXT NOT NULL,
  event_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS simulation_results (
  run_id TEXT NOT NULL REFERENCES simulation_runs(run_id),
  event_id TEXT NOT NULL REFERENCES canonical_events(event_id),
  historical_decision TEXT NOT NULL,
  simulated_decision TEXT NOT NULL,
  changed_decision INTEGER NOT NULL,
  reason TEXT,
  result_json TEXT NOT NULL,
  PRIMARY KEY (run_id, event_id)
);
CREATE TABLE IF NOT EXISTS policy_decisions (
  run_id TEXT NOT NULL REFERENCES simulation_runs(run_id),
  event_id TEXT NOT NULL REFERENCES canonical_events(event_id),
  policy_reference_json TEXT,
  decision TEXT NOT NULL,
  reason TEXT,
  PRIMARY KEY (run_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_imports_tenant_source ON imports (tenant_id, source, received_at);
CREATE INDEX IF NOT EXISTS idx_events_tenant_timestamp ON canonical_events (tenant, timestamp, event_id);
CREATE INDEX IF NOT EXISTS idx_events_tenant_actor ON canonical_events (tenant, actor_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_tenant_resource ON canonical_events (tenant, resource_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_tenant_action ON canonical_events (tenant, action, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_tenant_decision ON canonical_events (tenant, decision, timestamp);
CREATE INDEX IF NOT EXISTS idx_relationship_target ON relationships (tenant, relationship_type, target);
`;

function parseJson(value, fallback) {
  if (value === null || value === undefined) return fallback;
  try { return JSON.parse(value); } catch { return fallback; }
}

function normalizedImport(row, evidence = null) {
  if (!row) return null;
  return {
    ...row,
    warnings: parseJson(row.warnings_json, []),
    errors: parseJson(row.errors_json, []),
    warnings_json: undefined,
    errors_json: undefined,
    evidence
  };
}

function reasonText(reason) {
  if (typeof reason === "string") return reason;
  if (isPlainObject(reason) && typeof reason.code === "string") return reason.code;
  return null;
}

export function openEventStore(dbPath) {
  mkdirSync(dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;");
  db.exec(SCHEMA);
  db.prepare("INSERT INTO meta (key, value) VALUES ('schema_version', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(EVENT_STORE_SCHEMA_VERSION);

  const insertImport = db.prepare(`INSERT INTO imports (
    import_id, manifest_version, tenant_id, source, evidence_hash, status, format,
    received_at, received_from, import_operator, original_filename, warnings_json
  ) VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, ?)`);
  const insertEvidence = db.prepare(`INSERT INTO evidence (
    evidence_id, import_id, tenant_id, evidence_hash, chain_position, previous_evidence_hash,
    size_bytes, raw_path, manifest_path, manifest_hash, media_type, encoding, compression, signature_status
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  const insertEvent = db.prepare(`INSERT INTO canonical_events (
    event_id, import_id, tenant, source, actor_id, actor_json, resource_id, resource_json,
    action, action_category, decision, timestamp, duration, status, result_json, reason_text,
    reason_json, risk_level, policy_reference_json, evidence_json, relationships_json,
    attributes_json, tags_json, event_json
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  const upsertActor = db.prepare(`INSERT INTO actors (tenant, actor_id, actor_type, actor_json, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(tenant, actor_id) DO UPDATE SET
    actor_json = excluded.actor_json, actor_type = excluded.actor_type,
    first_seen = MIN(first_seen, excluded.first_seen), last_seen = MAX(last_seen, excluded.last_seen)`);
  const upsertResource = db.prepare(`INSERT INTO resources (tenant, resource_id, resource_type, resource_json, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(tenant, resource_id) DO UPDATE SET
    resource_json = excluded.resource_json, resource_type = excluded.resource_type,
    first_seen = MIN(first_seen, excluded.first_seen), last_seen = MAX(last_seen, excluded.last_seen)`);
  const insertRelationship = db.prepare("INSERT OR IGNORE INTO relationships (event_id, tenant, relationship_type, target) VALUES (?, ?, ?, ?)");
  const insertReceipt = db.prepare("INSERT OR IGNORE INTO receipts (tenant, event_id, receipt_reference) VALUES (?, ?, ?)");

  function getImport(importId) {
    const row = db.prepare("SELECT * FROM imports WHERE import_id = ?").get(importId);
    if (!row) return null;
    const evidence = db.prepare("SELECT * FROM evidence WHERE import_id = ?").get(importId) ?? null;
    return normalizedImport(row, evidence);
  }

  return {
    db,
    findDuplicate(tenantId, source, evidenceHash) {
      return normalizedImport(db.prepare("SELECT * FROM imports WHERE tenant_id = ? AND source = ? AND evidence_hash = ?").get(tenantId, source, evidenceHash));
    },
    nextEvidencePosition(tenantId) {
      const row = db.prepare(`SELECT chain_position, evidence_hash FROM evidence
        WHERE tenant_id = ? ORDER BY chain_position DESC LIMIT 1`).get(tenantId);
      return { chainPosition: (row?.chain_position ?? 0) + 1, previousEvidenceHash: row?.evidence_hash ?? null };
    },
    stageImport(manifest, evidence) {
      db.exec("BEGIN IMMEDIATE");
      try {
        insertImport.run(
          manifest.import_id, manifest.manifest_version, manifest.tenant_id, manifest.source,
          manifest.hash, manifest.format, manifest.received_at, manifest.received_from,
          manifest.import_operator, manifest.original_filename, JSON.stringify(manifest.warnings ?? [])
        );
        insertEvidence.run(
          evidence.evidence_id, manifest.import_id, manifest.tenant_id, evidence.evidence_hash, evidence.chain_position,
          evidence.previous_evidence_hash, evidence.size_bytes, evidence.raw_path, evidence.manifest_path,
          evidence.manifest_hash, evidence.media_type, evidence.encoding, evidence.compression, evidence.signature_status
        );
        db.exec("COMMIT");
      } catch (cause) {
        db.exec("ROLLBACK");
        if (/UNIQUE constraint failed: imports\.tenant_id, imports\.source, imports\.evidence_hash/.test(cause.message)) {
          throw new EventImportError(EVENT_IMPORT_ERRORS.DUPLICATE, "This evidence hash was already imported for the tenant and source", { cause });
        }
        throw cause;
      }
      return getImport(manifest.import_id);
    },
    getImport,
    eventExists(tenantId, eventId) {
      return db.prepare("SELECT 1 AS present FROM canonical_events WHERE tenant = ? AND event_id = ?").get(tenantId, eventId)?.present === 1;
    },
    markFailure(importId, status, error) {
      const failure = {
        reason_code: error.reason_code ?? EVENT_IMPORT_ERRORS.INPUT_INVALID,
        severity: error.severity ?? "ERROR",
        message: error.message,
        suggested_action: error.suggested_action ?? null,
        evidence: error.evidence ?? null
      };
      db.prepare("UPDATE imports SET status = ?, errors_json = ? WHERE import_id = ?").run(status, JSON.stringify([failure]), importId);
      return getImport(importId);
    },
    finalizeImport(importId, events, adapter) {
      db.exec("BEGIN IMMEDIATE");
      try {
        db.prepare("DELETE FROM canonical_events WHERE import_id = ?").run(importId);
        for (const event of events) {
          insertEvent.run(
            event.event_id, importId, event.tenant, event.source, event.actor.id, JSON.stringify(event.actor),
            event.resource.id, JSON.stringify(event.resource), event.action, event.action_category,
            event.decision, event.timestamp, event.duration, event.status, JSON.stringify(event.result),
            reasonText(event.reason), JSON.stringify(event.reason), event.risk_level,
            JSON.stringify(event.policy_reference), JSON.stringify(event.evidence), JSON.stringify(event.relationships),
            JSON.stringify(event.attributes), JSON.stringify(event.tags), JSON.stringify(event)
          );
          if (event.actor.id !== null) upsertActor.run(event.tenant, event.actor.id, event.actor_type, JSON.stringify(event.actor), event.timestamp, event.timestamp);
          if (event.resource.id !== null) upsertResource.run(event.tenant, event.resource.id, event.resource_type, JSON.stringify(event.resource), event.timestamp, event.timestamp);
          for (const [type, target] of Object.entries(event.relationships)) {
            for (const value of Array.isArray(target) ? target : [target]) {
              if (value !== null) insertRelationship.run(event.event_id, event.tenant, type, String(value));
            }
          }
          if (event.relationships.receipt !== null) insertReceipt.run(event.tenant, event.event_id, event.relationships.receipt);
        }
        db.prepare(`UPDATE imports SET status = 'COMPLETED', errors_json = '[]', adapter_name = ?,
          adapter_version = ?, event_count = ? WHERE import_id = ?`).run(adapter.name, adapter.version, events.length, importId);
        db.exec("COMMIT");
      } catch (cause) {
        db.exec("ROLLBACK");
        throw cause;
      }
      return getImport(importId);
    },
    queryEvents(filters = {}, options = {}) {
      if (typeof filters.tenant !== "string" || filters.tenant.length === 0) {
        throw new EventImportError(EVENT_IMPORT_ERRORS.QUERY_INVALID, "Every event query requires an explicit tenant");
      }
      const columns = {
        source: "e.source", actor: "e.actor_id", resource: "e.resource_id", action: "e.action",
        action_category: "e.action_category", decision: "e.decision", status: "e.status",
        risk_level: "e.risk_level", import_id: "e.import_id", reason: "e.reason_text"
      };
      const clauses = ["e.tenant = ?"];
      const params = [filters.tenant];
      for (const [key, value] of Object.entries(filters)) {
        if (key === "tenant" || value === undefined || value === null) continue;
        if (key in columns) {
          clauses.push(`${columns[key]} = ?`);
          params.push(String(value));
        } else if (key === "since" || key === "until") {
          if (Number.isNaN(Date.parse(value))) throw new EventImportError(EVENT_IMPORT_ERRORS.QUERY_INVALID, `${key} must be an ISO timestamp`);
          clauses.push(`e.timestamp ${key === "since" ? ">=" : "<="} ?`);
          params.push(new Date(value).toISOString());
        } else if (["workflow", "session", "ticket", "deployment", "receipt"].includes(key)) {
          clauses.push(`EXISTS (SELECT 1 FROM relationships r WHERE r.event_id = e.event_id AND r.relationship_type = ? AND r.target = ?)`);
          params.push(key, String(value));
        } else if (key === "tag") {
          clauses.push("EXISTS (SELECT 1 FROM json_each(e.tags_json) WHERE value = ?)");
          params.push(String(value));
        } else if (["repository", "cluster", "database", "host", "file"].includes(key)) {
          clauses.push(`json_extract(e.resource_json, '$.${key}') = ?`);
          params.push(String(value));
        } else if (key === "branch") {
          clauses.push("json_extract(e.attributes_json, '$.branch') = ?");
          params.push(String(value));
        } else if (key === "policy") {
          clauses.push(`(json_extract(e.policy_reference_json, '$.id') = ? OR
            json_extract(e.policy_reference_json, '$.name') = ? OR
            json_extract(e.policy_reference_json, '$.version') = ? OR
            json_extract(e.policy_reference_json, '$.hash') = ?)`);
          params.push(String(value), String(value), String(value), String(value));
        } else if (key === "evidence_hash") {
          clauses.push("i.evidence_hash = ?");
          params.push(String(value));
        } else {
          throw new EventImportError(EVENT_IMPORT_ERRORS.QUERY_INVALID, `Unknown event query filter: ${key}`);
        }
      }
      const limit = Math.min(Math.max(Number(options.limit ?? 100), 1), 1000);
      const rows = db.prepare(`SELECT e.event_json FROM canonical_events e JOIN imports i ON i.import_id = e.import_id
        WHERE ${clauses.join(" AND ")} ORDER BY e.timestamp ASC, e.event_id ASC LIMIT ?`).all(...params, limit);
      return rows.map((row) => JSON.parse(row.event_json));
    },
    recordSimulation(run, results) {
      db.exec("BEGIN IMMEDIATE");
      try {
        db.prepare(`INSERT INTO simulation_runs (run_id, tenant, mode, policy_reference_json, started_at, completed_at, status, event_count)
          VALUES (?, ?, ?, ?, ?, ?, 'COMPLETED', ?)`).run(run.run_id, run.tenant, run.mode, JSON.stringify(run.policy_reference), run.started_at, run.completed_at, results.length);
        const insertResult = db.prepare(`INSERT INTO simulation_results
          (run_id, event_id, historical_decision, simulated_decision, changed_decision, reason, result_json)
          VALUES (?, ?, ?, ?, ?, ?, ?)`);
        const insertDecision = db.prepare(`INSERT INTO policy_decisions
          (run_id, event_id, policy_reference_json, decision, reason) VALUES (?, ?, ?, ?, ?)`);
        for (const result of results) {
          insertResult.run(run.run_id, result.event_id, result.historical_decision, result.simulated_decision, result.changed_decision ? 1 : 0, result.reason, JSON.stringify(result));
          insertDecision.run(run.run_id, result.event_id, JSON.stringify(run.policy_reference), result.simulated_decision, result.reason);
        }
        db.exec("COMMIT");
      } catch (cause) {
        db.exec("ROLLBACK");
        throw cause;
      }
    },
    close() { db.close(); }
  };
}
