import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

import {
  EVENT_IMPORT_ERRORS,
  PARSER_FORMATS,
  buildTimeline,
  createPassthroughAdapter,
  executionSummary,
  importEvidence,
  openEventStore,
  replayEvents,
  resolveIdentities,
  resumeImport,
  runConnectorImport,
  stageEvidence,
  validateConnector
} from "../src/event-import/index.mjs";

const work = mkdtempSync(join(tmpdir(), "mnde-event-import-"));
const rawRoot = join(work, "raw");
const store = openEventStore(join(work, "events.db"));
const now = new Date("2026-08-05T12:00:00.000Z");
const results = [];
let chain = Promise.resolve();

function test(name, fn) {
  chain = chain.then(async () => {
    try {
      await fn();
      results.push(true);
      console.log(`  [PASS] ${name}`);
    } catch (error) {
      results.push(false);
      console.error(`  [FAIL] ${name}`);
      console.error(error?.stack ?? error);
    }
  });
}

function payload(overrides = {}) {
  return {
    timestamp: "2026-08-05T11:00:00.000Z",
    actor: { id: "actor-1", display_name: "Andrew", email: "andrew@example.test", executor: "executor-1" },
    actor_type: "human",
    resource: { id: "repo-1", type: "repository", repository: "org/repo" },
    resource_type: "repository",
    action: "deploy",
    action_category: "change",
    decision: "allow",
    status: "succeeded",
    risk_level: "high",
    relationships: { workflow: "workflow-1", receipt: "receipt-1" },
    attributes: { environment: "production", branch: "main" },
    tags: ["deployment", "production"],
    ...overrides
  };
}

function importOptions(overrides = {}) {
  return {
    store,
    rawRoot,
    tenantId: "tenant-a",
    source: "manual",
    format: "json",
    filename: "events.json",
    operator: "operator-1",
    now,
    input: JSON.stringify(payload()),
    ...overrides
  };
}

let firstImport;

test("stages immutable evidence and resumes into one canonical event", () => {
  const staged = stageEvidence(importOptions());
  assert.equal(staged.status, "PENDING");
  assert.equal(staged.evidence.chain_position, 1);
  assert.equal(staged.evidence.previous_evidence_hash, null);
  assert.ok(existsSync(staged.evidence.raw_path));
  assert.ok(existsSync(staged.evidence.manifest_path));
  const manifest = JSON.parse(readFileSync(staged.evidence.manifest_path, "utf8"));
  assert.equal(manifest.hash, staged.evidence_hash);
  assert.equal(manifest.import_operator, "operator-1");
  assert.equal(manifest.verification.hash_status, "VERIFIED");

  firstImport = resumeImport({ store, importId: staged.import_id, now });
  assert.equal(firstImport.import.status, "COMPLETED");
  assert.equal(firstImport.events.length, 1);
  assert.equal(firstImport.events[0].event_version, "mnde.canonical_execution_event.v1");
  assert.equal(firstImport.events[0].evidence.raw_hash, staged.evidence_hash);
});

test("completed imports resume idempotently without creating events", () => {
  const resumed = resumeImport({ store, importId: firstImport.import.import_id, now });
  assert.equal(resumed.resumed, true);
  assert.equal(resumed.events.length, 1);
  assert.equal(resumed.events[0].event_id, firstImport.events[0].event_id);
});

test("duplicate evidence is rejected by tenant, source, and hash", () => {
  assert.throws(() => importEvidence(importOptions()), (error) => error.reason_code === EVENT_IMPORT_ERRORS.DUPLICATE && error.import_id === firstImport.import.import_id);
});

test("expected-hash mismatch is preserved and quarantined", () => {
  let importId;
  assert.throws(() => {
    try {
      importEvidence(importOptions({ source: "hash-mismatch", expectedHash: `sha256:${"0".repeat(64)}` }));
    } catch (error) {
      importId = error.import_id;
      throw error;
    }
  }, (error) => error.reason_code === EVENT_IMPORT_ERRORS.HASH_MISMATCH);
  const record = store.getImport(importId);
  assert.equal(record.status, "QUARANTINED");
  assert.ok(existsSync(record.evidence.raw_path));
});

test("tenant-scoped search is deterministic and cannot omit tenant", () => {
  const first = store.queryEvents({ tenant: "tenant-a", actor: "actor-1", action: "deploy", tag: "production" });
  const second = store.queryEvents({ tenant: "tenant-a", actor: "actor-1", action: "deploy", tag: "production" });
  assert.deepEqual(first, second);
  assert.equal(first.length, 1);
  assert.equal(store.queryEvents({ tenant: "tenant-a", repository: "org/repo", branch: "main" }).length, 1);
  assert.throws(() => store.queryEvents({ actor: "actor-1" }), (error) => error.reason_code === EVENT_IMPORT_ERRORS.QUERY_INVALID);
  assert.deepEqual(store.queryEvents({ tenant: "tenant-b" }), []);
});

test("JSONL retains line and byte-offset evidence", () => {
  const result = importEvidence(importOptions({
    source: "jsonl",
    format: "jsonl",
    filename: "events.jsonl",
    input: `${JSON.stringify(payload({ action: "create" }))}\n${JSON.stringify(payload({ action: "update", actor: { id: "actor-2" } }))}\n`
  }));
  assert.equal(result.events.length, 2);
  assert.equal(result.events[0].evidence.line, 1);
  assert.equal(result.events[1].evidence.line, 2);
  assert.ok(result.events[1].evidence.offset > result.events[0].evidence.offset);
});

test("CSV handles quoted fields and normalizes through the same adapter", () => {
  const result = importEvidence(importOptions({
    source: "csv",
    format: "csv",
    filename: "events.csv",
    input: "timestamp,actor,resource,action,action_category,decision,status,risk_level,reason\n2026-08-05T10:00:00.000Z,robot-1,db-1,update,change,review,pending,medium,\"needs, approval\"\n"
  }));
  assert.equal(result.events[0].actor.id, "robot-1");
  assert.equal(result.events[0].reason, "needs, approval");
});

test("gzip is hash-verified as original evidence and decoded for parsing", () => {
  const compressed = gzipSync(Buffer.from(JSON.stringify(payload({ action: "rollback" })), "utf8"));
  const result = importEvidence(importOptions({ source: "gzip", filename: "events.json.gz", input: compressed }));
  assert.equal(result.import.evidence.compression, "gzip");
  assert.equal(result.events[0].action, "rollback");
});

test("required source signatures are accepted only through a verifier hook", () => {
  const result = importEvidence(importOptions({
    source: "signed-source",
    signatures: [{ algorithm: "fixture", value: "valid" }],
    requireSignature: true,
    signatureVerifier(bytes, signatures) {
      return { verified: bytes.length > 0 && signatures[0].value === "valid" };
    }
  }));
  assert.equal(result.import.evidence.signature_status, "VERIFIED");
  assert.equal(result.events[0].evidence.signature, "VERIFIED");
});

test("invalid required signatures are quarantined after preservation", () => {
  let importId;
  assert.throws(() => {
    try {
      importEvidence(importOptions({
        source: "bad-signature",
        signatures: [{ algorithm: "fixture", value: "invalid" }],
        requireSignature: true,
        signatureVerifier() { return { verified: false, reason: "fixture signature mismatch" }; }
      }));
    } catch (error) {
      importId = error.import_id;
      throw error;
    }
  }, (error) => error.reason_code === EVENT_IMPORT_ERRORS.SIGNATURE_INVALID);
  const record = store.getImport(importId);
  assert.equal(record.status, "QUARANTINED");
  assert.ok(existsSync(record.evidence.raw_path));
});

test("malformed JSON is quarantined after raw evidence is preserved", () => {
  let importId;
  assert.throws(() => {
    try {
      importEvidence(importOptions({ source: "bad-json", input: "{not-json" }));
    } catch (error) {
      importId = error.import_id;
      throw error;
    }
  }, (error) => error.reason_code === EVENT_IMPORT_ERRORS.PARSE);
  const record = store.getImport(importId);
  assert.equal(record.status, "QUARANTINED");
  assert.ok(existsSync(record.evidence.raw_path));
  assert.equal(record.errors[0].reason_code, EVENT_IMPORT_ERRORS.PARSE);
});

test("unsupported archive compression is preserved before quarantine", () => {
  const fakeZip = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from("opaque archive bytes")]);
  let importId;
  assert.throws(() => {
    try {
      importEvidence(importOptions({ source: "zip", filename: "events.zip", input: fakeZip }));
    } catch (error) {
      importId = error.import_id;
      throw error;
    }
  }, (error) => error.reason_code === EVENT_IMPORT_ERRORS.COMPRESSION_UNSUPPORTED);
  const record = store.getImport(importId);
  assert.equal(record.status, "QUARANTINED");
  assert.equal(record.evidence.encoding, "unknown");
  assert.ok(existsSync(record.evidence.raw_path));
});

test("normalization failure preserves evidence and a stable action", () => {
  const adapter = { name: "broken", version: "1", normalize() { throw new Error("adapter exploded"); } };
  let importId;
  assert.throws(() => {
    try {
      importEvidence(importOptions({ source: "broken-adapter", adapter }));
    } catch (error) {
      importId = error.import_id;
      throw error;
    }
  }, (error) => error.reason_code === EVENT_IMPORT_ERRORS.NORMALIZATION);
  const record = store.getImport(importId);
  assert.equal(record.status, "PRESERVED");
  assert.match(record.errors[0].suggested_action, /adapter/i);
});

test("canonical validation rejects cross-tenant adapter output", () => {
  let importId;
  assert.throws(() => {
    try {
      importEvidence(importOptions({ source: "tenant-attack", input: JSON.stringify(payload({ tenant: "tenant-b" })) }));
    } catch (error) {
      importId = error.import_id;
      throw error;
    }
  }, (error) => error.reason_code === EVENT_IMPORT_ERRORS.TENANT_MISMATCH);
  assert.equal(store.getImport(importId).status, "PRESERVED");
});

test("unknown event references fail closed", () => {
  const missing = "11111111-1111-4111-8111-111111111111";
  assert.throws(() => importEvidence(importOptions({
    source: "missing-ref",
    input: JSON.stringify(payload({ relationships: { parent_event: missing } }))
  })), (error) => error.reason_code === EVENT_IMPORT_ERRORS.REFERENCE_INVALID);
});

test("parent cycles fail closed before storage", () => {
  const one = "22222222-2222-4222-8222-222222222222";
  const two = "33333333-3333-4333-8333-333333333333";
  const input = [
    payload({ event_id: one, relationships: { parent_event: two } }),
    payload({ event_id: two, relationships: { parent_event: one } })
  ];
  assert.throws(() => importEvidence(importOptions({ source: "cycle", input: JSON.stringify(input) })), (error) => error.reason_code === EVENT_IMPORT_ERRORS.PARENT_CYCLE);
});

test("raw evidence tampering is detected before a staged import resumes", () => {
  const staged = stageEvidence(importOptions({ source: "tamper", input: JSON.stringify(payload({ action: "delete" })) }));
  chmodSync(staged.evidence.raw_path, 0o666);
  writeFileSync(staged.evidence.raw_path, "tampered");
  assert.throws(() => resumeImport({ store, importId: staged.import_id, now }), (error) => error.reason_code === EVENT_IMPORT_ERRORS.EVIDENCE_TAMPERED);
  assert.equal(store.getImport(staged.import_id).status, "QUARANTINED");
});

test("manifest tampering is detected before normalization", () => {
  const staged = stageEvidence(importOptions({ source: "manifest-tamper", input: JSON.stringify(payload({ action: "shutdown" })) }));
  const manifest = JSON.parse(readFileSync(staged.evidence.manifest_path, "utf8"));
  chmodSync(staged.evidence.manifest_path, 0o666);
  writeFileSync(staged.evidence.manifest_path, JSON.stringify({ ...manifest, tenant_id: "tenant-b" }));
  assert.throws(() => resumeImport({ store, importId: staged.import_id, now }), (error) => error.reason_code === EVENT_IMPORT_ERRORS.MANIFEST_INVALID);
  assert.equal(store.getImport(staged.import_id).status, "QUARANTINED");
});

test("connector contract is complete and connectors cannot skip normalization", async () => {
  assert.throws(() => validateConnector({ health() {} }), (error) => error.reason_code === EVENT_IMPORT_ERRORS.CONNECTOR_CONTRACT);
  const connector = {
    name: "fixture-connector",
    discover() { return []; },
    health() { return { ok: true }; },
    import() { return { input: JSON.stringify(payload({ action: "grant" })), filename: "connector.json", format: "json", source: "connector" }; },
    validate() { return { ok: true }; },
    normalize(raw, context) { return createPassthroughAdapter().normalize(raw, context); },
    version() { return "1.0.0"; },
    shutdown() {}
  };
  const result = await runConnectorImport(connector, { store, rawRoot, tenantId: "tenant-a", operator: "operator-1", now });
  assert.equal(result.events[0].action, "grant");
  assert.equal(result.import.adapter_name, "fixture-connector");
});

test("policy replay records comparison results and never executes actions", () => {
  let evaluations = 0;
  const run = replayEvents({
    store,
    tenantId: "tenant-a",
    filters: { import_id: firstImport.import.import_id },
    now,
    policy: { name: "deny-production", version: "1", evaluate(event) { evaluations += 1; return { decision: event.attributes.environment === "production" ? "deny" : "allow", reason: "simulation-only" }; } }
  });
  assert.equal(evaluations, 1);
  assert.equal(run.results[0].would_deny, true);
  assert.equal(run.results[0].changed_decision, true);
});

test("identity/resource views, timelines, and summaries consume canonical events only", () => {
  const events = store.queryEvents({ tenant: "tenant-a" }, { limit: 1000 });
  const identities = resolveIdentities(events, [{ identity_id: "person-andrew", aliases: ["actor-1"] }]);
  assert.ok(identities.some((identity) => identity.id === "person-andrew" && identity.confidence === 1));
  const timeline = buildTimeline(events, { type: "workflow", subjectId: "workflow-1" });
  assert.ok(timeline.events.length >= 1);
  const summary = executionSummary(events);
  assert.equal(summary.event_count, events.length);
  assert.ok(summary.actions.deploy >= 1);
});

test("parser registry exposes every v1 declared import family", () => {
  for (const format of ["json", "jsonl", "ndjson", "csv", "tsv", "xml", "yaml", "sqlite-export", "text-log", "apache-log", "syslog", "evtx-export", "cloudtrail-json", "github-export", "gitlab-export"]) {
    assert.ok(PARSER_FORMATS.includes(format), format);
  }
});

await chain;
store.close();
rmSync(work, { recursive: true, force: true });
const failed = results.filter((passed) => !passed).length;
console.log(failed === 0 ? `\nPASS generic event import foundation (${results.length}/${results.length})` : `\nFAIL generic event import foundation (${results.length - failed}/${results.length})`);
process.exit(failed === 0 ? 0 : 1);
