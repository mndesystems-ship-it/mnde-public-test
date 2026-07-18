// Receipt-index integration tests for frozen PE Receipt v1 and rule-bound v2.

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { INDEX_SCHEMA_VERSION, openIndex } from "../src/receipt-index/db.mjs";
import { filtersFrom } from "../src/receipt-index/cli.mjs";
import { extractEnvelope, isKnownSchema } from "../src/receipt-index/extract.mjs";
import { findReceipts, ingestRoots } from "../src/receipt-index/find.mjs";
import { verifyAnyReceiptObject } from "../tools/verify.mjs";

const readJson = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
const v1Receipt = readJson("../conformance/vectors/mnde.pe.receipt.v1.allow.json");
const v2Receipt = readJson("../conformance/vectors/mnde.pe.receipt.v2.allow.json");
const v1Authority = readJson("../conformance/vectors/mnde.authority.bundle.v1.json");
const v2Authority = readJson("../conformance/vectors/mnde.authority.bundle.v2.json");

const results = [];
let testChain = Promise.resolve();
function test(name, fn) {
  testChain = testChain.then(async () => {
    try {
      await fn();
      results.push(true);
      console.log(`  [PASS] ${name}`);
    } catch (error) {
      results.push(false);
      console.log(`  [FAIL] ${name}: ${error.stack ?? error.message}`);
    }
  });
}

function verifierOptions(authority) {
  return {
    authorityBundle: authority,
    trustedRootFingerprint: authority.root_key.fingerprint,
    now: "2026-06-25T00:00:00.000Z"
  };
}

async function verifyPolicyVector(receipt) {
  const authority = receipt.schema_version === "mnde.pe.receipt.v2" ? v2Authority : v1Authority;
  return verifyAnyReceiptObject(receipt, verifierOptions(authority));
}

const work = mkdtempSync(join(tmpdir(), "mnde-receipt-index-pe-v2-"));
const store = join(work, "receipts");
mkdirSync(store, { recursive: true });
writeFileSync(join(store, "pe-v1.json"), JSON.stringify(v1Receipt));
writeFileSync(join(store, "pe-v2.json"), JSON.stringify(v2Receipt));
writeFileSync(join(store, "unknown.json"), JSON.stringify({
  schema_version: "mnde.pe.receipt.v99",
  request_hash: "sha256:" + "9".repeat(64),
  decision_output: { decision: "ALLOW", rule_id: "must-not-be-trusted" }
}));

test("PE v1 extraction remains supported and never synthesizes rule_id", () => {
  assert.equal(isKnownSchema("mnde.pe.receipt.v1"), true);
  const envelope = extractEnvelope(v1Receipt);
  assert.equal(envelope.schema_version, "mnde.pe.receipt.v1");
  assert.equal(envelope.decision, "ALLOW");
  assert.equal(envelope.request_hash, v1Receipt.request_hash);
  assert.equal(envelope.rule_id, null);

  const hostileV1 = structuredClone(v1Receipt);
  hostileV1.decision_output.rule_id = "not-a-v1-field";
  assert.equal(extractEnvelope(hostileV1).rule_id, null);
});

test("PE v1 conformance vector still routes through and passes the PE verifier", async () => {
  assert.equal(Object.hasOwn(v1Receipt.decision_output, "rule_id"), false);
  const result = await verifyAnyReceiptObject(v1Receipt, verifierOptions(v1Authority));
  assert.equal(result.kind, "policy-engine");
  assert.equal(result.verified, true, result.reason);
});

test("PE v2 extraction preserves its signed rule_id", () => {
  assert.equal(isKnownSchema("mnde.pe.receipt.v2"), true);
  const envelope = extractEnvelope(v2Receipt);
  assert.equal(envelope.schema_version, "mnde.pe.receipt.v2");
  assert.equal(envelope.rule_id, v2Receipt.decision_output.rule_id);
  assert.equal(envelope.request_hash, v2Receipt.request_hash);
  assert.equal(envelope.timestamp, v2Receipt.decision_output.evaluated_at);
});

test("PE v2 conformance vector routes through and passes the PE verifier", async () => {
  const result = await verifyAnyReceiptObject(v2Receipt, verifierOptions(v2Authority));
  assert.equal(result.kind, "policy-engine");
  assert.equal(result.verified, true, result.reason);
});

test("tampering with PE v2 rule_id fails verification", async () => {
  const tampered = structuredClone(v2Receipt);
  tampered.decision_output.rule_id = "tampered-rule";
  const result = await verifyAnyReceiptObject(tampered, verifierOptions(v2Authority));
  assert.equal(result.kind, "policy-engine");
  assert.equal(result.verified, false);
  assert.match(result.reason, /decision drift: rule_id/);
});

test("rule_id persists in SQLite while indexed v1 remains NULL", () => {
  const index = openIndex(join(work, "new", "receipts.db"));
  try {
    ingestRoots(index, [store], { rebuild: true });
    const v2Rows = index.query({ rule_id: v2Receipt.decision_output.rule_id });
    assert.equal(v2Rows.length, 1);
    assert.equal(v2Rows[0].schema_version, "mnde.pe.receipt.v2");
    assert.equal(v2Rows[0].rule_id, v2Receipt.decision_output.rule_id);

    const v1Rows = index.query({ schema_version: "mnde.pe.receipt.v1" });
    assert.equal(v1Rows.length, 1);
    assert.equal(v1Rows[0].rule_id, null);
  } finally {
    index.close();
  }
});

test("indexed and direct searches return and filter PE v2 rule_id", async () => {
  const index = openIndex(join(work, "search", "receipts.db"));
  try {
    ingestRoots(index, [store], { rebuild: true });
    const options = {
      index,
      roots: [store],
      filters: { rule_id: v2Receipt.decision_output.rule_id },
      verify: verifyPolicyVector
    };
    const indexed = await findReceipts(options);
    assert.equal(indexed.hits.length, 1);
    assert.equal(indexed.hits[0].rule_id, v2Receipt.decision_output.rule_id);
    assert.equal(indexed.hits[0].receipt.schema_version, "mnde.pe.receipt.v2");
    assert.equal(indexed.hits[0].verification, "VERIFIED");

    const scanned = await findReceipts({ ...options, noIndex: true });
    assert.equal(scanned.hits.length, 1);
    assert.equal(scanned.hits[0].rule_id, v2Receipt.decision_output.rule_id);

    const missing = await findReceipts({ ...options, filters: { rule_id: "unknown-rule" } });
    assert.equal(missing.hits.length, 0);
  } finally {
    index.close();
  }
});

test("CLI filter mapping accepts --rule-id values", () => {
  assert.deepEqual(
    filtersFrom({ "rule-id": [v2Receipt.decision_output.rule_id] }),
    { rule_id: [v2Receipt.decision_output.rule_id] }
  );
});

test("unknown schemas remain indexed only as unverifiable envelopes", async () => {
  assert.equal(isKnownSchema("mnde.pe.receipt.v99"), false);
  assert.equal(extractEnvelope({ schema_version: "mnde.pe.receipt.v99", decision_output: { rule_id: "x" } }).rule_id, null);
  const index = openIndex(join(work, "unknown", "receipts.db"));
  try {
    ingestRoots(index, [store], { rebuild: true });
    let verifierCalled = false;
    const response = await findReceipts({
      index,
      roots: [store],
      filters: { schema_version: "mnde.pe.receipt.v99" },
      verify: async () => {
        verifierCalled = true;
        return { verified: true };
      }
    });
    assert.equal(response.hits.length, 1);
    assert.equal(response.hits[0].verification, "UNVERIFIABLE");
    assert.equal(response.hits[0].verification_reason, "schema_unknown");
    assert.equal(verifierCalled, false);
  } finally {
    index.close();
  }
});

test("a prior v1 database migrates additively and reopens idempotently", () => {
  const dbPath = join(work, "migration", "receipts.db");
  mkdirSync(join(work, "migration"), { recursive: true });
  const old = new DatabaseSync(dbPath);
  old.exec(`
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    INSERT INTO meta (key, value) VALUES ('index_schema', 'mnde.receipt-index.v1');
    CREATE TABLE receipts (
      path TEXT NOT NULL,
      line INTEGER NOT NULL DEFAULT -1,
      schema_version TEXT,
      request_hash TEXT,
      request_id TEXT,
      decision TEXT,
      reason_code TEXT,
      tenant_id TEXT,
      actor TEXT,
      tools TEXT NOT NULL DEFAULT '[]',
      region TEXT,
      policy_hash TEXT,
      policy_version TEXT,
      key_id TEXT,
      timestamp TEXT,
      cost_micro_usd INTEGER,
      surface TEXT,
      file_size INTEGER,
      file_mtime_ms INTEGER,
      parse_error TEXT,
      PRIMARY KEY (path, line)
    );
    INSERT INTO receipts (path, line, schema_version, decision, tools)
    VALUES ('legacy-v1.json', -1, 'mnde.pe.receipt.v1', 'ALLOW', '[]');
  `);
  old.close();

  const migrated = openIndex(dbPath);
  try {
    assert.equal(migrated.status().index_schema, INDEX_SCHEMA_VERSION);
    const rows = migrated.query({ schema_version: "mnde.pe.receipt.v1" });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].rule_id, null);
  } finally {
    migrated.close();
  }

  const reopened = openIndex(dbPath);
  reopened.close();
  const inspected = new DatabaseSync(dbPath, { readOnly: true });
  try {
    const ruleColumns = inspected.prepare("PRAGMA table_info(receipts)").all().filter((column) => column.name === "rule_id");
    assert.equal(ruleColumns.length, 1);
    assert.equal(inspected.prepare("SELECT rule_id FROM receipts WHERE path = 'legacy-v1.json'").get().rule_id, null);
    assert.ok(inspected.prepare("PRAGMA index_list(receipts)").all().some((entry) => entry.name === "idx_receipts_rule_id"));
  } finally {
    inspected.close();
  }
});

await testChain;
rmSync(work, { recursive: true, force: true });
const failed = results.filter((passed) => !passed).length;
console.log(failed === 0 ? `\nreceipt-index PE v2: all ${results.length} tests passed` : `\nreceipt-index PE v2: ${failed}/${results.length} tests FAILED`);
process.exit(failed === 0 ? 0 : 1);
