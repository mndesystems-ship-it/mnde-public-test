// Receipt search hostile tests.
//
//   node ./tests/test_receipt_index.mjs
//
// Proves the receipt index is untrusted-by-construction: a poisoned or stale
// index can never surface a forged receipt as VERIFIED, never change what a
// receipt says, and never hide that it lied. Also proves deterministic output
// and index/no-index equivalence. See docs/RECEIPT_SEARCH_SPEC.md §10.

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { openIndex } from "../src/receipt-index/db.mjs";
import { findReceipts, ingestRoots } from "../src/receipt-index/find.mjs";

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
      console.log(`  [FAIL] ${name}: ${error.message}`);
    }
  });
}

// ── Fixtures ──────────────────────────────────────────────────────────────────
// Custody-shaped receipts (a known schema) with a stub signature marker the
// stub verifier interprets. Real signature verification is covered by the
// existing verifier test suites; these tests target index trust semantics.

function receipt(overrides = {}) {
  return {
    schema_version: "mnde.receipt.v2_5",
    tenant_id: "tenant-a",
    request_hash: "a".repeat(64),
    decision: "ALLOW",
    reason_code: "POLICY_MATCH",
    policy_hash: "b".repeat(64),
    policy_version: "policy.v1",
    key_set_version: "ks1",
    timestamp: "2026-07-01T00:00:00.000Z",
    decision_payload_hash: "c".repeat(64),
    key_id: "key-1",
    signature: "sig",
    signatures: [],
    quorum: { required_signatures: 1, valid_signatures: 1, allowed_key_ids: ["key-1"] },
    _test_sig: "good",
    ...overrides
  };
}

async function stubVerify(candidate) {
  if (candidate._test_sig === "good") return { verified: true };
  if (candidate._test_sig === "badsig") return { verified: false, reason: "Ed25519 signature verification failed" };
  if (candidate._test_sig === "nokey") return { verified: false, reason: "key_id not present in authority bundle" };
  return { verified: false, reason: "unknown" };
}

const work = mkdtempSync(join(tmpdir(), "mnde-receipt-index-"));
const storeRoot = join(work, "receipts");
mkdirSync(join(storeRoot, "surface-one"), { recursive: true });
mkdirSync(join(storeRoot, "surface-two"), { recursive: true });

const r1 = receipt({ request_hash: "1".repeat(64), timestamp: "2026-07-01T01:00:00.000Z", decision: "ALLOW", tenant_id: "tenant-a" });
const r2 = receipt({ request_hash: "2".repeat(64), timestamp: "2026-07-02T01:00:00.000Z", decision: "REFUSE", reason_code: "LIMIT_EXCEEDED", tenant_id: "tenant-b", _test_sig: "badsig" });
const r3 = receipt({ request_hash: "3".repeat(64), timestamp: "2026-07-03T01:00:00.000Z", decision: "ALLOW", tenant_id: "tenant-a", key_id: "key-9", _test_sig: "nokey" });
const r4 = receipt({ request_hash: "4".repeat(64), timestamp: "2026-07-04T01:00:00.000Z", decision: "REFUSE", reason_code: "QUOTA", tenant_id: "tenant-a" });
const r5 = { schema_version: "mnde.mystery.v9", request_hash: "5".repeat(64), decision: "ALLOW", timestamp: "2026-07-05T01:00:00.000Z" };

const r1Path = join(storeRoot, "surface-one", "receipt-r1.json");
const r2Path = join(storeRoot, "surface-one", "receipt-r2.json");
const logPath = join(storeRoot, "surface-two", "decisions.jsonl");
writeFileSync(r1Path, JSON.stringify(r1));
writeFileSync(r2Path, JSON.stringify(r2));
writeFileSync(join(storeRoot, "surface-two", "receipt-r5.json"), JSON.stringify(r5));
writeFileSync(logPath, JSON.stringify(r3) + "\n" + JSON.stringify(r4) + "\n");

const dbPath = join(work, "index", "receipts.db");
const roots = [storeRoot];

function freshIndex() {
  const index = openIndex(dbPath);
  ingestRoots(index, roots, { rebuild: true });
  return index;
}

async function find(index, overrides = {}) {
  return findReceipts({ index, roots, verify: stubVerify, ...overrides });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test("rebuild indexes json files and jsonl lines", () => {
  const index = freshIndex();
  try {
    assert.equal(index.status().rows_indexed, 5);
  } finally {
    index.close();
  }
});

test("find filters by decision, tenant, time range; ordering is total", async () => {
  const index = freshIndex();
  try {
    const refused = await find(index, { filters: { decision: "REFUSE" } });
    assert.deepEqual(refused.hits.map((hit) => hit.receipt.request_hash), [r2.request_hash, r4.request_hash]);

    const tenantA = await find(index, { filters: { tenant: "tenant-a", until: "2026-07-03T12:00:00.000Z" } });
    assert.deepEqual(tenantA.hits.map((hit) => hit.receipt.request_hash), [r1.request_hash, r3.request_hash]);
  } finally {
    index.close();
  }
});

test("verification statuses: VERIFIED / TAMPERED / UNVERIFIABLE(key) / UNVERIFIABLE(schema_unknown)", async () => {
  const index = freshIndex();
  try {
    const all = await find(index, { limit: 100 });
    const byHash = Object.fromEntries(all.hits.map((hit) => [hit.receipt.request_hash, hit]));
    assert.equal(byHash[r1.request_hash].verification, "VERIFIED");
    assert.equal(byHash[r2.request_hash].verification, "TAMPERED");
    assert.equal(byHash[r3.request_hash].verification, "UNVERIFIABLE");
    assert.equal(byHash[r5.request_hash].verification, "UNVERIFIABLE");
    assert.equal(byHash[r5.request_hash].verification_reason, "schema_unknown");
    assert.deepEqual(all.summary, { ...all.summary, verified: 2, tampered: 1, unverifiable: 2 });
  } finally {
    index.close();
  }
});

test("same query twice yields byte-identical output", async () => {
  const index = freshIndex();
  try {
    const first = JSON.stringify(await find(index, { filters: { decision: "ALLOW" } }));
    const second = JSON.stringify(await find(index, { filters: { decision: "ALLOW" } }));
    assert.equal(first, second);
  } finally {
    index.close();
  }
});

test("no-index direct scan returns identical hits to indexed query", async () => {
  const index = freshIndex();
  try {
    const indexed = await find(index, { filters: { decision: "REFUSE" } });
    const scanned = await find(index, { filters: { decision: "REFUSE" }, noIndex: true });
    assert.deepEqual(
      scanned.hits.map((hit) => [hit.receipt.request_hash, hit.verification]),
      indexed.hits.map((hit) => [hit.receipt.request_hash, hit.verification])
    );
  } finally {
    index.close();
  }
});

test("forged index row pointing at a missing file is dropped and flags index_dirty", async () => {
  const index = freshIndex();
  try {
    index.upsert({
      path: join(storeRoot, "surface-one", "receipt-forged.json"),
      line: -1,
      surface: "surface-one",
      file_size: 0,
      file_mtime_ms: 0,
      parse_error: null,
      envelope: { schema_version: "mnde.receipt.v2_5", request_hash: "f".repeat(64), request_id: null, decision: "ALLOW", reason_code: null, tenant_id: "tenant-a", actor: null, tools: [], region: null, policy_hash: null, policy_version: null, key_id: null, timestamp: "2026-07-06T00:00:00.000Z", cost_micro_usd: null }
    });
    const response = await find(index, { filters: { decision: "ALLOW" } });
    assert.ok(!response.hits.some((hit) => hit.receipt.request_hash === "f".repeat(64)));
    assert.equal(response.summary.index_orphans, 1);
    assert.equal(response.index_dirty, true);

    const strict = await find(index, { filters: { decision: "ALLOW" }, verifiedOnly: true });
    assert.equal(strict.summary.index_orphans, 1);
  } finally {
    index.close();
  }
});

test("poisoned index row (REFUSE flipped to ALLOW) cannot smuggle the receipt into ALLOW results", async () => {
  const index = freshIndex();
  index.close();
  const raw = new DatabaseSync(dbPath);
  raw.prepare("UPDATE receipts SET decision = 'ALLOW' WHERE request_hash = ?").run(r2.request_hash);
  raw.close();

  const reopened = openIndex(dbPath);
  try {
    const allows = await find(reopened, { filters: { decision: "ALLOW" } });
    assert.ok(!allows.hits.some((hit) => hit.receipt.request_hash === r2.request_hash), "flipped receipt must not appear as ALLOW");
    assert.ok(allows.summary.index_mismatches >= 1);
    assert.equal(allows.index_dirty, true);

    // The file wins and the row self-repairs: the receipt is REFUSE again.
    const refused = await find(reopened, { filters: { decision: "REFUSE" } });
    assert.ok(refused.hits.some((hit) => hit.receipt.request_hash === r2.request_hash));
  } finally {
    reopened.close();
  }
});

test("file modified after indexing: file wins, hit flagged index_repaired", async () => {
  const index = freshIndex();
  try {
    writeFileSync(r1Path, JSON.stringify({ ...r1, reason_code: "POLICY_MATCH_V2" }));
    const response = await find(index, { filters: { request_hash: r1.request_hash } });
    assert.equal(response.hits.length, 1);
    assert.equal(response.hits[0].receipt.reason_code, "POLICY_MATCH_V2");
    assert.equal(response.hits[0].index_repaired, true);
  } finally {
    writeFileSync(r1Path, JSON.stringify(r1));
    index.close();
  }
});

test("verified-only drops non-verified hits and reports ok:false", async () => {
  const index = freshIndex();
  try {
    const response = await find(index, { verifiedOnly: true, limit: 100 });
    assert.ok(response.hits.every((hit) => hit.verification === "VERIFIED"));
    assert.ok(response.summary.dropped_unverified >= 3);
    assert.equal(response.ok, false);
  } finally {
    index.close();
  }
});

test("invalid filters and cursors fail closed with distinct reason codes", async () => {
  const index = freshIndex();
  try {
    await assert.rejects(find(index, { filters: { decision: "MAYBE" } }), (error) => error.reason_code === "ERR_RECEIPT_QUERY_INVALID");
    await assert.rejects(find(index, { filters: { nonsense: "x" } }), (error) => error.reason_code === "ERR_RECEIPT_QUERY_INVALID");
    await assert.rejects(find(index, { cursor: "not-a-cursor!!!" }), (error) => error.reason_code === "ERR_CURSOR_INVALID");
  } finally {
    index.close();
  }
});

test("cursor pagination walks the full result set in order without duplicates", async () => {
  const index = freshIndex();
  try {
    const seen = [];
    let cursor = null;
    for (let page = 0; page < 10; page += 1) {
      const response = await find(index, { limit: 2, cursor });
      seen.push(...response.hits.map((hit) => hit.receipt.request_hash));
      if (response.cursor === null) break;
      cursor = response.cursor;
    }
    assert.deepEqual(seen, [...new Set(seen)]);
    assert.equal(seen.length, 5);
  } finally {
    index.close();
  }
});

test("coverage reports stores scanned so zero results is not mistaken for absence", async () => {
  const index = freshIndex();
  try {
    const response = await find(index, { filters: { tenant: "tenant-nobody" } });
    assert.equal(response.hits.length, 0);
    assert.equal(response.coverage.roots_scanned, 1);
    assert.ok(response.coverage.files_on_disk >= 4);
  } finally {
    index.close();
  }
});

await testChain;
rmSync(work, { recursive: true, force: true });
const failed = results.filter((passed) => !passed).length;
console.log(failed === 0 ? `\nreceipt-index: all ${results.length} tests passed` : `\nreceipt-index: ${failed}/${results.length} tests FAILED`);
process.exit(failed === 0 ? 0 : 1);
