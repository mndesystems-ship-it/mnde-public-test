// MNDe V1 Execution Ledger — hostile tests.
//
//   npm run test:execution-ledger
//
// Proves the tamper-evident append-only chain over finalized receipts: normal
// append/verify, every tamper class fails closed with the right error code, the
// production fail-closed and disable-in-production rules hold, and — critically —
// the ledger never changes receipt bytes, the signed envelope, or standalone
// receipt verification. A live sidecar run proves entries are appended for real
// decisions and that the read endpoints are authority-gated.

import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalizeJson } from "../shared/json.ts";
import {
  LEDGER_ENTRY_SCHEMA,
  LEDGER_ERRORS,
  canonicalReceiptHash,
  computeEntryHash
} from "../src/execution-ledger/index.mjs";
import { appendLedgerEntry } from "../src/execution-ledger/append.mjs";
import { verifyLedger } from "../src/execution-ledger/verify.mjs";
import { ledgerStartupGate } from "../src/execution-ledger/paths.mjs";
import { resolveLedgerRuntime, recordReceiptInLedger } from "../src/execution-ledger/sidecar.mjs";
import { buildPolicyReceipt, verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import { startMndeSidecar } from "../executor/sidecar-harness.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const samplePolicy = join(repoRoot, "examples", "policy-engine", "sample-policy.json");

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

function tmpRoot() {
  return mkdtempSync(join(tmpdir(), "mnde-ledger-"));
}

// Build a store + 3-entry ledger. Receipts carry a receipt_id so we can exercise
// the precise edit-vs-delete distinction (RECEIPT_HASH vs RECEIPT_MISSING).
async function buildChain(root) {
  const storePath = join(root, "receipts.jsonl");
  const ledgerPath = join(root, ".data", "ledger.jsonl");
  const receipts = [1, 2, 3].map((n) => ({
    receipt_id: `r${n}`,
    schema_version: "mnde.pe.receipt.v1",
    request_hash: `rh${n}`,
    amount_cents: n * 100,
    decision_output: { decision: "REFUSE", reason_code: "NO_MATCHING_RULE" }
  }));
  writeFileSync(storePath, receipts.map((r) => canonicalizeJson(r)).join("\n") + "\n");
  for (const r of receipts) {
    const out = await appendLedgerEntry({ ledgerPath, receipt: r, receiptRef: { path: "receipts.jsonl", receipt_id: r.receipt_id } });
    assert.equal(out.ok, true, `append ${r.receipt_id}: ${out.code ?? ""} ${out.message ?? ""}`);
  }
  return { storePath, ledgerPath, receipts, receiptRoot: root };
}

function ledgerLines(ledgerPath) {
  return readFileSync(ledgerPath, "utf8").split("\n").filter((l) => l.trim() !== "");
}

async function main() {
  console.log("MNDe execution ledger — hostile tests\n");
  bootstrapReceiptKeys({ repoRoot });

  // ── Core append / verify ────────────────────────────────────────────────────
  await test("empty ledger verifies ok with entries_checked 0", () => {
    const root = tmpRoot();
    const ledgerPath = join(root, ".data", "ledger.jsonl");
    mkdirSync(dirname(ledgerPath), { recursive: true });
    writeFileSync(ledgerPath, "");
    const r = verifyLedger({ ledgerPath, receiptRoot: root });
    assert.equal(r.ok, true);
    assert.equal(r.entries_checked, 0);
    assert.equal(r.head, null);
    rmSync(root, { recursive: true, force: true });
  });

  await test("first append creates sequence 1 with previous_entry_hash null", async () => {
    const root = tmpRoot();
    const ledgerPath = join(root, ".data", "ledger.jsonl");
    const r1 = { receipt_id: "r1", v: 1 };
    writeFileSync(join(root, "receipts.jsonl"), canonicalizeJson(r1) + "\n");
    const out = await appendLedgerEntry({ ledgerPath, receipt: r1, receiptRef: { path: "receipts.jsonl", receipt_id: "r1" } });
    assert.equal(out.ok, true);
    assert.equal(out.sequence, 1);
    const entry = JSON.parse(ledgerLines(ledgerPath)[0]);
    assert.equal(entry.sequence, 1);
    assert.equal(entry.previous_entry_hash, null);
    assert.equal(entry.schema, LEDGER_ENTRY_SCHEMA);
    rmSync(root, { recursive: true, force: true });
  });

  await test("second append links to the first entry_hash", async () => {
    const root = tmpRoot();
    const { ledgerPath } = await buildChain(root);
    const [l1, l2] = ledgerLines(ledgerPath).map((l) => JSON.parse(l));
    assert.equal(l2.previous_entry_hash, l1.entry_hash);
    assert.equal(l2.sequence, 2);
    rmSync(root, { recursive: true, force: true });
  });

  await test("receipt_hash matches the canonical receipt bytes", async () => {
    const root = tmpRoot();
    const { ledgerPath, receipts } = await buildChain(root);
    const entry = JSON.parse(ledgerLines(ledgerPath)[0]);
    assert.equal(entry.receipt_hash, canonicalReceiptHash(receipts[0]));
    rmSync(root, { recursive: true, force: true });
  });

  await test("verification passes after normal appends", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const r = verifyLedger({ ledgerPath, receiptRoot });
    assert.equal(r.ok, true);
    assert.equal(r.entries_checked, 3);
    assert.equal(r.head.sequence, 3);
    rmSync(root, { recursive: true, force: true });
  });

  // ── Tampering the receipt store ─────────────────────────────────────────────
  await test("editing a receipt makes verification fail (RECEIPT_HASH)", async () => {
    const root = tmpRoot();
    const { ledgerPath, storePath, receipts, receiptRoot } = await buildChain(root);
    const edited = [{ ...receipts[0], amount_cents: 99999 }, receipts[1], receipts[2]];
    writeFileSync(storePath, edited.map((r) => canonicalizeJson(r)).join("\n") + "\n");
    const r = verifyLedger({ ledgerPath, receiptRoot });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.RECEIPT_HASH);
    rmSync(root, { recursive: true, force: true });
  });

  await test("deleting a receipt makes verification fail (RECEIPT_MISSING)", async () => {
    const root = tmpRoot();
    const { ledgerPath, storePath, receipts, receiptRoot } = await buildChain(root);
    writeFileSync(storePath, [receipts[1], receipts[2]].map((r) => canonicalizeJson(r)).join("\n") + "\n");
    const r = verifyLedger({ ledgerPath, receiptRoot });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.RECEIPT_MISSING);
    rmSync(root, { recursive: true, force: true });
  });

  // ── Tampering the ledger itself ─────────────────────────────────────────────
  await test("editing a ledger line body makes verification fail (ENTRY_HASH)", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    const e = JSON.parse(lines[1]);
    e.created_at = "1999-01-01T00:00:00.000Z"; // change body, keep stored entry_hash
    lines[1] = canonicalizeJson(e);
    writeFileSync(ledgerPath, lines.join("\n") + "\n");
    const r = verifyLedger({ ledgerPath, receiptRoot });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.ENTRY_HASH);
    rmSync(root, { recursive: true, force: true });
  });

  await test("deleting a middle ledger line makes verification fail (SEQUENCE)", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    writeFileSync(ledgerPath, [lines[0], lines[2]].join("\n") + "\n");
    const r = verifyLedger({ ledgerPath, receiptRoot });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.SEQUENCE);
    rmSync(root, { recursive: true, force: true });
  });

  await test("reordering ledger lines makes verification fail", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    writeFileSync(ledgerPath, [lines[1], lines[0], lines[2]].join("\n") + "\n");
    const r = verifyLedger({ ledgerPath, receiptRoot });
    assert.equal(r.ok, false);
    assert.ok([LEDGER_ERRORS.SEQUENCE, LEDGER_ERRORS.CHAIN_BROKEN].includes(r.errors[0].code), r.errors[0].code);
    rmSync(root, { recursive: true, force: true });
  });

  await test("duplicate sequence fails (DUPLICATE_SEQUENCE)", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    // Append a copy of entry 1 (sequence 1) after entry 1.
    writeFileSync(ledgerPath, [lines[0], lines[0]].join("\n") + "\n");
    const r = verifyLedger({ ledgerPath, receiptRoot });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.DUPLICATE_SEQUENCE);
    rmSync(root, { recursive: true, force: true });
  });

  await test("duplicate entry_hash on a distinct sequence fails (DUPLICATE_ENTRY_HASH)", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    const e1 = JSON.parse(lines[0]);
    // Forge a second entry: sequence 2, links correctly, but copies entry 1's hash.
    const forged = { ...e1, sequence: 2, previous_entry_hash: e1.entry_hash };
    writeFileSync(ledgerPath, [lines[0], canonicalizeJson(forged)].join("\n") + "\n");
    const r = verifyLedger({ ledgerPath, receiptRoot });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.DUPLICATE_ENTRY_HASH);
    rmSync(root, { recursive: true, force: true });
  });

  await test("unsafe receipt_ref.path fails (RECEIPT_REF_UNSAFE)", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    const e = JSON.parse(lines[0]);
    e.receipt_ref = { ...e.receipt_ref, path: "../../etc/passwd" };
    delete e.entry_hash;
    e.entry_hash = computeEntryHash(e); // recompute so it survives to the ref check
    writeFileSync(ledgerPath, canonicalizeJson(e) + "\n");
    const r = verifyLedger({ ledgerPath, receiptRoot });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.RECEIPT_REF_UNSAFE);
    rmSync(root, { recursive: true, force: true });
  });

  await test("malformed JSONL line fails (PARSE)", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    writeFileSync(ledgerPath, [lines[0], "{ this is not json", lines[2]].join("\n") + "\n");
    const r = verifyLedger({ ledgerPath, receiptRoot });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.PARSE);
    rmSync(root, { recursive: true, force: true });
  });

  // ── Profile / fail-closed rules ─────────────────────────────────────────────
  await test("production startup fails if ledger disabled", () => {
    assert.equal(ledgerStartupGate({ MNDE_PROFILE: "production", MNDE_EXECUTION_LEDGER: "off" }).ok, false);
    assert.equal(ledgerStartupGate({ MNDE_PROFILE: "production", MNDE_EXECUTION_LEDGER: "off" }).code, LEDGER_ERRORS.DISABLED_IN_PRODUCTION);
    assert.equal(ledgerStartupGate({ MNDE_PROFILE: "local", MNDE_EXECUTION_LEDGER: "off" }).ok, true);
    assert.equal(ledgerStartupGate({ MNDE_PROFILE: "production" }).ok, true);
  });

  await test("production decision fails closed if ledger append fails", async () => {
    const root = tmpRoot();
    // ledgerPath points at a directory -> every append fails.
    const badLedgerDir = join(root, "ledger-as-dir");
    mkdirSync(badLedgerDir, { recursive: true });
    const runtime = { enabled: true, ledgerPath: badLedgerDir, receiptRoot: root, receiptStorePath: join(root, "receipts.jsonl") };
    const receipt = { receipt_id: "x", v: 1 };
    const out = await recordReceiptInLedger({ runtime, receipt, durable: Promise.resolve(), profile: "production", engine: { name: "mnde-policy-engine", version: null } });
    assert.equal(out.appended, false);
    assert.equal(out.failClosed, true);
    assert.equal(out.code, LEDGER_ERRORS.APPEND_FAILED);
    rmSync(root, { recursive: true, force: true });
  });

  await test("local mode reports append failure without mutating the receipt", async () => {
    const root = tmpRoot();
    const badLedgerDir = join(root, "ledger-as-dir");
    mkdirSync(badLedgerDir, { recursive: true });
    const runtime = { enabled: true, ledgerPath: badLedgerDir, receiptRoot: root, receiptStorePath: join(root, "receipts.jsonl") };
    const receipt = { receipt_id: "x", v: 1 };
    const before = canonicalizeJson(receipt);
    const out = await recordReceiptInLedger({ runtime, receipt, durable: Promise.resolve(), profile: "local", engine: { name: "mnde-policy-engine", version: null } });
    assert.equal(out.appended, false);
    assert.equal(out.failClosed, false);
    assert.equal(canonicalizeJson(receipt), before, "receipt bytes must be unchanged");
    assert.equal("ledger" in receipt, false, "receipt must not gain a ledger field");
    rmSync(root, { recursive: true, force: true });
  });

  // ── Receipt-format-unchanged proofs (a real signed pe.receipt.v1) ────────────
  const realRequest = { schema_version: "1.0", request_id: "req-ledger", timestamp: "2026-06-29T00:00:00.000Z", principal: { id: "alice" }, agent: { id: "a1" }, tool: { tool_name: "read_status" }, parameters: {}, environment: {}, context: {} };
  const realPolicy = JSON.parse(readFileSync(samplePolicy, "utf8"));
  const realReceipt = buildPolicyReceipt(realRequest, realPolicy, {});

  await test("recording a receipt does not change its canonical bytes", async () => {
    const root = tmpRoot();
    const before = canonicalizeJson(realReceipt);
    writeFileSync(join(root, "receipts.jsonl"), before + "\n");
    await appendLedgerEntry({ ledgerPath: join(root, ".data", "l.jsonl"), receipt: realReceipt, receiptRef: { path: "receipts.jsonl", receipt_id: null } });
    assert.equal(canonicalizeJson(realReceipt), before, "ledger append must not mutate the receipt");
    rmSync(root, { recursive: true, force: true });
  });

  await test("a recorded receipt still verifies as a standalone pe.receipt.v1", async () => {
    assert.equal(verifyPolicyReceipt(realReceipt).verified, true);
    assert.equal("ledger" in realReceipt, false);
    assert.equal("entry_hash" in realReceipt, false);
  });

  await test("recording by content hash (no receipt_id) round-trips and verifies", async () => {
    const root = tmpRoot();
    const ledgerPath = join(root, ".data", "l.jsonl");
    writeFileSync(join(root, "receipts.jsonl"), canonicalizeJson(realReceipt) + "\n");
    const out = await appendLedgerEntry({ ledgerPath, receipt: realReceipt, receiptRef: { path: "receipts.jsonl", receipt_id: null } });
    assert.equal(out.ok, true);
    const r = verifyLedger({ ledgerPath, receiptRoot: root });
    assert.equal(r.ok, true);
    assert.equal(r.entries_checked, 1);
    rmSync(root, { recursive: true, force: true });
  });

  // ── Live sidecar integration ────────────────────────────────────────────────
  const port = 8801;
  const url = `http://127.0.0.1:${port}`;
  const sidecar = await startMndeSidecar({ url, env: { MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: samplePolicy, MNDE_BIND_PORT: String(port) } });
  try {
    await test("live decisions append ledger entries and /ledger/head verifies (ungated read in local)", async () => {
      const decide = (tool) => fetch(`${url}/v1/decisions`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ schema_version: "1.0", request_id: `req-${tool}`, timestamp: "2026-06-29T00:00:00.000Z", principal: { id: "alice" }, agent: { id: "a1" }, tool: { tool_name: tool }, parameters: {}, environment: {}, context: {} }) }).then((r) => r.json());
      const d1 = await decide("read_status");
      assert.equal(d1.decision_engine, "policy-engine");
      assert.equal(d1.ledger.appended, true, "response must carry ledger metadata outside the receipt");
      assert.equal("ledger" in d1.receipt, false, "ledger metadata must NOT be inside the receipt");
      await decide("read_status");
      const head = await fetch(`${url}/ledger/head`).then((r) => r.json());
      assert.equal(head.ok, true, JSON.stringify(head));
      assert.ok(head.head.sequence >= 2, `expected >= 2 entries, got ${head.head?.sequence}`);
    });

    await test("ledger verify/export endpoints are authority-gated", async () => {
      assert.equal((await fetch(`${url}/ledger/verify`)).status, 403);
      assert.equal((await fetch(`${url}/ledger/export`)).status, 403);
    });
  } finally {
    await sidecar.stop();
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL execution-ledger tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS execution-ledger tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
