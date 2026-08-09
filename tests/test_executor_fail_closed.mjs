// MNDe Executor — strict fail-closed enforcement (hostile).
//
//   npm run test:executor-fail-closed
//
// The product claim is that execution is contingent on a cryptographically
// verified, exact-request-bound ALLOW receipt — NOT merely the string "ALLOW".
// These tests attack that claim: a sidecar (or anything answering its port) that
// returns ALLOW with no receipt, an unverifiable receipt, or a genuinely valid
// receipt issued for a DIFFERENT request must never cause the wrapped function
// to run.
//
// Cases (b) and (c) reuse a REAL, signed, offline-verifiable receipt captured
// from the live sidecar and replay it against a mismatched request — proving the
// gate binds identity, not just signature validity.

import assert from "node:assert/strict";
import http from "node:http";
import { readFileSync, rmSync } from "node:fs";

import { createMndeExecutor } from "../executor/index.mjs";
import { startMndeSidecar } from "../executor/sidecar-harness.mjs";

const REAL_URL = "http://127.0.0.1:8806";
const MOCK_PORT = 8807;
const MOCK_URL = `http://127.0.0.1:${MOCK_PORT}`;
const RECEIPTS_DIR = "./mnde-receipts/executor-fail-closed-tests";

rmSync(RECEIPTS_DIR, { recursive: true, force: true });

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

// A mock "sidecar" that returns exactly the body we hand it, for any request.
function mockSidecar(bodyForRequest) {
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      let sent = {};
      try { sent = JSON.parse(raw); } catch { /* ignore */ }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(bodyForRequest(sent)));
    });
  });
  return {
    start: () => new Promise((done) => server.listen(MOCK_PORT, "127.0.0.1", done)),
    stop: () => new Promise((done) => server.close(done))
  };
}

async function main() {
  console.log("MNDe Executor — strict fail-closed enforcement\n");

  const sidecar = await startMndeSidecar({ url: REAL_URL, testerId: "EXEC-FC-001" });
  const real = createMndeExecutor({ sidecarUrl: REAL_URL, receiptsDir: RECEIPTS_DIR });

  // Capture a genuine, signed, offline-verifiable ALLOW receipt bound to a known
  // execution id + action. This is the material the replay/substitution attacks
  // below reuse.
  let capturedReceipt = null;
  const REAL_ID = "fc-real-allow-001";
  try {
    await test("positive: a valid, request-bound ALLOW receipt DOES execute", async () => {
      let ran = false;
      const r = await real.execute({ action: "read_status", input: {}, executionId: REAL_ID, run: async () => { ran = true; return "ok"; } });
      assert.equal(r.decision, "ALLOW");
      assert.equal(r.executed, true, "a valid bound receipt must execute");
      assert.equal(ran, true);
      assert.equal(r.verified, true, "the receipt must verify offline");
      assert.ok(r.receipt, "receipt must be present");
      capturedReceipt = r.receipt;
    });
  } finally {
    await sidecar.stop();
  }

  assert.ok(capturedReceipt, "could not capture a real receipt; cannot run replay attacks");

  // (a) Bare ALLOW, NO receipt — the core fail-open bug.
  await test("(a) ALLOW with NO receipt does NOT execute", async () => {
    const mock = mockSidecar(() => ({ decision: "ALLOW", reason_code: "OK_ALLOW" }));
    await mock.start();
    try {
      const exec = createMndeExecutor({ sidecarUrl: MOCK_URL, receiptsDir: RECEIPTS_DIR, timeoutMs: 2000 });
      let ran = false;
      const r = await exec.execute({ action: "read_status", input: {}, run: async () => { ran = true; return "DANGER"; } });
      assert.equal(ran, false, "a bare ALLOW with no receipt must NOT execute");
      assert.equal(r.executed, false);
      assert.equal(r.decision, "REFUSE");
      assert.equal(r.failClosed, true);
      assert.equal(r.reason, "ERR_NO_RECEIPT");
    } finally {
      await mock.stop();
    }
  });

  // (b) A genuinely valid receipt, but for a DIFFERENT execution id (replay).
  await test("(b) a VALID receipt replayed under a different execution id does NOT execute", async () => {
    const mock = mockSidecar(() => ({ decision: "ALLOW", reason_code: "OK_ALLOW", receipt: capturedReceipt }));
    await mock.start();
    try {
      const exec = createMndeExecutor({ sidecarUrl: MOCK_URL, receiptsDir: RECEIPTS_DIR, timeoutMs: 2000 });
      let ran = false;
      // Different execution id than the captured receipt was issued for.
      const r = await exec.execute({ action: "read_status", input: {}, executionId: "fc-replay-999", run: async () => { ran = true; return "DANGER"; } });
      assert.equal(ran, false, "a replayed receipt (wrong execution id) must NOT execute");
      assert.equal(r.executed, false);
      assert.equal(r.decision, "REFUSE");
      assert.equal(r.reason, "ERR_RECEIPT_REQUEST_MISMATCH");
    } finally {
      await mock.stop();
    }
  });

  // (c) A valid receipt for the right execution id but the WRONG action.
  await test("(c) a VALID receipt bound to a different action does NOT execute", async () => {
    const mock = mockSidecar(() => ({ decision: "ALLOW", reason_code: "OK_ALLOW", receipt: capturedReceipt }));
    await mock.start();
    try {
      const exec = createMndeExecutor({ sidecarUrl: MOCK_URL, receiptsDir: RECEIPTS_DIR, timeoutMs: 2000 });
      let ran = false;
      // Matching execution id, but the captured receipt is for read_status — ask
      // to delete backups instead.
      const r = await exec.execute({ action: "delete_backups", input: { path: "backups/" }, executionId: REAL_ID, run: async () => { ran = true; return "DELETED"; } });
      assert.equal(ran, false, "a receipt bound to a different action must NOT execute");
      assert.equal(r.executed, false);
      assert.equal(r.decision, "REFUSE");
      assert.equal(r.reason, "ERR_RECEIPT_ACTION_MISMATCH");
    } finally {
      await mock.stop();
    }
  });

  // (d) ALLOW with a present but unverifiable (forged) receipt.
  await test("(d) ALLOW with an unverifiable receipt does NOT execute", async () => {
    const forged = JSON.parse(JSON.stringify(capturedReceipt));
    // Corrupt the signature so offline verification fails.
    if (forged.signature) forged.signature.value = "0".repeat((forged.signature.value || "").length || 64);
    if (forged.verifiable_signature) forged.verifiable_signature.value = "0".repeat((forged.verifiable_signature.value || "").length || 128);
    const mock = mockSidecar(() => ({ decision: "ALLOW", reason_code: "OK_ALLOW", receipt: forged }));
    await mock.start();
    try {
      const exec = createMndeExecutor({ sidecarUrl: MOCK_URL, receiptsDir: RECEIPTS_DIR, timeoutMs: 2000 });
      let ran = false;
      const r = await exec.execute({ action: "read_status", input: {}, executionId: REAL_ID, run: async () => { ran = true; return "DANGER"; } });
      assert.equal(ran, false, "an unverifiable receipt must NOT execute");
      assert.equal(r.executed, false);
      assert.equal(r.decision, "REFUSE");
      assert.equal(r.reason, "ERR_RECEIPT_UNVERIFIED");
      // A distinct fail-closed refusal record must be written even though a
      // receipt was supplied — so audit can tell the executor refused it.
      assert.ok(r.receiptPath && /failclosed-/.test(r.receiptPath), "a fail-closed refusal record must be persisted");
      const record = JSON.parse(readFileSync(r.receiptPath, "utf8"));
      assert.equal(record.mnde_failclosed, true);
      assert.equal(record.reason, "ERR_RECEIPT_UNVERIFIED");
      assert.ok(record.supplied_receipt_path, "refusal record must reference the supplied receipt");
    } finally {
      await mock.stop();
    }
  });

  // (e, f) Policy-engine path — the SAME gate, a different receipt shape. The
  // MCP proxy runs the executor in PE mode, so the gate must bind PE receipts
  // (flat canonical_request with tool + parameters) just as strictly.
  const { fileURLToPath } = await import("node:url");
  const { dirname, join } = await import("node:path");
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
  const PE_URL = "http://127.0.0.1:8811";
  const pePolicy = join(repoRoot, "examples", "policy-engine", "sample-policy.json");
  const peSidecar = await startMndeSidecar({ url: PE_URL, testerId: "EXEC-FC-PE", env: { MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: pePolicy } });
  let peReceipt = null;
  const PE_ID = "fc-pe-allow-001";
  try {
    await test("(e) policy-engine: a valid, request-bound ALLOW receipt DOES execute", async () => {
      const exec = createMndeExecutor({ sidecarUrl: PE_URL, receiptsDir: RECEIPTS_DIR });
      let ran = false;
      const r = await exec.execute({ action: "read_status", input: {}, executionId: PE_ID, run: async () => { ran = true; return "ok"; } });
      assert.equal(r.executed, true, "a valid PE receipt must execute");
      assert.equal(ran, true);
      assert.equal(r.verified, true);
      peReceipt = r.receipt;
    });
  } finally {
    await peSidecar.stop();
  }
  assert.ok(peReceipt, "could not capture a PE receipt; cannot run the PE replay attack");

  await test("(f) policy-engine: a VALID PE receipt replayed under a different execution id does NOT execute", async () => {
    const mock = mockSidecar(() => ({ decision: "ALLOW", reason_code: "OK_ALLOW", receipt: peReceipt }));
    await mock.start();
    try {
      const exec = createMndeExecutor({ sidecarUrl: MOCK_URL, receiptsDir: RECEIPTS_DIR, timeoutMs: 2000 });
      let ran = false;
      const r = await exec.execute({ action: "read_status", input: {}, executionId: "fc-pe-replay-999", run: async () => { ran = true; return "DANGER"; } });
      assert.equal(ran, false, "a replayed PE receipt (wrong execution id) must NOT execute");
      assert.equal(r.executed, false);
      assert.equal(r.decision, "REFUSE");
      assert.equal(r.reason, "ERR_RECEIPT_REQUEST_MISMATCH");
    } finally {
      await mock.stop();
    }
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL executor fail-closed tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS executor fail-closed tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
