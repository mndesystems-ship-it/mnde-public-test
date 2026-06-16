// OpenClaw integration — live end-to-end evidence.
//
//   npm run test:openclaw
//
// Proves an OpenClaw-style guard works against the REAL MNDe contract: it maps
// an OpenClaw proposed action into the canonical execution-request envelope,
// POSTs to the live sidecar, and gets a real ALLOW / REFUSE with a signed
// receipt — then verifies and replays that receipt. No mocks, no fabricated
// request/response shapes. This is the contract OpenClaw must use (see
// docs/api-contract.md); if it drifts, this test fails.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { reviewerRequest } from "../scripts/reviewer-request.mjs";

const PORT = "8789";
const URL = `http://127.0.0.1:${PORT}`;

// The OpenClaw guard: map a proposed OpenClaw action into the canonical MNDe
// request envelope. OpenClaw's tool/command become the tool_call tool +
// parameters; MNDe decides on what the action *does*, before OpenClaw runs it.
function openClawToMnde(action) {
  return reviewerRequest({
    requestId: "openclaw-" + action.id,
    tool: action.tool,
    testerId: "openclaw",
    installationId: "mnde-openclaw-guard",
    parameters: action.command ? { script: action.command } : {}
  });
}

const results = [];
async function test(name, fn) {
  try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
}
async function decide(action) {
  const r = await fetch(`${URL}/v1/decisions`, { method: "POST", headers: { "content-type": "application/json", origin: URL }, body: JSON.stringify(openClawToMnde(action)) });
  assert.equal(r.status, 200, `HTTP ${r.status}`);
  return r.json();
}
async function post(path, body) {
  const r = await fetch(URL + path, { method: "POST", headers: { "content-type": "application/json", origin: URL }, body: JSON.stringify(body) });
  return { status: r.status, json: await r.json() };
}

async function main() {
  console.log("MNDe ⨉ OpenClaw integration (live)\n");
  const dir = mkdtempSync(join(tmpdir(), "mnde-openclaw-"));
  const sc = await startMndeSidecar({ url: URL, env: { MNDE_BIND_PORT: PORT, MNDE_RECEIPT_LOG: join(dir, "receipts.jsonl") } });
  let allowReceipt = null;
  try {
    await test("OpenClaw benign action -> live ALLOW with signed receipt", async () => {
      const json = await decide({ id: "read", tool: "read_status" });
      assert.equal(json.decision, "ALLOW", json.reason_code);
      assert.ok(json.receipt, "ALLOW returns a signed receipt OpenClaw can persist");
      allowReceipt = json.receipt;
    });

    await test("OpenClaw destructive action (rm -rf) -> live REFUSE before execution", async () => {
      const json = await decide({ id: "rmrf", tool: "recursive_delete", command: "rm -rf ./project" });
      assert.equal(json.decision, "REFUSE", `expected REFUSE, got ${json.decision}`);
      assert.equal(json.reason_code, "ERR_FORBIDDEN_ACTION_IN_PARAMETERS");
    });

    await test("OpenClaw receipt verifies (signature + decision integrity)", async () => {
      const { json } = await post("/console/verify", allowReceipt);
      assert.equal(json.status, "VALID", json.reason || "");
    });

    await test("OpenClaw decisions replay deterministically", async () => {
      // ensure both decisions are persisted before replay
      let list = [];
      for (let i = 0; i < 20 && list.length < 2; i += 1) {
        const r = await fetch(`${URL}/receipts/recent?limit=50`, { headers: { origin: URL } });
        list = await r.json();
        if (list.length < 2) await new Promise((res) => setTimeout(res, 100));
      }
      const { json } = await post("/console/replay", { limit: 50 });
      assert.equal(json.status, "PASS", JSON.stringify(json.failures || []));
      assert.ok(json.checked >= 2);
    });

    await test("the spec's OLD flat request shape is rejected (contract really is the envelope)", async () => {
      // The previously-documented {action, risk_category, args} shape is NOT the
      // contract; the real sidecar refuses it on schema, proving the fix matters.
      const r = await fetch(`${URL}/v1/decisions`, {
        method: "POST", headers: { "content-type": "application/json", origin: URL },
        body: JSON.stringify({ agent: "openclaw", action: "recursive_delete", tool: "shell", args: { command: "rm -rf ./project" }, risk_category: "recursive_delete", requires_execution: true })
      });
      const json = await r.json();
      assert.equal(json.decision, "REFUSE");
      assert.equal(json.reason_code, "ERR_SCHEMA_VALIDATION", `old flat shape should fail schema, got ${json.reason_code}`);
    });
  } finally {
    await sc.stop();
    rmSync(dir, { recursive: true, force: true });
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) { console.log(`FAIL openclaw tests (${results.length - failed}/${results.length})`); process.exit(1); }
  console.log(`PASS openclaw tests (${results.length}/${results.length})`);
}

main().catch((error) => { console.error(error); process.exit(1); });
