// Decision-engine default + selection gate (P0 chunk 1b).
//
//   npm run test:engine-default
//
// Proves the v1 default flip: policy-engine is the canonical default authority
// path, legacy is explicit, an unknown engine fails closed at startup, and a
// zero-config sidecar runs the built-in default-deny policy producing normal,
// offline-verifiable REFUSE receipts that carry NO deployment state.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { resolveDecisionEngine, DEFAULT_ENGINE } from "../shared/decision-engine.mjs";
import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import { verifyAnyReceiptObject } from "../tools/verify.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
bootstrapReceiptKeys({ repoRoot });
const PORT = 8804;

const results = [];
async function test(name, fn) {
  try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
}

function spawnSidecar(overrides) {
  const env = {
    ...process.env,
    MNDE_BIND_PORT: String(PORT),
    MNDE_INLINE_REFUSAL_RECEIPTS: "1",
    MNDE_RECEIPT_LOG: join(mkdtempSync(join(tmpdir(), "mnde-ed-")), "r.jsonl"),
    MNDE_WORKER_POOL_SIZE: "1"
  };
  // Start from a clean engine/profile/policy slate so we exercise the real default.
  for (const k of ["MNDE_DECISION_ENGINE", "MNDE_PROFILE", "MNDE_PE_POLICY", "MNDE_PE_POLICY_BUNDLE"]) delete env[k];
  for (const [k, v] of Object.entries(overrides)) { if (v === undefined) delete env[k]; else env[k] = v; }
  const child = spawn(process.execPath, ["mnde-local-sidecar.mjs"], { cwd: repoRoot, env });
  let err = ""; child.stderr.on("data", (d) => (err += d));
  return { child, err: () => err };
}
async function waitReady(s, ms = 8000) {
  const dl = Date.now() + ms;
  while (Date.now() < dl) {
    try { const r = await fetch(`http://127.0.0.1:${PORT}/readyz`); if ((await r.json()).ok) return true; } catch {}
    if (s.child.exitCode !== null) return false;
    await new Promise((r) => setTimeout(r, 120));
  }
  return false;
}
const stop = async (s) => { try { s.child.kill(); } catch {} await new Promise((r) => setTimeout(r, 150)); };
const peRequest = () => ({
  schema_version: "1.0", request_id: "ed-1", timestamp: "2026-06-25T00:00:00.000Z",
  principal: { id: "p" }, agent: { id: "a" }, tool: { tool_name: "read_status" },
  parameters: {}, environment: {}, context: {}
});

async function main() {
  console.log("MNDe decision-engine default + selection\n");

  // ── unit ─────────────────────────────────────────────────────────────────
  await test("unset resolves to policy-engine (v1 default)", () => {
    assert.equal(resolveDecisionEngine({}), "policy-engine");
    assert.equal(DEFAULT_ENGINE, "policy-engine");
  });
  await test("explicit legacy resolves to legacy", () => assert.equal(resolveDecisionEngine({ MNDE_DECISION_ENGINE: "legacy" }), "legacy"));
  await test("unknown engine resolves to null (fail-closed signal)", () => {
    assert.equal(resolveDecisionEngine({ MNDE_DECISION_ENGINE: "nonsense" }), null);
    assert.equal(resolveDecisionEngine({ MNDE_DECISION_ENGINE: "  " }), "policy-engine"); // whitespace == unset
  });

  // ── live: unknown engine refuses to boot ───────────────────────────────────
  await test("unknown MNDE_DECISION_ENGINE refuses to start", async () => {
    const s = spawnSidecar({ MNDE_DECISION_ENGINE: "totally-not-an-engine" });
    const ready = await waitReady(s, 5000);
    await stop(s);
    assert.equal(ready, false, "must not become ready on an unknown engine");
    assert.notEqual(s.child.exitCode, 0);
    assert.match(s.err(), /unknown MNDE_DECISION_ENGINE/);
  });

  // ── live: zero-config default == policy-engine + built-in default-deny ──────
  await test("zero-config default: policy-engine + default-deny REFUSE with a clean receipt", async () => {
    const s = spawnSidecar({}); // nothing set: real v1 default
    const ready = await waitReady(s);
    try {
      assert.equal(ready, true, `sidecar must boot under the default policy-engine: ${s.err().slice(-200)}`);
      const res = await fetch(`http://127.0.0.1:${PORT}/v1/decisions`, {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(peRequest())
      });
      const body = await res.json();

      // Decision facts
      assert.equal(body.decision_engine, "policy-engine", "default engine must be policy-engine");
      assert.equal(body.decision, "REFUSE", "default-deny must REFUSE");
      assert.equal(body.reason_code, "NO_MATCHING_RULE", "engine reason is deterministic NO_MATCHING_RULE");
      assert.equal(body.policy_id, "mnde.system.default_deny.v1");
      assert.equal(body.receipt.schema_version, "mnde.pe.receipt.v1");

      // Deployment state is surfaced in the API response...
      assert.equal(body.policy_configuration_state, "NO_POLICY_CONFIGURED", "API must surface deployment state");
      // ...but NEVER written into the signed receipt (decision facts only).
      assert.equal(JSON.stringify(body.receipt).includes("NO_POLICY_CONFIGURED"), false, "deployment state must not appear in the receipt");
      assert.equal(body.receipt.decision_output.reason_code, "NO_MATCHING_RULE", "receipt reason is the engine fact, not deployment state");

      // Receipt verifies offline + replays (no special verifier path).
      const verdict = verifyAnyReceiptObject(body.receipt);
      assert.equal(verdict.verified, true, `default-deny receipt must verify offline: ${verdict.reason ?? ""}`);
      assert.equal(verdict.kind, "policy-engine");
      assert.equal(verdict.decision, "REFUSE");
    } finally {
      await stop(s);
    }
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) { console.log(`FAIL engine-default tests (${results.length - failed}/${results.length})`); process.exit(1); }
  console.log(`PASS engine-default tests (${results.length}/${results.length})`);
}

main().catch((error) => { console.error(error); process.exit(1); });
