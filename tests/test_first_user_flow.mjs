// First-user flow — live, end-to-end, no terminal, no mocks.
//
//   npm run test:first-user
//
// Drives the exact calls the Authority Console makes against a real sidecar
// (default config): serve the console, make a real ALLOW and a real REFUSE
// decision via same-origin POST, read receipts, verify a receipt, replay, and
// read authority state — all over live HTTP. Also confirms the same-origin CORS
// allowance works and that cross-origin + the authority-gated /verify stay
// protected (no security weakening).

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { reviewerRequest } from "../scripts/reviewer-request.mjs";

const PORT = "8791";
const URL = `http://127.0.0.1:${PORT}`;
const ORIGIN = URL; // same-origin as the served console

const results = [];
async function test(name, fn) {
  try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
}
async function post(path, body, origin = ORIGIN) {
  const r = await fetch(URL + path, { method: "POST", headers: { "content-type": "application/json", origin }, body: JSON.stringify(body) });
  let json = null; try { json = await r.json(); } catch { /* non-json */ }
  return { status: r.status, json };
}
async function get(path) {
  const r = await fetch(URL + path, { headers: { origin: ORIGIN } });
  return { status: r.status, json: await r.json() };
}
const allowReq = () => reviewerRequest({ requestId: "console-allow-" + Date.now(), tool: "read_status" });
const refuseReq = () => reviewerRequest({ requestId: "console-refuse-" + Date.now(), tool: "recursive_delete", parameters: { script: "rm -rf /tmp/workspace" } });

async function main() {
  console.log("MNDe first-user flow (live)\n");
  const dir = mkdtempSync(join(tmpdir(), "mnde-firstuser-"));
  const sc = await startMndeSidecar({ url: URL, env: { MNDE_BIND_PORT: PORT, MNDE_RECEIPT_LOG: join(dir, "receipts.jsonl") } });
  let allowReceipt = null;
  try {
    await test("console is served at / (HTML)", async () => {
      const r = await fetch(URL + "/", { headers: { origin: ORIGIN } });
      assert.equal(r.status, 200);
      assert.match(r.headers.get("content-type") || "", /text\/html/);
    });

    await test("real ALLOW decision via same-origin POST", async () => {
      const { status, json } = await post("/v1/decisions", allowReq());
      assert.equal(status, 200);
      assert.equal(json.decision, "ALLOW");
      assert.ok(json.receipt, "ALLOW returns an inline signed receipt");
      allowReceipt = json.receipt;
    });

    await test("real REFUSE decision via same-origin POST", async () => {
      const { status, json } = await post("/v1/decisions", refuseReq());
      assert.equal(status, 200);
      assert.equal(json.decision, "REFUSE");
    });

    await test("receipts appear in the recent log", async () => {
      let list = [];
      for (let i = 0; i < 20 && list.length < 2; i += 1) {
        ({ json: list } = await get("/receipts/recent?limit=50"));
        if (list.length < 2) await new Promise((r) => setTimeout(r, 100));
      }
      assert.ok(list.length >= 2, `expected >=2 receipts, got ${list.length}`);
      assert.ok(list.some((r) => r.verdict === "ALLOW") && list.some((r) => r.verdict === "REFUSE"));
    });

    await test("verify a receipt from the console endpoint (no auth assertion needed)", async () => {
      const { status, json } = await post("/console/verify", allowReceipt);
      assert.equal(status, 200);
      assert.equal(json.status, "VALID", json.reason || "");
    });

    await test("replay recent decisions from the console endpoint", async () => {
      const { status, json } = await post("/console/replay", { limit: 50 });
      assert.equal(status, 200);
      assert.equal(json.status, "PASS", JSON.stringify(json.failures || []));
      assert.ok(json.checked >= 2);
    });

    await test("authority state is readable (trust chain + signing mode)", async () => {
      const { json } = await get("/authority");
      assert.equal(json.schema_version, "mnde.authority_state.v1");
      assert.equal(json.signing_mode, "legacy");
      assert.equal(json.trust_chain, "LOCAL_DEV");
      assert.ok(json.policy_hash);
    });

    // ── security preserved ──────────────────────────────────────────────────
    await test("cross-origin POST is still rejected (CORS enforced)", async () => {
      const { status, json } = await post("/v1/decisions", allowReq(), "http://evil.example");
      assert.equal(status, 403);
      assert.equal(json.reason_code, "ERR_UNAUTHORIZED_ORIGIN");
    });

    await test("authority-gated /verify is unchanged (still requires authority)", async () => {
      const r = await fetch(URL + "/verify", { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN }, body: JSON.stringify(allowReceipt) });
      assert.equal(r.status, 403); // gated endpoint untouched
    });
  } finally {
    await sc.stop();
    rmSync(dir, { recursive: true, force: true });
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) { console.log(`FAIL first-user tests (${results.length - failed}/${results.length})`); process.exit(1); }
  console.log(`PASS first-user tests (${results.length}/${results.length})`);
}

main().catch((error) => { console.error(error); process.exit(1); });
