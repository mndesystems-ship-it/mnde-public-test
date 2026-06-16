// API contract drift test.
//
//   npm run test:api-contract
//
// The canonical request examples in examples/decisions/ are the documented
// contract (docs/api-contract.md). This test POSTs them to a real sidecar and
// asserts the documented decisions, so documentation cannot drift from the
// behavior of the running system.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PORT = "8790";
const URL = `http://127.0.0.1:${PORT}`;

const cases = [
  { file: "allow-read-status.json", expect: "ALLOW" },
  { file: "refuse-recursive-delete.json", expect: "REFUSE" }
];

const results = [];
async function test(name, fn) {
  try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
}

async function main() {
  console.log("MNDe API contract (drift)\n");
  const sc = await startMndeSidecar({ url: URL, env: { MNDE_BIND_PORT: PORT } });
  try {
    for (const c of cases) {
      await test(`documented example ${c.file} -> ${c.expect}`, async () => {
        const body = readFileSync(join(repoRoot, "examples", "decisions", c.file), "utf8");
        const r = await fetch(`${URL}/v1/decisions`, { method: "POST", headers: { "content-type": "application/json", origin: URL }, body });
        assert.equal(r.status, 200, `HTTP ${r.status}`);
        const json = await r.json();
        assert.equal(json.decision, c.expect, `decision was ${json.decision} (${json.reason_code})`);
      });
    }
  } finally {
    await sc.stop();
  }
  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) { console.log(`FAIL api-contract tests (${results.length - failed}/${results.length})`); process.exit(1); }
  console.log(`PASS api-contract tests (${results.length}/${results.length})`);
}

main().catch((error) => { console.error(error); process.exit(1); });
