// Example: a safe action that MNDe ALLOWs.
//
//   node examples/executor-wrapper/read-status.js
//
// Shows the happy path: ask MNDe, get ALLOW, run the function, keep the receipt.

import { createMndeExecutor } from "../../executor/index.mjs";
import { startMndeSidecar } from "../../executor/sidecar-harness.mjs";

// ── YOUR CODE ────────────────────────────────────────────────────────────────
async function readStatus() {
  return { service: "billing", state: "healthy" };
}

async function run(sidecarUrl) {
  const mnde = createMndeExecutor({ sidecarUrl, receiptsDir: "./mnde-receipts/examples" });

  const result = await mnde.execute({
    action: "read_status",
    input: { service: "billing" },
    run: () => readStatus()
  });

  console.log("decision:   ", result.decision);
  console.log("executed:   ", result.executed);
  console.log("result:     ", JSON.stringify(result.result));
  console.log("receipt:    ", result.receiptPath);
  console.log("verified:   ", result.verified);
}
// ─────────────────────────────────────────────────────────────────────────────

// In production the sidecar is already running; this self-starts one so the
// example works with a single command.
const sidecar = await startMndeSidecar();
try {
  await run(sidecar.url);
} finally {
  await sidecar.stop();
}
