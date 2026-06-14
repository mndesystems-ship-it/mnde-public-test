// Example: wrap an agent's tools with MNDe.
//
//   node examples/executor-wrapper/agent-tool-wrapper.js
//
// An agent has three tools. Each is wrapped with MNDe. The agent decides to call
// delete_backups. MNDe refuses. The function never runs. The receipt verifies.

import { createMndeExecutor } from "../../executor/index.mjs";
import { startMndeSidecar } from "../../executor/sidecar-harness.mjs";

// ── YOUR CODE ────────────────────────────────────────────────────────────────
// The raw tools. Note we track whether the destructive one ever actually runs.
let backupsDeleted = false;

async function readStatus() { return { state: "healthy" }; }
async function restartService(input) { return { restarted: input?.service ?? "unknown" }; }
async function deleteBackups() { backupsDeleted = true; return { deleted: true }; }

function buildAgentTools(mnde) {
  return {
    read_status: mnde.wrapTool("read_status", readStatus),
    restart_service: mnde.wrapTool("restart_service", restartService),
    delete_backups: mnde.wrapTool("delete_backups", deleteBackups)
  };
}

async function run(sidecarUrl) {
  const mnde = createMndeExecutor({ sidecarUrl, receiptsDir: "./mnde-receipts/examples" });
  const tools = buildAgentTools(mnde);

  // The agent "thinks" and calls a destructive tool. A real agent tool that
  // deletes backups would shell out to something like `rm -rf` — which is exactly
  // what MNDe inspects and refuses.
  console.log("Agent asks delete_backups");
  const outcome = await tools.delete_backups({ path: "backups/", script: "rm -rf backups/" });

  console.log(`MNDe ${outcome.decision} (${outcome.reason})`);
  console.log(`Function never ran: ${backupsDeleted === false ? "CONFIRMED" : "FAILED — function executed!"}`);
  console.log(`Receipt: ${outcome.verified ? "VERIFIED" : "NOT VERIFIED"}`);
  console.log(`Receipt path: ${outcome.receiptPath}`);

  // For contrast: a safe tool the agent is allowed to use.
  const status = await tools.read_status({});
  console.log(`\nAgent asks read_status -> ${status.decision}, executed: ${status.executed}`);
}
// ─────────────────────────────────────────────────────────────────────────────

const sidecar = await startMndeSidecar();
try {
  await run(sidecar.url);
} finally {
  await sidecar.stop();
}
