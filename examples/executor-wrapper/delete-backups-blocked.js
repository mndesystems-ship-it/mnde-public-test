// Example: a destructive action that MNDe REFUSEs.
//
//   node examples/executor-wrapper/delete-backups-blocked.js
//
// The wrapped function deletes backups. MNDe inspects the request, sees a
// destructive command, and refuses. The function never runs — and you still
// get a signed receipt proving the refusal.

import { createMndeExecutor } from "../../executor/index.mjs";
import { startMndeSidecar } from "../../executor/sidecar-harness.mjs";

// ── YOUR CODE ────────────────────────────────────────────────────────────────
let realDeletionHappened = false;
async function deleteBackups() {
  realDeletionHappened = true; // this must NEVER run
  return { deleted: true };
}

async function run(sidecarUrl) {
  const mnde = createMndeExecutor({ sidecarUrl, receiptsDir: "./mnde-receipts/examples" });

  const result = await mnde.execute({
    action: "delete_backups",
    input: { path: "backups/", script: "rm -rf backups/" },
    run: () => deleteBackups()
  });

  console.log("decision:           ", result.decision);
  console.log("reason:             ", result.reason);
  console.log("executed:           ", result.executed);
  console.log("deletion happened?  ", realDeletionHappened);
  console.log("receipt:            ", result.receiptPath);
  console.log("verified:           ", result.verified);
}
// ─────────────────────────────────────────────────────────────────────────────

const sidecar = await startMndeSidecar();
try {
  await run(sidecar.url);
} finally {
  await sidecar.stop();
}
