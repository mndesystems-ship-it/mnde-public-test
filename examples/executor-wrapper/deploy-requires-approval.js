// Example: an action that exceeds the policy's manual-approval threshold.
//
//   node examples/executor-wrapper/deploy-requires-approval.js
//
// When the projected cost is above the policy's manual-approval threshold and
// the request is not approved, MNDe refuses with ERR_MANUAL_APPROVAL_REQUIRED.
// When the request carries an approval, the same action is allowed.
//
// NOTE: in this demo the approval is the request's `hold_state: "APPROVED"`,
// which the caller supplies. In production that approval must be a cryptographic
// hold token issued by an authenticated approver, not a client-set field —
// otherwise the caller can self-approve. (Tracked as an open hardening item.)

import { createMndeExecutor } from "../../executor/index.mjs";
import { startMndeSidecar } from "../../executor/sidecar-harness.mjs";

// Drive the projected cost above the policy threshold (default 5000 cents).
const EXPENSIVE = {
  pricing_data: { gpu_hour_cents: 6000 },
  execution_request: {
    runtime_observation: { actual_total_cost_cents: 6000 }
  }
};

// ── YOUR CODE ────────────────────────────────────────────────────────────────
async function deploy() {
  return { deployed: true };
}

async function run(sidecarUrl) {
  const mnde = createMndeExecutor({ sidecarUrl, receiptsDir: "./mnde-receipts/examples" });

  // 1) No approval -> REFUSE
  const blocked = await mnde.execute({
    action: "deploy",
    input: { target: "prod" },
    run: () => deploy(),
    requestOverrides: {
      ...EXPENSIVE,
      execution_request: { ...EXPENSIVE.execution_request, release_request: { hold_state: "NONE" } }
    }
  });
  console.log("without approval -> decision:", blocked.decision, "| reason:", blocked.reason, "| executed:", blocked.executed);

  // 2) With approval -> ALLOW
  const approved = await mnde.execute({
    action: "deploy",
    input: { target: "prod" },
    run: () => deploy(),
    requestOverrides: {
      ...EXPENSIVE,
      execution_request: { ...EXPENSIVE.execution_request, release_request: { hold_state: "APPROVED" } }
    }
  });
  console.log("with approval    -> decision:", approved.decision, "| executed:", approved.executed);
}
// ─────────────────────────────────────────────────────────────────────────────

const sidecar = await startMndeSidecar();
try {
  await run(sidecar.url);
} finally {
  await sidecar.stop();
}
