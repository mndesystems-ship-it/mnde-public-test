// Executor — custody-envelope binding + trust-context wiring (unit).
//
//   npm run test:executor-custody-binding
//
// A production custody-signed decision (`mnde.signed-receipt.v1/v2`) stores its
// signed decision and canonical request in the envelope's inner `receipt`. The
// gate must (a) forward the custody trust context to the verifier and (b) read
// request bindings from the verified INNER receipt, not the outer envelope.
// These are pure checks on the exported binding helpers plus the resolved config
// — no crypto, no live sidecar.

import assert from "node:assert/strict";

import { createMndeExecutor, receiptForBinding, receiptBinding } from "../executor/index.mjs";

let failures = 0;
function test(name, fn) {
  try { fn(); console.log(`  [PASS] ${name}`); } catch (e) { failures += 1; console.log(`  [FAIL] ${name}: ${e.message}`); }
}

// A legacy-shaped inner receipt (the shape a custody envelope wraps).
function innerReceipt(executionId, tool) {
  const canonical = JSON.stringify({
    execution_request: {
      request_id: executionId,
      release_request: { execution_id: executionId },
      tool_calls: [{ priority: 1, tool }]
    }
  });
  return {
    schema_version: "ecs.receipt.v2",
    canonical_request: canonical,
    request_hash: "deadbeef",
    decision_output: { decision: "ALLOW", execution_id: executionId, policy_hash: "ph-1", policy_version: "policy.v1" }
  };
}

function custodyEnvelope(executionId, tool) {
  return {
    schema_version: "mnde.signed-receipt.v2",
    receipt: innerReceipt(executionId, tool),
    custody_attestation: { signing_mode: "custody" }
  };
}

// P1 (203): receiptForBinding unwraps a custody envelope to its inner receipt.
test("receiptForBinding unwraps a custody envelope to its inner receipt", () => {
  const env = custodyEnvelope("exec-1", "read_status");
  assert.equal(receiptForBinding(env), env.receipt, "custody envelope must unwrap to inner receipt");
});

test("receiptForBinding passes a non-envelope receipt through unchanged", () => {
  const inner = innerReceipt("exec-1", "read_status");
  assert.equal(receiptForBinding(inner), inner);
  assert.equal(receiptForBinding(null), null);
});

// P1 (203): bindings come from the inner receipt, so a custody ALLOW binds.
test("receiptBinding extracts decision/id/action from the inner custody receipt", () => {
  const env = custodyEnvelope("exec-42", "deploy_service");
  const b = receiptBinding(receiptForBinding(env));
  assert.equal(b.decision, "ALLOW", "inner signed decision must surface");
  assert.ok(b.requestIds.includes("exec-42"), "inner execution id must surface");
  assert.equal(b.action, "deploy_service", "inner action must surface");
  assert.equal(b.policyHash, "ph-1");
});

test("receiptBinding self-unwraps a custody envelope (defense in depth)", () => {
  // receiptBinding unwraps internally too, so even a caller that hands it a raw
  // custody envelope binds the inner receipt rather than the binding-less wrapper.
  const env = custodyEnvelope("exec-42", "deploy_service");
  const b = receiptBinding(env);
  assert.equal(b.decision, "ALLOW");
  assert.ok(b.requestIds.includes("exec-42"));
  assert.equal(b.action, "deploy_service");
});

// P1 (191): the custody trust context is wired into the executor from config/env.
test("executor forwards custody trust context (root fingerprint + environment id)", () => {
  const exec = createMndeExecutor({
    sidecarUrl: "http://127.0.0.1:1",
    receiptsDir: "./mnde-receipts/custody-binding-test",
    verifyTrustedRootFingerprint: "root-fp-abc",
    verifyEnvironmentId: "prod-eu"
  });
  assert.equal(exec.config.verifyTrustedRootFingerprint, "root-fp-abc");
  assert.equal(exec.config.verifyEnvironmentId, "prod-eu");
});

if (failures > 0) {
  console.log(`\nFAIL executor custody-binding tests (${failures} failing)`);
  process.exit(1);
}
console.log("\nPASS executor custody-binding tests");
